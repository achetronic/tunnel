package wg

import (
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/achetronic/tunnel/internal/agentconfig"
)

// newKey returns a fresh base64 WireGuard private key for use in tests.
func newKey(t *testing.T) string {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return k.String()
}

// newPubKey returns a fresh base64 WireGuard public key for use in tests.
func newPubKey(t *testing.T) string {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return k.PublicKey().String()
}

func TestBuildDeviceConfig_Relay(t *testing.T) {
	cfg := agentconfig.WireGuardConfig{
		Interface: agentconfig.WireGuardInterface{
			Name:       "wg-relay",
			PrivateKey: newKey(t),
			ListenPort: 51821,
			Address:    "10.200.0.1/24",
		},
		Peers: []agentconfig.WireGuardPeer{
			{PublicKey: newPubKey(t), AllowedIPs: []string{"10.200.0.2/32"}},
			{PublicKey: newPubKey(t), AllowedIPs: []string{"10.200.0.3/32"}},
		},
	}

	out, err := buildDeviceConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.ListenPort == nil || *out.ListenPort != 51821 {
		t.Fatalf("listen port: got %v want 51821", out.ListenPort)
	}
	if !out.ReplacePeers {
		t.Fatal("ReplacePeers must be true")
	}
	if len(out.Peers) != 2 {
		t.Fatalf("peers: got %d want 2", len(out.Peers))
	}
	for i, p := range out.Peers {
		if !p.ReplaceAllowedIPs {
			t.Errorf("peer %d: ReplaceAllowedIPs must be true", i)
		}
		if len(p.AllowedIPs) != 1 {
			t.Errorf("peer %d: allowed IPs got %d want 1", i, len(p.AllowedIPs))
		}
		if p.Endpoint != nil {
			t.Errorf("peer %d: endpoint must be nil on the relay", i)
		}
		if p.PersistentKeepaliveInterval != nil {
			t.Errorf("peer %d: keepalive must be nil on the relay", i)
		}
	}
}

func TestBuildDeviceConfig_Uplink(t *testing.T) {
	cfg := agentconfig.WireGuardConfig{
		Interface: agentconfig.WireGuardInterface{
			Name:       "wg-uplink",
			PrivateKey: newKey(t),
			Address:    "10.200.0.2/32",
		},
		Peers: []agentconfig.WireGuardPeer{
			{
				PublicKey:           newPubKey(t),
				AllowedIPs:          []string{"10.200.0.0/24"},
				Endpoint:            "203.0.113.10:51821",
				PersistentKeepalive: 25,
			},
		},
	}

	out, err := buildDeviceConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.ListenPort != nil {
		t.Fatalf("uplink must not set a listen port, got %v", *out.ListenPort)
	}
	if len(out.Peers) != 1 {
		t.Fatalf("peers: got %d want 1", len(out.Peers))
	}
	p := out.Peers[0]
	if p.Endpoint == nil || p.Endpoint.String() != "203.0.113.10:51821" {
		t.Fatalf("endpoint: got %v", p.Endpoint)
	}
	if p.PersistentKeepaliveInterval == nil || *p.PersistentKeepaliveInterval != 25*time.Second {
		t.Fatalf("keepalive: got %v want 25s", p.PersistentKeepaliveInterval)
	}
}

func TestBuildDeviceConfig_Errors(t *testing.T) {
	valid := newKey(t)
	validPub := newPubKey(t)
	cases := map[string]agentconfig.WireGuardConfig{
		"bad private key": {
			Interface: agentconfig.WireGuardInterface{Name: "wg0", PrivateKey: "not-a-key", Address: "10.0.0.1/24"},
		},
		"bad public key": {
			Interface: agentconfig.WireGuardInterface{Name: "wg0", PrivateKey: valid, Address: "10.0.0.1/24"},
			Peers:     []agentconfig.WireGuardPeer{{PublicKey: "nope", AllowedIPs: []string{"10.0.0.2/32"}}},
		},
		"bad allowed ip": {
			Interface: agentconfig.WireGuardInterface{Name: "wg0", PrivateKey: valid, Address: "10.0.0.1/24"},
			Peers:     []agentconfig.WireGuardPeer{{PublicKey: validPub, AllowedIPs: []string{"10.0.0.2"}}},
		},
		"bad endpoint": {
			Interface: agentconfig.WireGuardInterface{Name: "wg0", PrivateKey: valid, Address: "10.0.0.1/24"},
			Peers:     []agentconfig.WireGuardPeer{{PublicKey: validPub, AllowedIPs: []string{"10.0.0.2/32"}, Endpoint: "no-port"}},
		},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := buildDeviceConfig(cfg); err == nil {
				t.Fatalf("expected an error for %q", name)
			}
		})
	}
}
