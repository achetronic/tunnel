// SPDX-FileCopyrightText: 2026 Alby Hernández (Achetronic)
// SPDX-License-Identifier: Apache-2.0

package wg

import (
	"net"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
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

// mustCIDR parses a CIDR into the *net.IPNet shape RouteList returns.
func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("parse cidr %q: %v", s, err)
	}
	return ipnet
}

// staleRoutes must flag exactly the routes whose destination no current peer
// claims, and must never touch kernel-originated routes (the implicit route of
// the interface address) or routes without a destination (default routes).
func TestStaleRoutes(t *testing.T) {
	cfg := agentconfig.WireGuardConfig{
		Peers: []agentconfig.WireGuardPeer{
			{PublicKey: "k1", AllowedIPs: []string{"10.200.0.2/32"}},
			{PublicKey: "k2", AllowedIPs: []string{"10.200.0.3/32"}},
		},
	}

	keep1 := netlink.Route{Dst: mustCIDR(t, "10.200.0.2/32")}
	keep2 := netlink.Route{Dst: mustCIDR(t, "10.200.0.3/32")}
	// Replica removed by a scale-down: its route must be flagged stale.
	gone := netlink.Route{Dst: mustCIDR(t, "10.200.0.4/32")}
	// Kernel route for the interface address subnet: never touched even
	// though no peer claims it.
	kernel := netlink.Route{Dst: mustCIDR(t, "10.200.0.0/24"), Protocol: unix.RTPROT_KERNEL}
	// Default route shape (nil Dst): never touched.
	defaultRoute := netlink.Route{Dst: nil}

	stale := staleRoutes(cfg, []netlink.Route{keep1, keep2, gone, kernel, defaultRoute})

	if len(stale) != 1 {
		t.Fatalf("expected exactly 1 stale route, got %d: %v", len(stale), stale)
	}
	if stale[0].Dst.String() != "10.200.0.4/32" {
		t.Errorf("stale route is %q, want 10.200.0.4/32", stale[0].Dst)
	}
}

// A config with no peers flags every non-kernel destination route as stale,
// and an empty route list yields no work.
func TestStaleRoutes_Edges(t *testing.T) {
	empty := agentconfig.WireGuardConfig{}

	if got := staleRoutes(empty, nil); len(got) != 0 {
		t.Errorf("no routes installed: expected none stale, got %v", got)
	}

	routes := []netlink.Route{
		{Dst: mustCIDR(t, "10.200.0.2/32")},
		{Dst: mustCIDR(t, "10.200.0.0/24"), Protocol: unix.RTPROT_KERNEL},
	}
	got := staleRoutes(empty, routes)
	if len(got) != 1 || got[0].Dst.String() != "10.200.0.2/32" {
		t.Errorf("scale to zero: expected only 10.200.0.2/32 stale, got %v", got)
	}
}
