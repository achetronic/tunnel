// SPDX-FileCopyrightText: 2026 Alby Hernández (Achetronic)
// SPDX-License-Identifier: Apache-2.0

package configtransform

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/achetronic/tunnel/internal/agentconfig"
)

// TestUplinkTransformsAsset runs the real shipped assets/uplink.transforms.yaml
// against a representative uplink template, locking in that the CEL it carries
// compiles, derives the right per-replica identity, and yields a document that
// validates.
func TestUplinkTransformsAsset(t *testing.T) {
	rules, err := os.ReadFile("../../assets/uplink.transforms.yaml")
	if err != nil {
		t.Fatal(err)
	}

	keysDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(keysDir, "priv-1"), []byte("replicaprivkey\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("POD_NAME", "edge-1-uplink-1")
	t.Setenv("KEYS_DIR", keysDir)

	template := []byte("{\"version\":1,\"wireguard\":{\"interface\":{\"name\":\"wg-uplink\",\"privateKey\":\"\",\"address\":\"\",\"mtu\":1420}," +
		"\"peers\":[{\"publicKey\":\"relaypub\",\"allowedIPs\":[\"10.200.0.1/32\"],\"endpoint\":\"203.0.113.10:51821\",\"persistentKeepalive\":25}]}," +
		"\"nftables\":{\"interface\":\"wg-uplink\",\"tunnelNetwork\":\"10.200.0.0/24\"," +
		"\"rules\":[{\"protocol\":\"TCP\",\"listenPort\":80,\"targetIP\":\"10.96.1.1\",\"targetPort\":8080}]}}")

	out, err := Apply(template, rules)
	if err != nil {
		t.Fatalf("apply uplink transforms: %v", err)
	}

	doc, err := agentconfig.Parse(out)
	if err != nil {
		t.Fatalf("transformed document does not validate: %v", err)
	}
	// Ordinal 1 maps to host .2+ordinal = 10.200.0.3.
	if doc.WireGuard.Interface.Address != "10.200.0.3/32" {
		t.Errorf("address = %q, want 10.200.0.3/32", doc.WireGuard.Interface.Address)
	}
	if doc.WireGuard.Interface.PrivateKey != "replicaprivkey" {
		t.Errorf("privateKey = %q, want trimmed 'replicaprivkey'", doc.WireGuard.Interface.PrivateKey)
	}
}
