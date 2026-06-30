// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package configtransform

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// decode is a tiny helper to pull a nested value out of the transformed JSON.
func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	return m
}

func TestApply_NoRulesIsNoop(t *testing.T) {
	cfg := []byte(`{"a":1}`)
	out, err := Apply(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(cfg) {
		t.Fatalf("expected config unchanged, got %s", out)
	}
}

func TestApply_GetenvAndCidrHost(t *testing.T) {
	t.Setenv("ORDINAL", "1")
	cfg := []byte(`{"wireguard":{"interface":{"address":""}},"net":"10.200.0.0/24"}`)
	rules := []byte(`
transforms:
  - path: wireguard.interface.address
    expr: 'cidrHost(config.net, 2 + int(getenv("ORDINAL"))) + "/32"'
`)
	out, err := Apply(cfg, rules)
	if err != nil {
		t.Fatal(err)
	}
	m := decode(t, out)
	addr := m["wireguard"].(map[string]any)["interface"].(map[string]any)["address"]
	if addr != "10.200.0.3/32" {
		t.Fatalf("address = %v, want 10.200.0.3/32", addr)
	}
}

func TestApply_ReadFileWithTrim(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "priv-0")
	if err := os.WriteFile(keyFile, []byte("supersecretkey\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEY_DIR", dir)
	cfg := []byte(`{"wireguard":{"interface":{"privateKey":""}}}`)
	rules := []byte(`
transforms:
  - path: wireguard.interface.privateKey
    expr: 'readFile(getenv("KEY_DIR") + "/priv-0").trim()'
`)
	out, err := Apply(cfg, rules)
	if err != nil {
		t.Fatal(err)
	}
	m := decode(t, out)
	key := m["wireguard"].(map[string]any)["interface"].(map[string]any)["privateKey"]
	if key != "supersecretkey" {
		t.Fatalf("privateKey = %q, want trimmed 'supersecretkey'", key)
	}
}

func TestApply_FromJSONExtract(t *testing.T) {
	cfg := []byte(`{"target":""}`)
	rules := []byte(`
transforms:
  - path: target
    expr: 'fromJSON("{\"host\":\"10.0.0.5\"}").host'
`)
	out, err := Apply(cfg, rules)
	if err != nil {
		t.Fatal(err)
	}
	if decode(t, out)["target"] != "10.0.0.5" {
		t.Fatalf("target = %v, want 10.0.0.5", decode(t, out)["target"])
	}
}

func TestApply_FromYAMLExtract(t *testing.T) {
	cfg := []byte(`{"target":""}`)
	rules := []byte(`
transforms:
  - path: target
    expr: |
      fromYAML("host: 10.0.0.9\nport: 80").host
`)
	out, err := Apply(cfg, rules)
	if err != nil {
		t.Fatal(err)
	}
	if decode(t, out)["target"] != "10.0.0.9" {
		t.Fatalf("target = %v, want 10.0.0.9", decode(t, out)["target"])
	}
}

// TestApply_LaterRuleSeesEarlier verifies rules apply in order, so a later rule
// observes an earlier rule's write.
func TestApply_LaterRuleSeesEarlier(t *testing.T) {
	cfg := []byte(`{"a":"","b":""}`)
	rules := []byte(`
transforms:
  - path: a
    expr: '"first"'
  - path: b
    expr: 'config.a + "-second"'
`)
	out, err := Apply(cfg, rules)
	if err != nil {
		t.Fatal(err)
	}
	if decode(t, out)["b"] != "first-second" {
		t.Fatalf("b = %v, want first-second", decode(t, out)["b"])
	}
}

func TestApply_Errors(t *testing.T) {
	cases := []struct {
		name, rules, want string
	}{
		{"empty path", "transforms:\n  - path: \"\"\n    expr: '1'", "path is empty"},
		{"index into scalar", "transforms:\n  - path: a[0]\n    expr: '1'", "list at index 0"},
		{"bad index syntax", "transforms:\n  - path: a[x]\n    expr: '1'", "invalid index"},
		{"bad expr", "transforms:\n  - path: a\n    expr: 'nope('", "compile"},
		{"readFile missing", "transforms:\n  - path: a\n    expr: 'readFile(\"/no/such/file\")'", "readFile"},
	}
	cfg := []byte(`{"a":""}`)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Apply(cfg, []byte(tc.rules))
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to contain %q", err.Error(), tc.want)
			}
		})
	}
}

// TestApply_ListsAndCreation exercises bracket indices and the creation of
// missing intermediate objects and lists.
func TestApply_ListsAndCreation(t *testing.T) {
	cfg := []byte(`{}`)
	rules := []byte(`
transforms:
  - path: a.b.c
    expr: '"deep"'
  - path: items[1]
    expr: '"second"'
  - path: peers[0].name
    expr: '"p0"'
`)
	out, err := Apply(cfg, rules)
	if err != nil {
		t.Fatal(err)
	}
	m := decode(t, out)

	// Nested object created from scratch.
	if got := m["a"].(map[string]any)["b"].(map[string]any)["c"]; got != "deep" {
		t.Errorf("a.b.c = %v, want deep", got)
	}
	// List created and grown: index 0 is a null filler, index 1 is the value.
	items := m["items"].([]any)
	if len(items) != 2 || items[0] != nil || items[1] != "second" {
		t.Errorf("items = %v, want [null second]", items)
	}
	// List of objects created.
	peers := m["peers"].([]any)
	if len(peers) != 1 || peers[0].(map[string]any)["name"] != "p0" {
		t.Errorf("peers = %v, want [{name:p0}]", peers)
	}
}

func TestCidrHost(t *testing.T) {
	cases := []struct {
		cidr  string
		index int64
		want  string
	}{
		{"10.200.0.0/24", 1, "10.200.0.1"},
		{"10.200.0.0/24", 2, "10.200.0.2"},
		{"10.200.0.0/24", 257, "10.200.1.1"},
		{"192.168.0.0/16", 300, "192.168.1.44"},
		{"fd00::/64", 5, "fd00::5"},
	}
	for _, tc := range cases {
		got, err := cidrHost(tc.cidr, tc.index)
		if err != nil {
			t.Fatalf("cidrHost(%q,%d): %v", tc.cidr, tc.index, err)
		}
		if got != tc.want {
			t.Errorf("cidrHost(%q,%d) = %q, want %q", tc.cidr, tc.index, got, tc.want)
		}
	}
}
