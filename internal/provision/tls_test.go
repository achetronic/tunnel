package provision

import (
	"context"
	"strings"
	"testing"

	"github.com/achetronic/tunnel/internal/planner"
	"github.com/achetronic/tunnel/internal/sshexec"
)

// unameX8664 is the canned `uname -m` output the provision test fakes report.
const unameX8664 = "x86_64\n"

// tlsTestFiles is the TLS material used across the provision TLS tests.
func tlsTestFiles() []TLSFile {
	return []TLSFile{
		{Path: "/etc/envoy/tls/web.crt", Content: []byte("CERT")},
		{Path: "/etc/envoy/tls/web.key", Content: []byte("KEY")},
	}
}

// TestApplyTLSFiles_WritesAtomically checks that pushing TLS material creates the
// directory, streams each file to a temp path and installs it with chmod 600 + mv,
// reports that it wrote, and persists the new hash into the state.
func TestApplyTLSFiles_WritesAtomically(t *testing.T) {
	fake := sshexec.NewFakeExecutor()
	files := tlsTestFiles()
	hash := hashTLSFiles(files)
	state := &State{}

	wrote, err := applyTLSFiles(context.Background(), fake, files, hash, state)
	if err != nil {
		t.Fatal(err)
	}
	if !wrote {
		t.Fatal("expected applyTLSFiles to report a write")
	}
	if state.TLSHash != hash {
		t.Fatalf("state TLSHash not persisted: got %q want %q", state.TLSHash, hash)
	}

	if _, ok := fake.Files["/etc/envoy/tls/web.crt.tmp"]; !ok {
		t.Fatal("cert was not streamed to its temp path")
	}
	if _, ok := fake.Files["/etc/envoy/tls/web.key.tmp"]; !ok {
		t.Fatal("key was not streamed to its temp path")
	}

	joined := strings.Join(fake.Runs, "\n")
	if !strings.Contains(joined, "mkdir -p /etc/envoy/tls") {
		t.Fatalf("missing mkdir for the TLS dir; runs:\n%s", joined)
	}
	for _, want := range []string{
		"chmod 600 /etc/envoy/tls/web.crt.tmp && mv /etc/envoy/tls/web.crt.tmp /etc/envoy/tls/web.crt",
		"chmod 600 /etc/envoy/tls/web.key.tmp && mv /etc/envoy/tls/web.key.tmp /etc/envoy/tls/web.key",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing atomic install command %q; runs:\n%s", want, joined)
		}
	}
}

// TestApplyTLSFiles_Idempotent checks that a second apply with an unchanged hash
// is a no-op that neither reports a write nor issues new commands.
func TestApplyTLSFiles_Idempotent(t *testing.T) {
	files := tlsTestFiles()
	hash := hashTLSFiles(files)
	state := &State{TLSHash: hash}

	fake := sshexec.NewFakeExecutor()
	wrote, err := applyTLSFiles(context.Background(), fake, files, hash, state)
	if err != nil {
		t.Fatal(err)
	}
	if wrote {
		t.Fatal("expected no write when the TLS hash is unchanged")
	}
	if len(fake.Runs) != 0 {
		t.Fatalf("expected no commands on a no-op apply, got %v", fake.Runs)
	}
}

// TestEnroll_TLSRotationRestartsEnvoy verifies that when only the TLS material
// changes (the binding shape, and therefore the LDS/CDS, stays the same) Enroll
// forces an Envoy restart so the rotated certificate is actually picked up.
// File-based tls_certificate references are only re-read on a (re)load, so
// without this a rotated cert would be written to disk but never served.
func TestEnroll_TLSRotationRestartsEnvoy(t *testing.T) {
	fake := sshexec.NewFakeExecutor()

	// State already in place for everything except the TLS material: relay,
	// LDS and CDS hashes match the plan, only tlsHash differs (a rotation).
	fake.Files["/etc/tunnel-operator/state.json"] = []byte(
		`{"relayDocumentHash":"r","tunnelctlHash":"","envoyLdsHash":"l","envoyCdsHash":"c","tlsHash":"old"}`)

	fake.RunFunc = func(ctx context.Context, cmd string) (string, error) {
		switch {
		case strings.Contains(cmd, "cat /etc/tunnel-operator/state.json"):
			return string(fake.Files["/etc/tunnel-operator/state.json"]), nil
		case strings.Contains(cmd, "uname -m"):
			return unameX8664, nil
		case strings.Contains(cmd, "tunnelctl status"):
			return relayStatusJSON, nil
		case strings.Contains(cmd, "systemctl is-active"):
			return activeServiceLine, nil
		default:
			return "", nil
		}
	}

	plan := &planner.Plan{
		RelayDocument:     []byte(`{"version":1}`),
		EnvoyLDS:          []byte("lds"),
		EnvoyCDS:          []byte("cds"),
		RelayDocumentHash: "r",
		TunnelctlDir:      tunnelctlFixtureDir(t),
		EnvoyLDSHash:      "l",
		EnvoyCDSHash:      "c",
	}

	tlsApplied, err := Enroll(context.Background(), fake, plan, tlsTestFiles())
	if err != nil {
		t.Fatalf("enroll failed: %v", err)
	}
	if !tlsApplied {
		t.Fatal("expected tlsApplied to be true on a rotation")
	}

	joined := strings.Join(fake.Runs, "\n")
	if !strings.Contains(joined, "systemctl restart envoy") {
		t.Fatalf("expected an envoy restart to pick up the rotated cert; runs:\n%s", joined)
	}
	// The LDS/CDS were unchanged, so no discovery file should have been moved.
	if strings.Contains(joined, "mv /etc/envoy/lds.yaml.tmp") || strings.Contains(joined, "mv /etc/envoy/cds.yaml.tmp") {
		t.Fatalf("LDS/CDS should not have been rewritten on a cert-only rotation; runs:\n%s", joined)
	}
}

// TestHashTLSFiles_DeterministicAndOrderIndependent checks the hash is stable
// regardless of slice order and that nil and empty slices hash equally.
func TestHashTLSFiles_DeterministicAndOrderIndependent(t *testing.T) {
	a := []TLSFile{
		{Path: "/etc/envoy/tls/a.crt", Content: []byte("A")},
		{Path: "/etc/envoy/tls/b.crt", Content: []byte("B")},
	}
	b := []TLSFile{
		{Path: "/etc/envoy/tls/b.crt", Content: []byte("B")},
		{Path: "/etc/envoy/tls/a.crt", Content: []byte("A")},
	}
	if hashTLSFiles(a) != hashTLSFiles(b) {
		t.Fatal("hash must be independent of slice order")
	}
	if hashTLSFiles(nil) != hashTLSFiles([]TLSFile{}) {
		t.Fatal("nil and empty slice must hash equally")
	}
	if hashTLSFiles(a) == hashTLSFiles(nil) {
		t.Fatal("non-empty material must not hash like the empty input")
	}
}
