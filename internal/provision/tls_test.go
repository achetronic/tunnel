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

// TestEnroll_TLSRotationReloadsViaSDS verifies that when only the TLS material
// changes (the binding shape, and therefore the LDS/CDS, stays the same) Enroll
// rewrites the per-binding SDS document atomically (temp + chmod 600 + mv into
// the watched /etc/envoy/tls directory) and does NOT restart Envoy: the atomic
// move triggers Envoy's graceful file-based SDS reload, so the rotated cert is
// picked up with zero dropped connections.
func TestEnroll_TLSRotationReloadsViaSDS(t *testing.T) {
	fake := sshexec.NewFakeExecutor()

	// State already in place for everything except the TLS material: relay,
	// LDS and CDS hashes match the plan, only tlsHash differs (a rotation).
	fake.Files["/etc/tunnel-operator/state.json"] = []byte(
		`{"relayDocumentHash":"r","tunnelctlHash":"e7397bcaae209695d27f7ecb24fc00eb2490a7937a570233ce48aa1294b6ad4e","envoyVersion":"1.30.1","envoyLdsHash":"l","envoyCdsHash":"c","tlsHash":"old"}`)

	fake.RunFunc = func(ctx context.Context, cmd string) (string, error) {
		switch {
		case strings.Contains(cmd, "cat /etc/tunnel-operator/state.json"):
			return string(fake.Files["/etc/tunnel-operator/state.json"]), nil
		case strings.Contains(cmd, "cat /etc/envoy/envoy.yaml"):
			return testBootstrap10_200_0_1, nil
		case strings.Contains(cmd, "uname -m"):
			return unameX8664, nil
		case strings.Contains(cmd, "envoy --version"):
			return testEnvoyVersion1301, nil
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
		RelayIP:           "10.200.0.1",
		EnvoyVersion:      "1.30.1",
	}

	sdsPath := "/etc/envoy/tls/web.sds.yaml"
	rotated := []TLSFile{{Path: sdsPath, Content: []byte(`{"resources":[]}`)}}

	tlsApplied, err := Enroll(context.Background(), fake, plan, rotated)
	if err != nil {
		t.Fatalf("enroll failed: %v", err)
	}
	if !tlsApplied {
		t.Fatal("expected tlsApplied to be true on a rotation")
	}

	joined := strings.Join(fake.Runs, "\n")
	// The SDS document must be staged to a temp path and atomically moved into
	// the watched directory (this is what triggers the graceful reload).
	if _, ok := fake.Files[sdsPath+".tmp"]; !ok {
		t.Fatal("SDS document was not streamed to its temp path")
	}
	if !strings.Contains(joined, "chmod 600 "+sdsPath+".tmp && mv "+sdsPath+".tmp "+sdsPath) {
		t.Fatalf("SDS document was not installed atomically with 0600; runs:\n%s", joined)
	}
	// A cert rotation must NOT bounce Envoy: the SDS file move reloads it gracefully.
	if strings.Contains(joined, "systemctl restart envoy") {
		t.Fatalf("a TLS rotation must not restart Envoy (SDS reloads gracefully); runs:\n%s", joined)
	}
	// The LDS/CDS were unchanged, so no discovery file should have been moved.
	if strings.Contains(joined, "mv /etc/envoy/lds.yaml.tmp") || strings.Contains(joined, "mv /etc/envoy/cds.yaml.tmp") {
		t.Fatalf("LDS/CDS should not have been rewritten on a cert-only rotation; runs:\n%s", joined)
	}
}

// TestApplyTLSFiles_PrunesOrphans verifies that applying the current SDS set
// removes TLS material for bindings that no longer exist (and pre-SDS cert/key
// files), keeps the desired files, and never touches unrelated files.
func TestApplyTLSFiles_PrunesOrphans(t *testing.T) {
	fake := sshexec.NewFakeExecutor()
	fake.RunFunc = func(ctx context.Context, cmd string) (string, error) {
		if strings.Contains(cmd, "ls -1 /etc/envoy/tls") {
			return "a.sds.yaml\nb.sds.yaml\nlegacy.crt\nlegacy.key\nunrelated.txt\n", nil
		}
		return "", nil
	}

	files := []TLSFile{{Path: "/etc/envoy/tls/a.sds.yaml", Content: []byte(`{"resources":[]}`)}}
	state := &State{TLSHash: "old"}

	wrote, err := applyTLSFiles(context.Background(), fake, files, "new", state)
	if err != nil {
		t.Fatal(err)
	}
	if !wrote {
		t.Fatal("expected applyTLSFiles to report a write")
	}
	if state.TLSHash != "new" {
		t.Fatalf("state TLSHash not persisted: got %q", state.TLSHash)
	}

	joined := strings.Join(fake.Runs, "\n")
	// The desired file must be kept.
	if strings.Contains(joined, "rm -f /etc/envoy/tls/a.sds.yaml") {
		t.Fatalf("the desired SDS file must not be pruned; runs:\n%s", joined)
	}
	// Orphaned SDS and legacy cert/key files must be removed.
	for _, want := range []string{
		"rm -f /etc/envoy/tls/b.sds.yaml",
		"rm -f /etc/envoy/tls/legacy.crt",
		"rm -f /etc/envoy/tls/legacy.key",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected prune to run %q; runs:\n%s", want, joined)
		}
	}
	// An unrelated file (not TLS material) must be left untouched.
	if strings.Contains(joined, "unrelated.txt") {
		t.Fatalf("prune must not touch unrelated files; runs:\n%s", joined)
	}
}

// TestApplyTLSFiles_PrunesAllWhenEmpty verifies that removing every TLS binding
// (empty desired set, with a changed hash) prunes all SDS material from the edge.
func TestApplyTLSFiles_PrunesAllWhenEmpty(t *testing.T) {
	fake := sshexec.NewFakeExecutor()
	fake.RunFunc = func(ctx context.Context, cmd string) (string, error) {
		if strings.Contains(cmd, "ls -1 /etc/envoy/tls") {
			return "web.sds.yaml\n", nil
		}
		return "", nil
	}

	state := &State{TLSHash: "had-tls"}
	wrote, err := applyTLSFiles(context.Background(), fake, nil, hashTLSFiles(nil), state)
	if err != nil {
		t.Fatal(err)
	}
	if wrote {
		t.Fatal("an empty desired set must not report a write")
	}
	if state.TLSHash != hashTLSFiles(nil) {
		t.Fatalf("state TLSHash not updated to the empty hash: got %q", state.TLSHash)
	}
	if !strings.Contains(strings.Join(fake.Runs, "\n"), "rm -f /etc/envoy/tls/web.sds.yaml") {
		t.Fatalf("expected the orphaned SDS file to be pruned; runs:\n%v", fake.Runs)
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
