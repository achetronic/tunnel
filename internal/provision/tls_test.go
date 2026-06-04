package provision

import (
	"context"
	"strings"
	"testing"

	"github.com/achetronic/tunnel/internal/sshexec"
)

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
