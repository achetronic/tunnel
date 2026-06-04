package provision

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/achetronic/tunnel/internal/planner"
	"github.com/achetronic/tunnel/internal/sshexec"
	"golang.org/x/crypto/ssh"
)

// tunnelctlFixtureDir returns a temp dir holding a dummy tunnelctl-linux-amd64
// binary so installTunnelctl (which reads the binary from the local dir and
// pushes it over SSH) has something to read. The fakes report x86_64 for uname -m.
func tunnelctlFixtureDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tunnelctl-linux-amd64"), []byte("fake-tunnelctl"), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// relayStatusJSON is the canned tunnelctl status report used by the provision
// test fakes so CheckHealth sees a ready relay.
const relayStatusJSON = `{"interface":"wg-relay","exists":true,"up":true,"ready":true,"detail":"healthy","peers":[]}`

func TestEnroll_Idempotent(t *testing.T) {
	fake := sshexec.NewFakeExecutor()

	fake.RunFunc = func(ctx context.Context, cmd string) (string, error) {
		if strings.Contains(cmd, "mv /etc/envoy/lds.yaml.tmp /etc/envoy/lds.yaml") {
			fake.Files["/etc/envoy/lds.yaml"] = fake.Files["/etc/envoy/lds.yaml.tmp"]
			delete(fake.Files, "/etc/envoy/lds.yaml.tmp")
			return "", nil
		}
		if strings.Contains(cmd, "mv /etc/envoy/cds.yaml.tmp /etc/envoy/cds.yaml") {
			fake.Files["/etc/envoy/cds.yaml"] = fake.Files["/etc/envoy/cds.yaml.tmp"]
			delete(fake.Files, "/etc/envoy/cds.yaml.tmp")
			return "", nil
		}
		if strings.Contains(cmd, "uname -m") {
			return "x86_64\n", nil
		}
		if strings.Contains(cmd, "test -x "+tunnelctlBinPath) {
			// Binary already present, so a version-matching reconcile skips install.
			return "", nil
		}
		if strings.Contains(cmd, "cat /etc/tunnel-operator/state.json") {
			if _, ok := fake.Files["/etc/tunnel-operator/state.json"]; !ok {
				return "", &ssh.ExitError{}
			}
			return string(fake.Files["/etc/tunnel-operator/state.json"]), nil
		}
		if strings.Contains(cmd, "tunnelctl status") {
			return relayStatusJSON, nil
		}
		if strings.Contains(cmd, "systemctl is-active") {
			return activeServiceLine, nil
		}
		return "", nil
	}

	plan := &planner.Plan{
		RelayDocument:     []byte(`{"version":1}`),
		EnvoyLDS:          []byte("lds"),
		EnvoyCDS:          []byte("cds"),
		RelayDocumentHash: "hash1",
		TunnelctlDir:      tunnelctlFixtureDir(t),
		EnvoyLDSHash:      "hash2",
		EnvoyCDSHash:      "hash3",
	}

	_, err := Enroll(context.Background(), fake, plan, nil)
	if err != nil {
		t.Fatalf("first enroll failed: %v", err)
	}

	if string(fake.Files["/etc/envoy/lds.yaml"]) != "lds" {
		t.Fatal("lds.yaml not written")
	}
	if string(fake.Files["/etc/envoy/cds.yaml"]) != "cds" {
		t.Fatal("cds.yaml not written")
	}

	// The relay document is staged to a temp path before the atomic rename.
	if string(fake.Files["/etc/tunnel-operator/relay.json.tmp"]) != `{"version":1}` {
		t.Fatal("relay document not staged")
	}

	// tunnelctl apply must have run for the relay document.
	if !strings.Contains(strings.Join(fake.Runs, "\n"), "tunnelctl apply --config "+relayDocumentPath) {
		t.Fatal("tunnelctl apply was not run")
	}

	runsBefore := len(fake.Runs)
	_, err = Enroll(context.Background(), fake, plan, nil)
	if err != nil {
		t.Fatalf("second enroll failed: %v", err)
	}

	runsAfter := len(fake.Runs)
	// A no-op enroll only reads the state (cat state.json) and runs the two
	// CheckHealth probes (is-active envoy, tunnelctl status) before short-circuiting.
	if runsAfter != runsBefore+3 {
		t.Fatalf("expected 3 runs (cat state, 2x CheckHealth), got %d extra runs", runsAfter-runsBefore)
	}
}

func TestEnroll_PartialFail(t *testing.T) {
	fake := sshexec.NewFakeExecutor()

	fake.RunFunc = func(ctx context.Context, cmd string) (string, error) {
		if strings.Contains(cmd, "mv /etc/envoy/lds.yaml.tmp /etc/envoy/lds.yaml") {
			fake.Files["/etc/envoy/lds.yaml"] = fake.Files["/etc/envoy/lds.yaml.tmp"]
			delete(fake.Files, "/etc/envoy/lds.yaml.tmp")
			return "", nil
		}
		if strings.Contains(cmd, "mv /etc/envoy/cds.yaml.tmp /etc/envoy/cds.yaml") {
			fake.Files["/etc/envoy/cds.yaml"] = fake.Files["/etc/envoy/cds.yaml.tmp"]
			delete(fake.Files, "/etc/envoy/cds.yaml.tmp")
			return "", nil
		}
		if strings.Contains(cmd, "uname -m") {
			return "x86_64\n", nil
		}
		if strings.Contains(cmd, "cat /etc/tunnel-operator/state.json") {
			if _, ok := fake.Files["/etc/tunnel-operator/state.json"]; !ok {
				return "", &ssh.ExitError{}
			}
			return string(fake.Files["/etc/tunnel-operator/state.json"]), nil
		}
		if strings.Contains(cmd, "tunnelctl status") {
			// Relay not ready yet, but no transport error.
			return `{"ready":false,"peers":[]}`, &ssh.ExitError{}
		}
		if strings.Contains(cmd, "systemctl is-active envoy") {
			// Envoy never becomes active, so ensureEnvoyRunning fails fast.
			return "failed\n", nil
		}
		return "", nil
	}

	plan := &planner.Plan{
		RelayDocument:     []byte(`{"version":1}`),
		EnvoyLDS:          []byte("bad-lds"),
		EnvoyCDS:          []byte("bad-cds"),
		RelayDocumentHash: "relayhash",
		TunnelctlDir:      tunnelctlFixtureDir(t),
		EnvoyLDSHash:      "hash2",
		EnvoyCDSHash:      "hash3",
	}

	_, err := Enroll(context.Background(), fake, plan, nil)
	if err == nil {
		t.Fatal("expected error from envoy start")
	}

	// The relay hash is persisted before the envoy step, so a later failure does
	// not lose the relay progress.
	stateStr := string(fake.Files["/etc/tunnel-operator/state.json"])
	if !strings.Contains(stateStr, "relayhash") {
		t.Fatal("relay document hash not persisted")
	}
}

// TestEnroll_TransportErrorIsFatal verifies that a transport/network failure
// from CheckHealth (anything that is not an *ssh.ExitError) aborts Enroll
// instead of being masked and continuing to install against a dead VPS.
func TestEnroll_TransportErrorIsFatal(t *testing.T) {
	fake := sshexec.NewFakeExecutor()

	fake.RunFunc = func(ctx context.Context, cmd string) (string, error) {
		if strings.Contains(cmd, "cat /etc/tunnel-operator/state.json") {
			// State file absent: an exit error, the normal first-enroll case.
			return "", &ssh.ExitError{}
		}
		if strings.Contains(cmd, "systemctl is-active") || strings.Contains(cmd, "tunnelctl status") {
			// Connection dropped: a transport error, not an exit error.
			return "", errors.New("ssh: connection lost")
		}
		return "", nil
	}

	plan := &planner.Plan{
		RelayDocument:     []byte(`{"version":1}`),
		EnvoyLDS:          []byte("lds"),
		EnvoyCDS:          []byte("cds"),
		RelayDocumentHash: "hash1",
		TunnelctlDir:      tunnelctlFixtureDir(t),
		EnvoyLDSHash:      "hash2",
		EnvoyCDSHash:      "hash3",
	}

	_, err := Enroll(context.Background(), fake, plan, nil)
	if err == nil {
		t.Fatal("expected enroll to fail when CheckHealth hits a transport error")
	}

	// It must fail during the health check, before any install or apply runs.
	for _, cmd := range fake.Runs {
		if strings.Contains(cmd, "uname -m") || strings.Contains(cmd, "tunnelctl apply") {
			t.Fatalf("enroll proceeded past health check, ran %q", cmd)
		}
	}
}

func TestTeardown(t *testing.T) {
	fake := sshexec.NewFakeExecutor()
	err := Teardown(context.Background(), fake)
	if err != nil {
		t.Fatal(err)
	}

	joined := strings.Join(fake.Runs, "\n")
	for _, want := range []string{
		"ip link del wg-relay",
		"rm -f " + tunnelctlBinPath,
		"systemctl disable --now envoy",
		"rm -f /etc/systemd/system/envoy.service",
		"systemctl daemon-reload",
		"rm -rf /etc/envoy",
		"rm -f /etc/sysctl.d/99-tunnel.conf",
		"rm -rf /etc/tunnel-operator",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("teardown did not run %q; ran:\n%s", want, joined)
		}
	}
}
