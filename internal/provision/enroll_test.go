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

// testEnvoyVersion1301 is a mocked envoy version output.
const testEnvoyVersion1301 = "envoy version: /1.30.1/\n"

// testBootstrap10_200_0_1 is the mocked bootstrap config for the 10.200.0.1 IP.
const testBootstrap10_200_0_1 = `node:
  id: tunnel-relay
  cluster: tunnel-relay

admin:
  address:
    socket_address:
      address: 10.200.0.1
      port_value: 9901

dynamic_resources:
  lds_config:
    path_config_source:
      path: /etc/envoy/lds.yaml
  cds_config:
    path_config_source:
      path: /etc/envoy/cds.yaml
`

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
			return unameX8664, nil
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
		EnvoyVersion:      "1.30.1",
		EnvoyLDSHash:      "hash2",
		EnvoyCDSHash:      "hash3",
		RelayIP:           "10.200.0.1",
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

	// Assert the Envoy version probe uses the absolute path, not a bare command.
	var foundAbsoluteEnvoyProbe bool
	var foundBareEnvoyProbe bool
	for _, cmd := range fake.Runs {
		if strings.Contains(cmd, "envoy --version") {
			if strings.HasPrefix(cmd, "/usr/local/bin/envoy") {
				foundAbsoluteEnvoyProbe = true
			} else {
				foundBareEnvoyProbe = true
			}
		}
	}
	if !foundAbsoluteEnvoyProbe {
		t.Error("expected absolute path for Envoy version probe, but none was found")
	}
	if foundBareEnvoyProbe {
		t.Error("found bare envoy --version invocation which violates absolute path requirements")
	}

	// Assert the tunnelctl apply uses the absolute path, not a bare command.
	var foundAbsoluteTunnelctlApply bool
	for _, cmd := range fake.Runs {
		if strings.Contains(cmd, "tunnelctl apply") {
			if strings.HasPrefix(cmd, "/usr/local/bin/tunnelctl apply") {
				foundAbsoluteTunnelctlApply = true
			}
		}
	}
	if !foundAbsoluteTunnelctlApply {
		t.Error("expected absolute path for tunnelctl apply, but none was found")
	}

	runsBefore := len(fake.Runs)
	_, err = Enroll(context.Background(), fake, plan, nil)
	if err != nil {
		t.Fatalf("second enroll failed: %v", err)
	}

	runsAfter := len(fake.Runs)
	// A no-op enroll only reads the state (cat state.json), runs the cheap architecture detection
	// (uname -m), runs the two CheckHealth probes (is-active envoy, tunnelctl status), and runs the sweep command before short-circuiting.
	if runsAfter != runsBefore+5 {
		t.Fatalf("expected 5 runs (cat state, uname -m, 2x CheckHealth, sweep), got %d extra runs", runsAfter-runsBefore)
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
			return unameX8664, nil
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
		EnvoyVersion:      "1.30.1",
		EnvoyLDSHash:      "hash2",
		EnvoyCDSHash:      "hash3",
		RelayIP:           "10.200.0.1",
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
		EnvoyVersion:      "1.30.1",
		EnvoyLDSHash:      "hash2",
		EnvoyCDSHash:      "hash3",
		RelayIP:           "10.200.0.1",
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
		"systemctl disable --now wg-relay.service",
		"rm -f /etc/systemd/system/envoy.service",
		"rm -f /etc/systemd/system/wg-relay.service",
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

func TestEnroll_BootstrapCustomIP(t *testing.T) {
	fake := sshexec.NewFakeExecutor()

	fake.RunFunc = func(ctx context.Context, cmd string) (string, error) {
		switch {
		case strings.Contains(cmd, "uname -m"):
			return unameX8664, nil
		case strings.Contains(cmd, "test -x "+tunnelctlBinPath):
			return "", nil
		case strings.Contains(cmd, "cat /etc/tunnel-operator/state.json"):
			return "", &ssh.ExitError{}
		case strings.Contains(cmd, "tunnelctl status"):
			return relayStatusJSON, nil
		case strings.Contains(cmd, "systemctl is-active"):
			return activeServiceLine, nil
		case strings.Contains(cmd, "cat /etc/envoy/envoy.yaml"):
			// Remote bootstrap is missing (or empty) so it will differ.
			return "", &ssh.ExitError{}
		default:
			return "", nil
		}
	}

	plan := &planner.Plan{
		RelayDocument:     []byte(`{"version":1}`),
		EnvoyLDS:          []byte("lds"),
		EnvoyCDS:          []byte("cds"),
		RelayDocumentHash: "hash1",
		TunnelctlDir:      tunnelctlFixtureDir(t),
		EnvoyVersion:      "1.30.1",
		EnvoyLDSHash:      "hash2",
		EnvoyCDSHash:      "hash3",
		RelayIP:           "10.77.0.1",
	}

	_, err := Enroll(context.Background(), fake, plan, nil)
	if err != nil {
		t.Fatalf("enroll failed: %v", err)
	}

	content, ok := fake.Files["/etc/envoy/envoy.yaml"]
	if !ok {
		t.Fatal("envoy.yaml was not written")
	}

	bootstrapStr := string(content)
	if !strings.Contains(bootstrapStr, "address: 10.77.0.1") {
		t.Errorf("expected bootstrap to contain custom IP 10.77.0.1, got:\n%s", bootstrapStr)
	}
	if strings.Contains(bootstrapStr, "10.200.0.1") {
		t.Errorf("expected bootstrap NOT to contain default IP 10.200.0.1, got:\n%s", bootstrapStr)
	}

	// Since bootstrap was missing/differed, Envoy must be restarted.
	joined := strings.Join(fake.Runs, "\n")
	if !strings.Contains(joined, "systemctl restart envoy") {
		t.Errorf("expected envoy to be restarted when bootstrap is missing, runs were:\n%s", joined)
	}
}

func TestEnroll_BootstrapDiffRestartsEnvoy(t *testing.T) {
	fake := sshexec.NewFakeExecutor()

	fake.RunFunc = func(ctx context.Context, cmd string) (string, error) {
		switch {
		case strings.Contains(cmd, "uname -m"):
			return unameX8664, nil
		case strings.Contains(cmd, "test -x "+tunnelctlBinPath):
			return "", nil
		case strings.Contains(cmd, "cat /etc/tunnel-operator/state.json"):
			return "", &ssh.ExitError{}
		case strings.Contains(cmd, "tunnelctl status"):
			return relayStatusJSON, nil
		case strings.Contains(cmd, "systemctl is-active"):
			return activeServiceLine, nil
		case strings.Contains(cmd, "cat /etc/envoy/envoy.yaml"):
			// Return a different bootstrap configuration.
			return "different-bootstrap-content\n", nil
		default:
			return "", nil
		}
	}

	plan := &planner.Plan{
		RelayDocument:     []byte(`{"version":1}`),
		EnvoyLDS:          []byte("lds"),
		EnvoyCDS:          []byte("cds"),
		RelayDocumentHash: "hash1",
		TunnelctlDir:      tunnelctlFixtureDir(t),
		EnvoyVersion:      "1.30.1",
		EnvoyLDSHash:      "hash2",
		EnvoyCDSHash:      "hash3",
		RelayIP:           "10.77.0.1",
	}

	_, err := Enroll(context.Background(), fake, plan, nil)
	if err != nil {
		t.Fatalf("enroll failed: %v", err)
	}

	// Since bootstrap differed, Envoy must be restarted unconditionally.
	joined := strings.Join(fake.Runs, "\n")
	if !strings.Contains(joined, "systemctl restart envoy") {
		t.Errorf("expected envoy to be restarted when bootstrap differs, runs were:\n%s", joined)
	}
}

func TestEnroll_BootstrapIdenticalNoRestart(t *testing.T) {
	fake := sshexec.NewFakeExecutor()

	// Desired bootstrap for 10.77.0.1
	desiredBootstrap := `node:
  id: tunnel-relay
  cluster: tunnel-relay

admin:
  address:
    socket_address:
      address: 10.77.0.1
      port_value: 9901

dynamic_resources:
  lds_config:
    path_config_source:
      path: /etc/envoy/lds.yaml
  cds_config:
    path_config_source:
      path: /etc/envoy/cds.yaml
`

	fake.RunFunc = func(ctx context.Context, cmd string) (string, error) {
		switch {
		case strings.Contains(cmd, "uname -m"):
			return unameX8664, nil
		case strings.Contains(cmd, "test -x "+tunnelctlBinPath):
			return "", nil
		case strings.Contains(cmd, "envoy --version"):
			return testEnvoyVersion1301, nil
		case strings.Contains(cmd, "cat /etc/tunnel-operator/state.json"):
			return "", &ssh.ExitError{}
		case strings.Contains(cmd, "tunnelctl status"):
			return relayStatusJSON, nil
		case strings.Contains(cmd, "systemctl is-active"):
			return activeServiceLine, nil
		case strings.Contains(cmd, "cat /etc/envoy/envoy.yaml"):
			// Return identical bootstrap.
			return desiredBootstrap, nil
		default:
			return "", nil
		}
	}

	// Set fake files so Put of envoy.yaml won't be seen unless it gets written.
	fake.Files["/etc/envoy/envoy.yaml"] = []byte(desiredBootstrap)

	plan := &planner.Plan{
		RelayDocument:     []byte(`{"version":1}`),
		EnvoyLDS:          []byte("lds"),
		EnvoyCDS:          []byte("cds"),
		RelayDocumentHash: "hash1",
		TunnelctlDir:      tunnelctlFixtureDir(t),
		EnvoyLDSHash:      "hash2",
		EnvoyCDSHash:      "hash3",
		RelayIP:           "10.77.0.1",
		EnvoyVersion:      "1.30.1",
	}

	// Clear fake puts/files trackers or track changes.
	// Since identical, we assert no Put occurred on /etc/envoy/envoy.yaml and no restart cmd was run.
	delete(fake.Files, "/etc/envoy/envoy.yaml")

	_, err := Enroll(context.Background(), fake, plan, nil)
	if err != nil {
		t.Fatalf("enroll failed: %v", err)
	}

	if _, ok := fake.Files["/etc/envoy/envoy.yaml"]; ok {
		t.Error("expected envoy.yaml NOT to be Put when remote bootstrap is identical")
	}

	joined := strings.Join(fake.Runs, "\n")
	if strings.Contains(joined, "systemctl restart envoy") {
		t.Errorf("expected envoy NOT to be restarted when bootstrap is identical, runs were:\n%s", joined)
	}
}

func TestEnroll_EmptyRelayIPFails(t *testing.T) {
	fake := sshexec.NewFakeExecutor()

	fake.RunFunc = func(ctx context.Context, cmd string) (string, error) {
		switch {
		case strings.Contains(cmd, "uname -m"):
			return unameX8664, nil
		case strings.Contains(cmd, "test -x "+tunnelctlBinPath):
			return "", nil
		case strings.Contains(cmd, "cat /etc/tunnel-operator/state.json"):
			return "", &ssh.ExitError{}
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
		RelayDocumentHash: "hash1",
		TunnelctlDir:      tunnelctlFixtureDir(t),
		EnvoyVersion:      "1.30.1",
		EnvoyLDSHash:      "hash2",
		EnvoyCDSHash:      "hash3",
		RelayIP:           "", // Intentionally empty
	}

	_, err := Enroll(context.Background(), fake, plan, nil)
	if err == nil {
		t.Fatal("expected enroll to fail with empty RelayIP")
	}

	if !strings.Contains(err.Error(), "ensureEnvoyRunning: plan.RelayIP is empty") {
		t.Errorf("expected error message to complain about plan.RelayIP being empty, got: %v", err)
	}
}

func TestEnroll_TunnelctlHashMismatch_PushesBinary(t *testing.T) {
	fake := sshexec.NewFakeExecutor()

	// All state and plan hashes match, VPS is healthy, but tunnelctl hash in state differs from the fixture binary.
	// Since the local fixture binary "fake-tunnelctl" hash is:
	// e7397bcaae209695d27f7ecb24fc00eb2490a7937a570233ce48aa1294b6ad4e
	// we will set a different hash ("diff-hash") in the mocked state.
	fake.Files["/etc/tunnel-operator/state.json"] = []byte(
		`{"relayDocumentHash":"r","tunnelctlHash":"diff-hash","envoyVersion":"1.30.1","envoyLdsHash":"l","envoyCdsHash":"c","tlsHash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}`)

	fake.RunFunc = func(ctx context.Context, cmd string) (string, error) {
		switch {
		case strings.Contains(cmd, "uname -m"):
			return unameX8664, nil
		case strings.Contains(cmd, "envoy --version"):
			return testEnvoyVersion1301, nil
		case strings.Contains(cmd, "tunnelctl status"):
			return relayStatusJSON, nil
		case strings.Contains(cmd, "systemctl is-active"):
			return activeServiceLine, nil
		case strings.Contains(cmd, "cat /etc/envoy/envoy.yaml"):
			// Return identical bootstrap so Envoy ensure running skips restart.
			return testBootstrap10_200_0_1, nil
		case strings.Contains(cmd, "cat /etc/tunnel-operator/state.json"):
			return string(fake.Files["/etc/tunnel-operator/state.json"]), nil
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

	_, err := Enroll(context.Background(), fake, plan, nil)
	if err != nil {
		t.Fatalf("enroll failed: %v", err)
	}

	// Assert that tunnelctl push happened (Put to the tunnelctl tmp path).
	tmpPath := tunnelctlBinPath + ".tmp"
	if _, ok := fake.Files[tmpPath]; !ok {
		t.Errorf("expected tunnelctl to be pushed to %s, but it was not", tmpPath)
	}
}

func TestEnroll_EnvoyVersionMismatch_InstallsAndRestarts(t *testing.T) {
	fake := sshexec.NewFakeExecutor()

	// All state and plan hashes match, VPS is healthy, but Envoy version in state differs.
	fake.Files["/etc/tunnel-operator/state.json"] = []byte(
		`{"relayDocumentHash":"r","tunnelctlHash":"e7397bcaae209695d27f7ecb24fc00eb2490a7937a570233ce48aa1294b6ad4e","envoyVersion":"1.30.1","envoyLdsHash":"l","envoyCdsHash":"c","tlsHash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}`)

	fake.RunFunc = func(ctx context.Context, cmd string) (string, error) {
		switch {
		case strings.Contains(cmd, "uname -m"):
			return unameX8664, nil
		case strings.Contains(cmd, "envoy --version"):
			// Return older version so the probe detects mismatch.
			return testEnvoyVersion1301, nil
		case strings.Contains(cmd, "tunnelctl status"):
			return relayStatusJSON, nil
		case strings.Contains(cmd, "systemctl is-active"):
			return activeServiceLine, nil
		case strings.Contains(cmd, "cat /etc/envoy/envoy.yaml"):
			// Return identical bootstrap.
			return testBootstrap10_200_0_1, nil
		case strings.Contains(cmd, "cat /etc/tunnel-operator/state.json"):
			return string(fake.Files["/etc/tunnel-operator/state.json"]), nil
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
		EnvoyVersion:      "1.30.2",
	}

	_, err := Enroll(context.Background(), fake, plan, nil)
	if err != nil {
		t.Fatalf("enroll failed: %v", err)
	}

	joined := strings.Join(fake.Runs, "\n")

	// Assert the install command runs (curl download URL with v1.30.2/envoy-1.30.2).
	if !strings.Contains(joined, "curl -fsL https://github.com/envoyproxy/envoy/releases/download/v1.30.2/envoy-1.30.2-linux-x86_64") {
		t.Error("expected Envoy download command to run, but it did not")
	}

	// Assert that systemctl restart envoy is issued.
	if !strings.Contains(joined, "systemctl restart envoy") {
		t.Error("expected Envoy to restart via systemctl restart envoy, but it did not")
	}
}

func TestEnroll_FullSteadyState_EarlyExits(t *testing.T) {
	fake := sshexec.NewFakeExecutor()

	// All state and plan fields match exactly.
	fake.Files["/etc/tunnel-operator/state.json"] = []byte(
		`{"relayDocumentHash":"r","tunnelctlHash":"e7397bcaae209695d27f7ecb24fc00eb2490a7937a570233ce48aa1294b6ad4e","envoyVersion":"1.30.1","envoyLdsHash":"l","envoyCdsHash":"c","tlsHash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}`)

	fake.RunFunc = func(ctx context.Context, cmd string) (string, error) {
		switch {
		case strings.Contains(cmd, "uname -m"):
			return unameX8664, nil
		case strings.Contains(cmd, "tunnelctl status"):
			return relayStatusJSON, nil
		case strings.Contains(cmd, "systemctl is-active"):
			return activeServiceLine, nil
		case strings.Contains(cmd, "cat /etc/tunnel-operator/state.json"):
			return string(fake.Files["/etc/tunnel-operator/state.json"]), nil
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

	_, err := Enroll(context.Background(), fake, plan, nil)
	if err != nil {
		t.Fatalf("enroll failed: %v", err)
	}

	// Since we early exited, we expect no puts or restarts.
	for _, cmd := range fake.Runs {
		if strings.Contains(cmd, "systemctl restart") || strings.Contains(cmd, "curl") || strings.Contains(cmd, "chmod") {
			t.Errorf("did not expect command: %s", cmd)
		}
	}

	// The state file must NOT have been rewritten (no extra Puts on /etc/tunnel-operator/state.json).
	for cmd := range fake.Files {
		if strings.Contains(cmd, "tmp") {
			t.Errorf("did not expect any temporary files, got: %s", cmd)
		}
	}
}

func TestEnroll_BackfillEnvoyVersion_NoDownloadNoRestart_PersistsVersion(t *testing.T) {
	fake := sshexec.NewFakeExecutor()

	// Initial state has empty EnvoyVersion (representing pre-existing VPS).
	fake.Files["/etc/tunnel-operator/state.json"] = []byte(
		`{"relayDocumentHash":"r","tunnelctlHash":"e7397bcaae209695d27f7ecb24fc00eb2490a7937a570233ce48aa1294b6ad4e","envoyVersion":"","envoyLdsHash":"l","envoyCdsHash":"c","tlsHash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}`)

	fake.RunFunc = func(ctx context.Context, cmd string) (string, error) {
		switch {
		case strings.Contains(cmd, "uname -m"):
			return unameX8664, nil
		case strings.Contains(cmd, "envoy --version"):
			// Probe says the binary matches the desired plan version.
			return testEnvoyVersion1301, nil
		case strings.Contains(cmd, "tunnelctl status"):
			return relayStatusJSON, nil
		case strings.Contains(cmd, "systemctl is-active"):
			return activeServiceLine, nil
		case strings.Contains(cmd, "cat /etc/envoy/envoy.yaml"):
			// Return identical bootstrap.
			return testBootstrap10_200_0_1, nil
		case strings.Contains(cmd, "cat /etc/tunnel-operator/state.json"):
			return string(fake.Files["/etc/tunnel-operator/state.json"]), nil
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

	_, err := Enroll(context.Background(), fake, plan, nil)
	if err != nil {
		t.Fatalf("enroll failed: %v", err)
	}

	joined := strings.Join(fake.Runs, "\n")

	// Assert no curl / download command was run.
	if strings.Contains(joined, "curl") {
		t.Error("expected no Envoy download command to run (backfill scenario), but it did")
	}

	// Assert no restart occurred.
	if strings.Contains(joined, "systemctl restart envoy") {
		t.Error("expected no Envoy restart, but it was restarted")
	}

	// Assert EnvoyVersion is backfilled/persisted in the written state.json.
	stateBytes, ok := fake.Files["/etc/tunnel-operator/state.json"]
	if !ok {
		t.Fatal("expected state.json to be persisted, but it was not")
	}

	stateStr := string(stateBytes)
	if !strings.Contains(stateStr, `"envoyVersion":"1.30.1"`) {
		t.Errorf("expected state.json to persist EnvoyVersion '1.30.1', got: %s", stateStr)
	}
}

// installEnvoyBinary interpolates the version into root shell commands on the
// VPS, so it must reject anything that is not bare semver before any command
// runs: a typo'd --envoy-version must fail validation, not become a root RCE.
func TestInstallEnvoyBinary_RejectsUnsafeVersion(t *testing.T) {
	for _, version := range []string{
		"1.29.3; rm -rf /",
		"$(reboot)",
		"`id`",
		"1.29",
		"v1.29.3",
		"1.29.3 ",
		"",
	} {
		t.Run(version, func(t *testing.T) {
			fake := sshexec.NewFakeExecutor()
			if _, err := installEnvoyBinary(context.Background(), fake, version); err == nil {
				t.Fatalf("version %q: expected a validation error, got nil", version)
			}
			if len(fake.Runs) != 0 {
				t.Errorf("version %q: no command must reach the VPS, ran %v", version, fake.Runs)
			}
		})
	}
}

// A well-formed version passes validation and proceeds to the architecture
// probe (the first remote command).
func TestInstallEnvoyBinary_AcceptsSemver(t *testing.T) {
	fake := sshexec.NewFakeExecutor()
	fake.RunFunc = func(_ context.Context, cmd string) (string, error) {
		if cmd == "uname -m" {
			return unameX8664, nil
		}
		return testEnvoyVersion1301, nil
	}
	if _, err := installEnvoyBinary(context.Background(), fake, "1.30.1"); err != nil {
		t.Fatalf("expected semver to pass validation, got: %v", err)
	}
	if len(fake.Runs) == 0 || fake.Runs[0] != "uname -m" {
		t.Errorf("expected the arch probe to run first, got %v", fake.Runs)
	}
}

// TestEnroll_SweepStaleTempFiles verifies that a sweep command is issued early
// in the enrollment flow to clean up any temporary files left behind.
func TestEnroll_SweepStaleTempFiles(t *testing.T) {
	fake := sshexec.NewFakeExecutor()
	fake.RunFunc = func(ctx context.Context, cmd string) (string, error) {
		if strings.Contains(cmd, "uname -m") {
			return unameX8664, nil
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
		EnvoyVersion:      "1.30.1",
		EnvoyLDSHash:      "hash2",
		EnvoyCDSHash:      "hash3",
		RelayIP:           "10.200.0.1",
	}

	_, err := Enroll(context.Background(), fake, plan, nil)
	if err != nil {
		t.Fatalf("enroll failed: %v", err)
	}

	var foundSweep bool
	for _, cmd := range fake.Runs {
		if strings.Contains(cmd, "find") && strings.Contains(cmd, ".tunnel.*") {
			foundSweep = true
			break
		}
	}
	if !foundSweep {
		t.Error("expected a sweep command to be issued, but none was found")
	}
}

// TestEnroll_CorruptedStateReEnrolls asserts that if state.json is corrupted
// and fails parsing, the enroll process recovers gracefully by treating it as
// an empty state and performing a full re-enroll rather than failing.
func TestEnroll_CorruptedStateReEnrolls(t *testing.T) {
	fake := sshexec.NewFakeExecutor()
	fake.RunFunc = func(ctx context.Context, cmd string) (string, error) {
		if strings.Contains(cmd, "uname -m") {
			return unameX8664, nil
		}
		if strings.Contains(cmd, "cat /etc/tunnel-operator/state.json") {
			// Return a corrupted JSON string.
			return "{corrupted-json", nil
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
		EnvoyVersion:      "1.30.1",
		EnvoyLDSHash:      "hash2",
		EnvoyCDSHash:      "hash3",
		RelayIP:           "10.200.0.1",
	}

	_, err := Enroll(context.Background(), fake, plan, nil)
	if err != nil {
		t.Fatalf("enroll failed on corrupted state: %v", err)
	}

	// Verify that we actually did write-related actions (e.g., installTunnelctl, etc.),
	// which indicates a full re-enroll was performed instead of early-exiting.
	var wroteState bool
	for file := range fake.Files {
		if strings.Contains(file, "state.json") {
			wroteState = true
			break
		}
	}
	if !wroteState {
		t.Error("expected state.json to be written during full re-enroll, but it was not")
	}
}

// TestEnroll_RebootSurvivalAndConfigOrder verifies the enroll robustness fixes:
// a wg-relay boot oneshot is installed and enabled, the Envoy unit depends on
// it, the stale-temp sweep covers /etc/systemd/system, and CDS is written
// before LDS so a write interruption never leaves a listener referencing an
// absent cluster.
func TestEnroll_RebootSurvivalAndConfigOrder(t *testing.T) {
	fake := sshexec.NewFakeExecutor()
	fake.RunFunc = func(ctx context.Context, cmd string) (string, error) {
		switch {
		case strings.Contains(cmd, "mv /etc/envoy/lds.yaml.tmp /etc/envoy/lds.yaml"):
			fake.Files["/etc/envoy/lds.yaml"] = fake.Files["/etc/envoy/lds.yaml.tmp"]
			delete(fake.Files, "/etc/envoy/lds.yaml.tmp")
			return "", nil
		case strings.Contains(cmd, "mv /etc/envoy/cds.yaml.tmp /etc/envoy/cds.yaml"):
			fake.Files["/etc/envoy/cds.yaml"] = fake.Files["/etc/envoy/cds.yaml.tmp"]
			delete(fake.Files, "/etc/envoy/cds.yaml.tmp")
			return "", nil
		case strings.Contains(cmd, "uname -m"):
			return unameX8664, nil
		case strings.Contains(cmd, "test -x "+tunnelctlBinPath):
			return "", nil
		case strings.Contains(cmd, "cat /etc/tunnel-operator/state.json"):
			if _, ok := fake.Files["/etc/tunnel-operator/state.json"]; !ok {
				return "", &ssh.ExitError{}
			}
			return string(fake.Files["/etc/tunnel-operator/state.json"]), nil
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
		RelayDocumentHash: "h1",
		TunnelctlDir:      tunnelctlFixtureDir(t),
		EnvoyVersion:      "1.30.1",
		EnvoyLDSHash:      "h2",
		EnvoyCDSHash:      "h3",
		RelayIP:           "10.200.0.1",
	}

	if _, err := Enroll(context.Background(), fake, plan, nil); err != nil {
		t.Fatalf("enroll failed: %v", err)
	}

	joined := strings.Join(fake.Runs, "\n")

	// FIX reboot: the wg-relay boot oneshot must be installed with a tunnelctl
	// apply ExecStart for the relay document, the Envoy unit must depend on it,
	// and wg-relay must be enabled so it runs on boot.
	wgUnit := string(fake.Files["/etc/systemd/system/wg-relay.service"])
	if !strings.Contains(wgUnit, "ExecStart="+tunnelctlBinPath+" apply --config "+relayDocumentPath) {
		t.Fatalf("wg-relay.service missing tunnelctl apply ExecStart; got:\n%s", wgUnit)
	}
	if !strings.Contains(wgUnit, "Type=oneshot") || !strings.Contains(wgUnit, "WantedBy=multi-user.target") {
		t.Fatalf("wg-relay.service is not a boot oneshot; got:\n%s", wgUnit)
	}
	envoyUnit := string(fake.Files["/etc/systemd/system/envoy.service"])
	if !strings.Contains(envoyUnit, "Requires=wg-relay.service") {
		t.Fatalf("envoy.service must require wg-relay.service; got:\n%s", envoyUnit)
	}
	if !strings.Contains(joined, "systemctl enable wg-relay.service") {
		t.Fatalf("wg-relay.service was not enabled; runs:\n%s", joined)
	}

	// FIX m-3: the sweep must cover /etc/systemd/system where unit temp files land.
	if !strings.Contains(joined, "/etc/systemd/system") || !strings.Contains(joined, ".tunnel.*") {
		t.Fatalf("stale-temp sweep does not cover /etc/systemd/system; runs:\n%s", joined)
	}

	// FIX m-4: CDS must be written before LDS.
	cdsIdx := strings.Index(joined, "mv /etc/envoy/cds.yaml.tmp /etc/envoy/cds.yaml")
	ldsIdx := strings.Index(joined, "mv /etc/envoy/lds.yaml.tmp /etc/envoy/lds.yaml")
	if cdsIdx < 0 || ldsIdx < 0 {
		t.Fatalf("expected both CDS and LDS atomic moves; runs:\n%s", joined)
	}
	if cdsIdx > ldsIdx {
		t.Fatalf("CDS must be applied before LDS, got cds at %d after lds at %d", cdsIdx, ldsIdx)
	}
}
