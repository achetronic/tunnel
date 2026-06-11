package provision

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/achetronic/tunnel/internal/planner"
	"github.com/achetronic/tunnel/internal/sshexec"
)

// Paths and download settings for the tunnelctl-based relay provisioning.
const (
	// relayDocumentPath is where the relay's tunnelctl desired-state document is
	// staged on the VPS.
	relayDocumentPath = "/etc/tunnel-operator/relay.json"
	// tunnelctlBinPath is where the tunnelctl binary is installed on the VPS.
	tunnelctlBinPath = "/usr/local/bin/tunnelctl"
	// archAMD64 and archARM64 are the GOARCH suffixes used in the tunnelctl
	// release asset names (tunnelctl-linux-<arch>).
	archAMD64 = "amd64"
	archARM64 = "arm64"
	// archX8664 is the "uname -m" output for 64-bit x86 hosts.
	archX8664 = "x86_64"
)

// Enroll ensures the VPS is configured according to the Plan. It is fully
// idempotent: it reads the state previously persisted on the VPS and only
// applies the steps whose hash changed. Every remote command is bounded by ctx.
//
// tlsFiles contains the raw cert/key material to write to the VPS before
// Envoy is started or reloaded. Pass nil or an empty slice when the plan has
// no TLS bindings that require edge termination (passthrough mode, or no TLS).
// The controller is responsible for reading the content from Kubernetes Secrets
// and assembling the slice; Enroll never touches the API server.
//
// A missing state file is normal on the first enrollment and is treated as an
// empty state. Any other failure to read the state, or any failure to check the
// VPS health, is a transport/network problem and is returned as a fatal error
// instead of being masked, so the operator never installs packages or writes
// config against an unreachable VPS.
func Enroll(ctx context.Context, exec sshexec.Executor, plan *planner.Plan, tlsFiles []TLSFile) (tlsApplied bool, err error) {
	state, stateErr := readState(ctx, exec)
	if stateErr != nil {
		if !isExitError(stateErr) {
			return false, fmt.Errorf("failed to read state from VPS: %w", stateErr)
		}
		// The state file does not exist yet (cat exits non-zero). This is the
		// expected situation on a first enrollment, so start from scratch.
		state = &State{}
	}

	status, healthErr := CheckHealth(ctx, exec)
	if healthErr != nil {
		return false, fmt.Errorf("failed to check VPS health before enrolling: %w", healthErr)
	}

	tlsHash := hashTLSFiles(tlsFiles)

	if stateErr == nil &&
		state.RelayDocumentHash == plan.RelayDocumentHash &&
		state.EnvoyLDSHash == plan.EnvoyLDSHash &&
		state.EnvoyCDSHash == plan.EnvoyCDSHash &&
		state.TLSHash == tlsHash &&
		status.RelayHealthy && status.EnvoyHealthy {
		// Already up to date and healthy, nothing to do.
		slog.Debug("enroll: VPS already up to date and healthy, nothing to apply")
		return false, nil
	}

	if err := installTunnelctl(ctx, exec, plan.TunnelctlDir, state); err != nil {
		return false, err
	}
	if err := installEnvoyBinary(ctx, exec, plan.EnvoyVersion); err != nil {
		return false, err
	}
	if err := writeEnvoyService(ctx, exec); err != nil {
		return false, err
	}
	if err := enableIPForwarding(ctx, exec); err != nil {
		return false, err
	}
	if err := applyRelayDocument(ctx, exec, plan, state); err != nil {
		return false, err
	}
	// TLS material is delivered as per-binding SDS documents (see
	// internal/render.RenderEnvoySDS). Writing one atomically into the watched
	// /etc/envoy/tls directory triggers Envoy's graceful SDS reload, so a cert
	// rotation needs no LDS change and no Envoy restart.
	tlsApplied, err = applyTLSFiles(ctx, exec, tlsFiles, tlsHash, state)
	if err != nil {
		return false, err
	}
	if err := applyEnvoyConfig(ctx, exec, plan, state); err != nil {
		return false, err
	}
	if err := ensureEnvoyRunning(ctx, exec); err != nil {
		return false, err
	}
	return tlsApplied, nil
}

// installTunnelctl pushes the static tunnelctl binary matching the host
// architecture to the VPS. The binary is read from the local tunnelctlDir (baked
// into the operator image, or a local build dir under `make run`), so nothing is
// downloaded on the VPS and the VPS needs no internet access for it. The install
// is idempotent: it skips the push only when the persisted state records the same
// binary hash AND the binary is actually present (so a rebuilt VPS still gets it).
// On a successful push it persists the new hash so subsequent reconciles are no-ops.
func installTunnelctl(ctx context.Context, exec sshexec.Executor, tunnelctlDir string, state *State) error {
	archOut, err := exec.Run(ctx, "uname -m")
	if err != nil {
		return fmt.Errorf("failed to detect architecture: %w", err)
	}
	var arch string
	switch strings.TrimSpace(archOut) {
	case archX8664, archAMD64:
		arch = archAMD64
	case "aarch64", archARM64:
		arch = archARM64
	default:
		return fmt.Errorf("unsupported architecture for tunnelctl: %s", strings.TrimSpace(archOut))
	}

	localPath := filepath.Join(tunnelctlDir, "tunnelctl-linux-"+arch)
	bin, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("read tunnelctl binary %q: %w", localPath, err)
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(bin))

	if state.TunnelctlHash == hash {
		if _, err := exec.Run(ctx, "test -x "+tunnelctlBinPath); err == nil {
			return nil
		} else if !isExitError(err) {
			return fmt.Errorf("failed to check tunnelctl presence: %w", err)
		}
	}

	slog.Info("enroll: pushing tunnelctl binary", "arch", arch, "source", localPath)
	tmp := tunnelctlBinPath + ".tmp"
	if err := exec.Put(ctx, tmp, bin); err != nil {
		return fmt.Errorf("failed to push tunnelctl binary: %w", err)
	}
	if _, err := exec.Run(ctx, fmt.Sprintf("chmod +x %s && mv %s %s", tmp, tmp, tunnelctlBinPath)); err != nil {
		return fmt.Errorf("failed to install tunnelctl binary: %w", err)
	}

	state.TunnelctlHash = hash
	if err := writeState(ctx, exec, state); err != nil {
		return fmt.Errorf("failed to persist tunnelctl state: %w", err)
	}
	return nil
}

// installEnvoyBinary installs the requested Envoy release on the VPS, matching
// the host architecture. The download URL is built from version and the arch
// suffix rather than hardcoded. The install is version-aware: it (re)downloads
// only when no envoy is present or the installed one is a different version, so
// changing EnvoyVersion on the EdgeNode actually replaces the binary (a running
// envoy still needs its service restart, handled by ensureEnvoyRunning).
func installEnvoyBinary(ctx context.Context, exec sshexec.Executor, version string) error {
	archOut, err := exec.Run(ctx, "uname -m")
	if err != nil {
		return fmt.Errorf("failed to detect architecture: %w", err)
	}
	arch := strings.TrimSpace(archOut)

	var archSuffix string
	switch arch {
	case archX8664, archAMD64:
		archSuffix = archX8664
	case "aarch64", "arm64":
		archSuffix = "aarch_64"
	default:
		return fmt.Errorf("unsupported architecture for Envoy: %s", arch)
	}

	downloadURL := fmt.Sprintf(
		"https://github.com/envoyproxy/envoy/releases/download/v%s/envoy-%s-linux-%s",
		version, version, archSuffix,
	)

	// Reinstall when envoy is absent or reports a different version. Envoy's
	// --version output embeds the release as "/<version>/".
	installCmd := fmt.Sprintf(
		"envoy --version 2>/dev/null | grep -q '/%s/' || (curl -sL %s -o /tmp/envoy && chmod +x /tmp/envoy && mv /tmp/envoy /usr/local/bin/envoy)",
		version, downloadURL,
	)
	slog.Info("enroll: ensuring envoy binary (downloads on first run or version change)", "arch", arch, "version", version)
	if _, err := exec.Run(ctx, installCmd); err != nil {
		return fmt.Errorf("failed to install envoy binary: %w", err)
	}
	return nil
}

// writeEnvoyService installs the Envoy systemd unit and reloads systemd so it
// picks up the new unit.
func writeEnvoyService(ctx context.Context, exec sshexec.Executor) error {
	envoyService := `[Unit]
Description=Envoy Proxy
After=network.target

[Service]
ExecStart=/usr/local/bin/envoy -c /etc/envoy/envoy.yaml
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`
	if _, err := exec.Run(ctx, "mkdir -p /etc/envoy"); err != nil {
		return fmt.Errorf("failed to create envoy dir: %w", err)
	}
	if err := exec.Put(ctx, "/etc/systemd/system/envoy.service", []byte(envoyService)); err != nil {
		return fmt.Errorf("failed to write envoy.service: %w", err)
	}
	if _, err := exec.Run(ctx, "systemctl daemon-reload"); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}
	return nil
}

// enableIPForwarding turns on IPv4 forwarding so the relay can route traffic
// between peers, persisting it through a sysctl drop-in.
func enableIPForwarding(ctx context.Context, exec sshexec.Executor) error {
	if _, err := exec.Run(ctx, "sysctl -w net.ipv4.ip_forward=1 && echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-tunnel.conf"); err != nil {
		return fmt.Errorf("failed to set sysctl: %w", err)
	}
	return nil
}

// applyRelayDocument writes the relay tunnelctl desired-state document and applies
// it natively with "tunnelctl apply" when the plan hash changed, then persists the
// new hash. It is a no-op when the relay is already at the desired hash. The
// document carries the relay's WireGuard private key, so it is staged with 0600
// permissions via a temp file and atomic rename.
func applyRelayDocument(ctx context.Context, exec sshexec.Executor, plan *planner.Plan, state *State) error {
	if state.RelayDocumentHash == plan.RelayDocumentHash {
		return nil
	}
	slog.Info("enroll: applying relay document via tunnelctl")

	if _, err := exec.Run(ctx, "mkdir -p /etc/tunnel-operator"); err != nil {
		return fmt.Errorf("failed to create tunnel-operator dir: %w", err)
	}

	tmp := relayDocumentPath + ".tmp"
	if err := exec.Put(ctx, tmp, plan.RelayDocument); err != nil {
		return fmt.Errorf("failed to put relay document: %w", err)
	}
	if _, err := exec.Run(ctx, fmt.Sprintf("chmod 600 %s && mv %s %s", tmp, tmp, relayDocumentPath)); err != nil {
		return fmt.Errorf("failed to install relay document: %w", err)
	}

	if _, err := exec.Run(ctx, "tunnelctl apply --config "+relayDocumentPath); err != nil {
		return fmt.Errorf("failed to apply relay document: %w", err)
	}

	state.RelayDocumentHash = plan.RelayDocumentHash
	if err := writeState(ctx, exec, state); err != nil {
		return fmt.Errorf("failed to persist relay document state: %w", err)
	}
	return nil
}

// applyEnvoyConfig syncs the Envoy LDS and CDS discovery files when their plan
// hashes changed, persisting each new hash as it is applied.
func applyEnvoyConfig(ctx context.Context, exec sshexec.Executor, plan *planner.Plan, state *State) error {
	if state.EnvoyLDSHash != plan.EnvoyLDSHash {
		slog.Info("enroll: applying envoy LDS config")
		if err := exec.Put(ctx, "/etc/envoy/lds.yaml.tmp", plan.EnvoyLDS); err != nil {
			return fmt.Errorf("failed to put lds.yaml.tmp: %w", err)
		}
		if _, err := exec.Run(ctx, "mv /etc/envoy/lds.yaml.tmp /etc/envoy/lds.yaml"); err != nil {
			return fmt.Errorf("failed to rename lds.yaml: %w", err)
		}

		state.EnvoyLDSHash = plan.EnvoyLDSHash
		if err := writeState(ctx, exec, state); err != nil {
			return fmt.Errorf("failed to persist lds config state: %w", err)
		}
	}

	if state.EnvoyCDSHash != plan.EnvoyCDSHash {
		slog.Info("enroll: applying envoy CDS config")
		if err := exec.Put(ctx, "/etc/envoy/cds.yaml.tmp", plan.EnvoyCDS); err != nil {
			return fmt.Errorf("failed to put cds.yaml.tmp: %w", err)
		}
		if _, err := exec.Run(ctx, "mv /etc/envoy/cds.yaml.tmp /etc/envoy/cds.yaml"); err != nil {
			return fmt.Errorf("failed to rename cds.yaml: %w", err)
		}

		state.EnvoyCDSHash = plan.EnvoyCDSHash
		if err := writeState(ctx, exec, state); err != nil {
			return fmt.Errorf("failed to persist cds config state: %w", err)
		}
	}
	return nil
}

// ensureEnvoyRunning deploys the static bootstrap config that points Envoy at
// the LDS/CDS files and makes sure the service is active, without restarting it
// when it already runs.
func ensureEnvoyRunning(ctx context.Context, exec sshexec.Executor) error {
	slog.Info("enroll: ensuring envoy is running")
	// node id/cluster are mandatory in the bootstrap when dynamic_resources
	// (file-based LDS/CDS) are used, otherwise Envoy refuses to load the config.
	bootstrapYAML := `node:
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
	if err := exec.Put(ctx, "/etc/envoy/envoy.yaml", []byte(bootstrapYAML)); err != nil {
		return fmt.Errorf("failed to put envoy.yaml bootstrap: %w", err)
	}

	// Start envoy when it is not already active. If it is in a failed or
	// activating (auto-restart) state from a previous bad config, restart it so
	// it reloads the bootstrap just written. A healthy envoy is left untouched so
	// steady-state reconciles never bounce live connections.
	out, err := exec.Run(ctx, "systemctl is-active envoy")
	if err != nil && !isExitError(err) {
		return fmt.Errorf("failed to query envoy status: %w", err)
	}
	if strings.TrimSpace(out) != serviceActive {
		if _, err := exec.Run(ctx, "systemctl enable envoy && systemctl restart envoy"); err != nil {
			return fmt.Errorf("failed to start envoy: %w", err)
		}
	}

	return waitEnvoyActive(ctx, exec)
}

// RestartEnvoy restarts the Envoy service on the VPS and waits for it to become
// active. It is used to apply a new Envoy binary on demand (for example after an
// --envoy-version change), which a running service would not otherwise pick up.
func RestartEnvoy(ctx context.Context, exec sshexec.Executor) error {
	slog.Info("restarting envoy on request")
	if _, err := exec.Run(ctx, "systemctl restart envoy"); err != nil {
		return fmt.Errorf("failed to restart envoy: %w", err)
	}
	return waitEnvoyActive(ctx, exec)
}

// waitEnvoyActive polls the envoy service until it reports active, bounded by
// ctx. It fails fast when systemd reports the unit as failed (a genuine crash,
// e.g. a bad config) and tolerates the transient "activating" state while the
// process comes up, so a healthy but still-starting envoy is not misread as a
// failure.
func waitEnvoyActive(ctx context.Context, exec sshexec.Executor) error {
	const attempts = 10
	var last string
	for range attempts {
		out, err := exec.Run(ctx, "systemctl is-active envoy")
		if err != nil && !isExitError(err) {
			return fmt.Errorf("failed to check envoy status: %w", err)
		}
		last = strings.TrimSpace(out)
		switch last {
		case serviceActive:
			return nil
		case "failed":
			return fmt.Errorf("envoy failed to start; inspect 'journalctl -u envoy' on the VPS")
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for envoy to become active cancelled: %w", ctx.Err())
		case <-time.After(time.Second):
		}
	}
	return fmt.Errorf("envoy did not become active in time, last state %q", last)
}

// readState reads and parses the operator state persisted on the VPS. A missing
// state file makes the underlying cat exit non-zero, which surfaces here as an
// *ssh.ExitError; callers can tell that case apart from a real transport error
// with isExitError. Any returned error is left unwrapped at the SSH layer so
// that classification stays possible.
func readState(ctx context.Context, exec sshexec.Executor) (*State, error) {
	out, err := exec.Run(ctx, "cat /etc/tunnel-operator/state.json")
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		return nil, fmt.Errorf("failed to parse state.json: %w", err)
	}
	return &st, nil
}

// writeState marshals st and persists it atomically to the VPS, creating the
// operator directory first.
func writeState(ctx context.Context, exec sshexec.Executor, st *State) error {
	if _, err := exec.Run(ctx, "mkdir -p /etc/tunnel-operator"); err != nil {
		return fmt.Errorf("failed to create tunnel-operator dir: %w", err)
	}
	b, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}
	return exec.Put(ctx, "/etc/tunnel-operator/state.json", b)
}

// applyTLSFiles writes cert and key material to /etc/envoy/tls on the VPS when
// the hash of the material has changed. Each file is written atomically via
// exec.Put (which uses a temp file + rename under the hood). The /etc/envoy/tls
// directory is created with mkdir -p before any Put so the first enrollment
// does not fail on a missing directory. On success the state TLSHash is updated
// and persisted so subsequent reconciles are no-ops.
func applyTLSFiles(ctx context.Context, exec sshexec.Executor, files []TLSFile, newHash string, state *State) (bool, error) {
	if state.TLSHash == newHash {
		return false, nil
	}
	if len(files) == 0 && newHash == hashTLSFiles(nil) {
		// Nothing to push and the state already reflects no TLS material;
		// clear the hash so it stays consistent.
		state.TLSHash = newHash
		return false, writeState(ctx, exec, state)
	}

	if _, err := exec.Run(ctx, "mkdir -p /etc/envoy/tls"); err != nil {
		return false, fmt.Errorf("failed to create /etc/envoy/tls: %w", err)
	}

	for _, f := range files {
		// Write to a temp path first, then chmod 600 and rename atomically so
		// Envoy never reads a partial file and the private key is never world
		// readable, not even briefly.
		tmp := f.Path + ".tmp"
		if err := exec.Put(ctx, tmp, f.Content); err != nil {
			return false, fmt.Errorf("failed to put TLS file %s: %w", f.Path, err)
		}
		cmd := fmt.Sprintf("chmod 600 %s && mv %s %s", tmp, tmp, f.Path)
		if _, err := exec.Run(ctx, cmd); err != nil {
			return false, fmt.Errorf("failed to install TLS file %s: %w", f.Path, err)
		}
	}

	state.TLSHash = newHash
	if err := writeState(ctx, exec, state); err != nil {
		return false, fmt.Errorf("failed to persist TLS state: %w", err)
	}
	return len(files) > 0, nil
}

// hashTLSFiles returns a deterministic hex-encoded SHA-256 hash of all TLS
// file paths and their contents. Files are sorted by path before hashing so
// the result is independent of slice order. An empty or nil slice returns the
// hash of an empty input.
func hashTLSFiles(files []TLSFile) string {
	if len(files) == 0 {
		return fmt.Sprintf("%x", sha256.Sum256(nil))
	}
	// Sort by path for determinism.
	sorted := make([]TLSFile, len(files))
	copy(sorted, files)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Path < sorted[j].Path
	})
	h := sha256.New()
	for _, f := range sorted {
		_, _ = h.Write([]byte(f.Path))
		_, _ = h.Write(f.Content)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
