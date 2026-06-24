// SPDX-FileCopyrightText: 2026 Alby Hernández (Achetronic)
// SPDX-License-Identifier: Apache-2.0

package provision

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
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
	relayDocumentPath = "/etc/tunnel/relay.json"
	// tunnelctlBinPath is where the tunnelctl binary is installed on the VPS.
	tunnelctlBinPath = "/usr/local/bin/tunnelctl"
	// envoyBinPath is the absolute path to the Envoy binary on the VPS.
	// This absolute path is used to invoke the binary directly.
	envoyBinPath = "/usr/local/bin/envoy"
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

	// Clean up stale temporary files from interrupted transfers in designated directories.
	sweepCmd := "find /usr/local/bin /etc/tunnel /etc/envoy /etc/envoy/tls /etc/systemd/system -maxdepth 1 -name '.tunnel.*' -delete 2>/dev/null || true"
	if _, err := exec.Run(ctx, sweepCmd); err != nil {
		slog.Warn("enroll: failed to sweep stale temporary files", "error", err)
	}

	tlsHash := HashTLSFiles(tlsFiles)

	bin, tunnelctlHash, err := resolveTunnelctlBinary(ctx, exec, plan.TunnelctlDir)
	if err != nil {
		return false, err
	}

	if stateErr == nil &&
		state.RelayDocumentHash == plan.RelayDocumentHash &&
		state.TunnelctlHash == tunnelctlHash &&
		state.EnvoyVersion == plan.EnvoyVersion &&
		state.EnvoyLDSHash == plan.EnvoyLDSHash &&
		state.EnvoyCDSHash == plan.EnvoyCDSHash &&
		state.TLSHash == tlsHash &&
		status.RelayHealthy && status.EnvoyHealthy {
		// Already up to date and healthy, nothing to do.
		slog.Debug("enroll: VPS already up to date and healthy, nothing to apply")
		return false, nil
	}

	if err := installTunnelctl(ctx, exec, bin, tunnelctlHash, state); err != nil {
		return false, err
	}
	replaced, err := installEnvoyBinary(ctx, exec, plan.EnvoyVersion)
	if err != nil {
		return false, err
	}
	if replaced || state.EnvoyVersion != plan.EnvoyVersion {
		state.EnvoyVersion = plan.EnvoyVersion
		if err := writeState(ctx, exec, state); err != nil {
			return false, fmt.Errorf("failed to persist envoy version state: %w", err)
		}
	}
	if err := writeEnvoyService(ctx, exec); err != nil {
		return false, err
	}
	if err := writeHostSysctls(ctx, exec, plan.KernelMaxSocketBufferBytes); err != nil {
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
	if err := ensureEnvoyRunning(ctx, exec, plan); err != nil {
		return false, err
	}
	if replaced {
		// Restart Envoy to pick up the newly installed binary since a live
		// systemd service does not automatically reload its binary on disk.
		// One redundant restart on a first enrollment is acceptable and harmless.
		if err := RestartEnvoy(ctx, exec); err != nil {
			return false, err
		}
	}
	return tlsApplied, nil
}

// resolveTunnelctlBinary detects the architecture of the VPS, reads the corresponding
// tunnelctl binary from the local tunnelctlDir, and computes its SHA-256 hash.
func resolveTunnelctlBinary(ctx context.Context, exec sshexec.Executor, tunnelctlDir string) (bin []byte, hash string, err error) {
	archOut, err := exec.Run(ctx, "uname -m")
	if err != nil {
		return nil, "", fmt.Errorf("failed to detect architecture: %w", err)
	}
	var arch string
	switch strings.TrimSpace(archOut) {
	case archX8664, archAMD64:
		arch = archAMD64
	case "aarch64", archARM64:
		arch = archARM64
	default:
		return nil, "", fmt.Errorf("unsupported architecture for tunnelctl: %s", strings.TrimSpace(archOut))
	}

	localPath := filepath.Join(tunnelctlDir, "tunnelctl-linux-"+arch)
	bin, err = os.ReadFile(localPath)
	if err != nil {
		return nil, "", fmt.Errorf("read tunnelctl binary %q: %w", localPath, err)
	}
	hash = fmt.Sprintf("%x", sha256.Sum256(bin))
	return bin, hash, nil
}

// installTunnelctl pushes the static tunnelctl binary matching the host
// architecture to the VPS. The binary and its hash are resolved beforehand.
// The install is idempotent: it skips the push only when the persisted state records the same
// binary hash AND the binary is actually present (so a rebuilt VPS still gets it).
// On a successful push it persists the new hash so subsequent reconciles are no-ops.
func installTunnelctl(ctx context.Context, exec sshexec.Executor, bin []byte, hash string, state *State) error {
	if state.TunnelctlHash == hash {
		if _, err := exec.Run(ctx, "test -x "+tunnelctlBinPath); err == nil {
			return nil
		} else if !isExitError(err) {
			return fmt.Errorf("failed to check tunnelctl presence: %w", err)
		}
	}

	slog.Info("enroll: pushing tunnelctl binary", "hash", hash)
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

// envoyVersionPattern constrains the Envoy release string interpolated into
// root shell commands on the VPS (the download URL and the version probe). The
// value is operator-controlled (--envoy-version flag), but a typo must fail
// validation, not become a root RCE. Bare semver only, no leading "v": the
// download URL template already prefixes it.
var envoyVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

// installEnvoyBinary installs the requested Envoy release on the VPS, matching
// the host architecture. The download URL is built from version and the arch
// suffix rather than hardcoded. The install is version-aware: it (re)downloads
// only when no envoy is present or the installed one is a different version, so
// changing EnvoyVersion on the EdgeNode actually replaces the binary (a running
// envoy still needs its service restart, handled by ensureEnvoyRunning).
func installEnvoyBinary(ctx context.Context, exec sshexec.Executor, version string) (replaced bool, err error) {
	if !envoyVersionPattern.MatchString(version) {
		return false, fmt.Errorf("invalid envoy version %q: must match %s", version, envoyVersionPattern)
	}
	archOut, err := exec.Run(ctx, "uname -m")
	if err != nil {
		return false, fmt.Errorf("failed to detect architecture: %w", err)
	}
	arch := strings.TrimSpace(archOut)

	var archSuffix string
	switch arch {
	case archX8664, archAMD64:
		archSuffix = archX8664
	case "aarch64", "arm64":
		archSuffix = "aarch_64"
	default:
		return false, fmt.Errorf("unsupported architecture for Envoy: %s", arch)
	}

	downloadURL := fmt.Sprintf(
		"https://github.com/envoyproxy/envoy/releases/download/v%s/envoy-%s-linux-%s",
		version, version, archSuffix,
	)

	// Reinstall when envoy is absent or reports a different version. Envoy's
	// --version output embeds the release as "/<version>/".
	probeOut, probeErr := exec.Run(ctx, envoyBinPath+" --version 2>/dev/null")
	if probeErr != nil && !isExitError(probeErr) {
		return false, fmt.Errorf("failed to probe envoy version: %w", probeErr)
	}

	if probeErr == nil && strings.Contains(probeOut, fmt.Sprintf("/%s/", version)) {
		return false, nil
	}

	downloadCmd := fmt.Sprintf(
		"curl -fsL %s -o /tmp/envoy && chmod +x /tmp/envoy && mv /tmp/envoy %s",
		downloadURL,
		envoyBinPath,
	)

	slog.Info("enroll: ensuring envoy binary (downloads on first run or version change)", "arch", arch, "version", version)
	if _, err := exec.Run(ctx, downloadCmd); err != nil {
		return false, fmt.Errorf("failed to install envoy binary: %w", err)
	}
	return true, nil
}

// writeEnvoyService installs the Envoy systemd unit and a boot-time oneshot
// (tunnel-boot.service) that reapplies the whole node desired-state document,
// then reloads systemd and enables both so they come back after a VPS reboot.
// The wg-relay interface is created natively by tunnelctl and is not
// kernel-persistent, so without a boot unit a reboot leaves Envoy unable to bind
// its admin to the tunnel IP and unable to reach the uplinks until the next
// operator reconcile. The tunnel-boot oneshot runs the same tunnelctl already on
// the host (no resident daemon), reapplying the relay document (WireGuard plus
// any netdev tuning), and the Envoy unit depends on it so the relay is up before
// Envoy starts. The systemd unit is named tunnel-boot.service; the WireGuard
// interface it brings up is still wg-relay.
func writeEnvoyService(ctx context.Context, exec sshexec.Executor) error {
	bootService := `[Unit]
Description=Tunnel node boot reconcile
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=` + tunnelctlBinPath + ` apply --config ` + relayDocumentPath + `

[Install]
WantedBy=multi-user.target
`
	envoyService := `[Unit]
Description=Envoy Proxy
After=network.target tunnel-boot.service
Requires=tunnel-boot.service

[Service]
ExecStart=` + envoyBinPath + ` -c /etc/envoy/envoy.yaml
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`
	if _, err := exec.Run(ctx, "mkdir -p /etc/envoy"); err != nil {
		return fmt.Errorf("failed to create envoy dir: %w", err)
	}
	if err := exec.Put(ctx, "/etc/systemd/system/tunnel-boot.service", []byte(bootService)); err != nil {
		return fmt.Errorf("failed to write tunnel-boot.service: %w", err)
	}
	if err := exec.Put(ctx, "/etc/systemd/system/envoy.service", []byte(envoyService)); err != nil {
		return fmt.Errorf("failed to write envoy.service: %w", err)
	}
	if _, err := exec.Run(ctx, "systemctl daemon-reload"); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}
	// Enable tunnel-boot so the relay is reapplied on boot. Envoy is enabled
	// alongside its start in ensureEnvoyRunning; enabling tunnel-boot here keeps
	// the boot-survival contract in one place.
	if _, err := exec.Run(ctx, "systemctl enable tunnel-boot.service"); err != nil {
		return fmt.Errorf("failed to enable tunnel-boot.service: %w", err)
	}
	return nil
}

// sysctlDropInPath is the persisted sysctl drop-in the operator owns on the VPS.
const sysctlDropInPath = "/etc/sysctl.d/99-tunnel.conf"

// defaultKernelMaxSocketBufferBytes is the socket-buffer ceiling used when the
// plan carries a non-positive value, mirroring the planner/CRD default (25MB).
// It keeps the sysctl drop-in valid even if a caller builds a Plan directly.
const defaultKernelMaxSocketBufferBytes int64 = 26214400

// writeHostSysctls installs the operator's sysctl drop-in on the VPS in a single
// overwrite (never an append, so re-applying never duplicates lines) and applies
// it with "sysctl -p". It enables IPv4 forwarding so the relay routes between
// WireGuard peers, and raises the kernel socket-buffer ceiling
// (net.core.rmem_max/wmem_max) to the configured value so high-throughput UDP
// listeners can use larger SO_RCVBUF/SO_SNDBUF (UDP does not autotune).
func writeHostSysctls(ctx context.Context, exec sshexec.Executor, bufferBytes int64) error {
	if bufferBytes <= 0 {
		bufferBytes = defaultKernelMaxSocketBufferBytes
	}
	// Managed drop-in: a single overwrite keeps it idempotent across reconciles.
	// Docs: kernel ip-sysctl (ip_forward) and admin-guide/sysctl/net (core buffers).
	content := fmt.Sprintf(`# Managed by Tunnel. Do not edit; this file is overwritten on every reconcile.
# IPv4 forwarding lets the relay route traffic between WireGuard peers.
# https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt
net.ipv4.ip_forward=1
# Socket-buffer ceiling for high-throughput UDP listeners. UDP does not autotune,
# so Envoy sets SO_RCVBUF/SO_SNDBUF up to this maximum; TCP autotunes below it.
# https://www.kernel.org/doc/Documentation/admin-guide/sysctl/net.rst
net.core.rmem_max=%d
net.core.wmem_max=%d
`, bufferBytes, bufferBytes)

	if err := exec.Put(ctx, sysctlDropInPath, []byte(content)); err != nil {
		return fmt.Errorf("failed to write sysctl drop-in: %w", err)
	}
	if _, err := exec.Run(ctx, "sysctl -p "+sysctlDropInPath); err != nil {
		return fmt.Errorf("failed to apply sysctl drop-in: %w", err)
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

	if _, err := exec.Run(ctx, "mkdir -p /etc/tunnel"); err != nil {
		return fmt.Errorf("failed to create tunnel dir: %w", err)
	}

	tmp := relayDocumentPath + ".tmp"
	if err := exec.Put(ctx, tmp, plan.RelayDocument); err != nil {
		return fmt.Errorf("failed to put relay document: %w", err)
	}
	if _, err := exec.Run(ctx, fmt.Sprintf("chmod 600 %s && mv %s %s", tmp, tmp, relayDocumentPath)); err != nil {
		return fmt.Errorf("failed to install relay document: %w", err)
	}

	if _, err := exec.Run(ctx, tunnelctlBinPath+" apply --config "+relayDocumentPath); err != nil {
		return fmt.Errorf("failed to apply relay document: %w", err)
	}

	state.RelayDocumentHash = plan.RelayDocumentHash
	if err := writeState(ctx, exec, state); err != nil {
		return fmt.Errorf("failed to persist relay document state: %w", err)
	}
	return nil
}

// applyEnvoyConfig syncs the Envoy LDS and CDS discovery files when their plan
// hashes changed, persisting each new hash as it is applied. CDS is written
// before LDS: Envoy loads clusters independently, so writing the cluster first
// guarantees that if the connection drops between the two writes, the existing
// listeners still reference present clusters and a newly added listener never
// references a cluster that has not arrived yet.
func applyEnvoyConfig(ctx context.Context, exec sshexec.Executor, plan *planner.Plan, state *State) error {
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
	return nil
}

// ensureEnvoyRunning installs the static bootstrap that points Envoy at the
// LDS/CDS files and makes sure the service is active. Envoy reads its bootstrap
// only at startup, so it is rewritten and the service restarted only when the
// bootstrap on the VPS differs from the desired one; an Envoy whose bootstrap
// already matches is left running so steady-state reconciles never bounce live
// connections. On default-network nodes the bootstrap is byte-identical across
// operator versions, so an upgrade triggers no restart.
func ensureEnvoyRunning(ctx context.Context, exec sshexec.Executor, plan *planner.Plan) error {
	slog.Info("enroll: ensuring envoy is running")
	if plan == nil {
		return fmt.Errorf("ensureEnvoyRunning: plan is nil")
	}
	if plan.RelayIP == "" {
		return fmt.Errorf("ensureEnvoyRunning: plan.RelayIP is empty")
	}

	// node id/cluster are mandatory in the bootstrap when dynamic_resources
	// (file-based LDS/CDS) are used, otherwise Envoy refuses to load the config.
	bootstrapYAML := fmt.Sprintf(`node:
  id: tunnel-relay
  cluster: tunnel-relay

admin:
  address:
    socket_address:
      address: %s
      port_value: 40600

dynamic_resources:
  lds_config:
    path_config_source:
      path: /etc/envoy/lds.yaml
  cds_config:
    path_config_source:
      path: /etc/envoy/cds.yaml
`, plan.RelayIP)

	currentYAML, err := exec.Run(ctx, "cat /etc/envoy/envoy.yaml")
	var needsUpdate bool
	if err != nil {
		if isExitError(err) {
			// The file is missing or cat returned non-zero. Treat as different/missing.
			needsUpdate = (currentYAML != bootstrapYAML)
		} else {
			return fmt.Errorf("failed to read remote envoy bootstrap: %w", err)
		}
	} else {
		needsUpdate = (currentYAML != bootstrapYAML)
	}

	if needsUpdate {
		slog.Info("enroll: envoy bootstrap configuration differs or is missing, writing new config and restarting envoy")
		if err := exec.Put(ctx, "/etc/envoy/envoy.yaml", []byte(bootstrapYAML)); err != nil {
			return fmt.Errorf("failed to put envoy.yaml bootstrap: %w", err)
		}
		if _, err := exec.Run(ctx, "systemctl enable envoy && systemctl restart envoy"); err != nil {
			return fmt.Errorf("failed to restart envoy after bootstrap update: %w", err)
		}
	} else {
		// The bootstrap on the VPS already matches. Start envoy only when it is
		// not active (failed or auto-restarting from a previous bad config); a
		// healthy envoy is left untouched so steady-state reconciles never
		// bounce live connections.
		out, err := exec.Run(ctx, "systemctl is-active envoy")
		if err != nil && !isExitError(err) {
			return fmt.Errorf("failed to query envoy status: %w", err)
		}
		if strings.TrimSpace(out) != serviceActive {
			if _, err := exec.Run(ctx, "systemctl enable envoy && systemctl restart envoy"); err != nil {
				return fmt.Errorf("failed to start envoy: %w", err)
			}
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
	const attempts = 30
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
	out, err := exec.Run(ctx, "cat /etc/tunnel/state.json")
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		slog.Warn("enroll: failed to parse state.json, treating as empty state", "error", err)
		return &State{}, nil
	}
	return &st, nil
}

// writeState marshals st and persists it atomically to the VPS, creating the
// operator directory first.
func writeState(ctx context.Context, exec sshexec.Executor, st *State) error {
	if _, err := exec.Run(ctx, "mkdir -p /etc/tunnel"); err != nil {
		return fmt.Errorf("failed to create tunnel dir: %w", err)
	}
	b, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}
	return exec.Put(ctx, "/etc/tunnel/state.json", b)
}

// tlsDirPath is the directory on the VPS holding the per-binding SDS documents.
// It is also the watched_directory Envoy monitors for atomic moves to reload a
// rotated certificate gracefully. The operator owns it exclusively.
const tlsDirPath = "/etc/envoy/tls"

// safeTLSArtifact matches the file names the operator is willing to delete when
// pruning stale TLS material: the SDS documents it writes today plus the
// cert/key files left by the pre-SDS layout. It is deliberately conservative so
// an unexpected file in the directory is never removed, and rules out shell
// metacharacters in a name that would otherwise reach a remote command.
var safeTLSArtifact = regexp.MustCompile(`^[A-Za-z0-9._-]+\.(sds\.yaml|crt|key)$`)

// applyTLSFiles syncs the per-binding SDS documents under /etc/envoy/tls on the
// VPS when the hash of the material has changed. Each file is written atomically
// (temp + chmod 600 + rename) so Envoy never reads a partial file, the private
// key is never world readable, and the move triggers Envoy's graceful SDS
// reload. After writing the desired set it prunes any stale TLS material left
// behind by removed bindings (or by the pre-SDS cert/key layout) so private keys
// never linger on the edge. On success the state TLSHash is updated and
// persisted so subsequent reconciles are no-ops.
func applyTLSFiles(ctx context.Context, exec sshexec.Executor, files []TLSFile, newHash string, state *State) (bool, error) {
	if state.TLSHash == newHash {
		return false, nil
	}

	if len(files) > 0 {
		if _, err := exec.Run(ctx, "mkdir -p "+tlsDirPath); err != nil {
			return false, fmt.Errorf("failed to create %s: %w", tlsDirPath, err)
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
	}

	// Remove TLS material for bindings that no longer exist (and any pre-SDS
	// cert/key files) so a deleted binding does not leave its private key on the
	// edge until full teardown.
	if err := pruneTLSFiles(ctx, exec, files); err != nil {
		return false, err
	}

	state.TLSHash = newHash
	if err := writeState(ctx, exec, state); err != nil {
		return false, fmt.Errorf("failed to persist TLS state: %w", err)
	}
	return len(files) > 0, nil
}

// pruneTLSFiles removes every TLS-material file in tlsDirPath that is not part of
// the desired set. It only ever deletes names matching safeTLSArtifact, so an
// unrelated file dropped in the directory is left untouched. A missing directory
// is fine (nothing to prune): ls exits non-zero, which is an *ssh.ExitError and
// not a transport failure.
func pruneTLSFiles(ctx context.Context, exec sshexec.Executor, desired []TLSFile) error {
	keep := make(map[string]struct{}, len(desired))
	for _, f := range desired {
		keep[filepath.Base(f.Path)] = struct{}{}
	}

	out, err := exec.Run(ctx, "ls -1 "+tlsDirPath+" 2>/dev/null")
	if err != nil {
		if isExitError(err) {
			// Directory absent (or empty with a shell that errors): nothing to prune.
			return nil
		}
		return fmt.Errorf("failed to list %s for pruning: %w", tlsDirPath, err)
	}

	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		name := strings.TrimSpace(line)
		if name == "" || !safeTLSArtifact.MatchString(name) {
			continue
		}
		if _, ok := keep[name]; ok {
			continue
		}
		slog.Info("enroll: pruning stale TLS material", "file", name)
		if _, err := exec.Run(ctx, "rm -f "+tlsDirPath+"/"+name); err != nil {
			return fmt.Errorf("failed to remove stale TLS file %q: %w", name, err)
		}
	}
	return nil
}

// HashTLSFiles returns a deterministic hex-encoded SHA-256 hash of all TLS
// file paths and their contents. Files are sorted by path for determinism so
// the result is independent of slice order. An empty or nil slice returns the
// hash of an empty input.
func HashTLSFiles(files []TLSFile) string {
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
