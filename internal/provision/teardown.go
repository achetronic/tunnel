// SPDX-FileCopyrightText: 2026 Alby Hernández (Achetronic)
// SPDX-License-Identifier: Apache-2.0

package provision

import (
	"context"
	"fmt"

	"github.com/achetronic/tunnel/internal/sshexec"
)

// Teardown cleans up the VPS when the EdgeNode is deleted. It reverses what
// Enroll provisions: it removes the WireGuard relay interface and Envoy
// service plus their configuration, the systemd unit, the sysctl drop-in, the
// tunnelctl binary and the operator state directory.
//
// Service-stop commands are made idempotent with a trailing "|| true" so that
// a missing unit or interface (e.g. the relay was never started) is not treated
// as a failure, while genuine command execution errors are still surfaced and
// handled explicitly. Every command is bounded by ctx.
func Teardown(ctx context.Context, exec sshexec.Executor) error {
	// WireGuard relay interface (created natively by tunnelctl apply, no service).
	if _, err := exec.Run(ctx, "ip link del wg-relay || true"); err != nil {
		return fmt.Errorf("failed to delete wg-relay interface: %w", err)
	}
	if _, err := exec.Run(ctx, "rm -f "+tunnelctlBinPath); err != nil {
		return fmt.Errorf("failed to remove tunnelctl binary: %w", err)
	}

	// Envoy service and configuration (envoy.yaml, lds.yaml, cds.yaml) and wg-relay service
	if _, err := exec.Run(ctx, "systemctl disable --now envoy || true"); err != nil {
		return fmt.Errorf("failed to stop envoy: %w", err)
	}
	if _, err := exec.Run(ctx, "systemctl disable --now wg-relay.service || true"); err != nil {
		return fmt.Errorf("failed to stop wg-relay.service: %w", err)
	}
	if _, err := exec.Run(ctx, "rm -f /etc/systemd/system/envoy.service"); err != nil {
		return fmt.Errorf("failed to remove envoy.service: %w", err)
	}
	if _, err := exec.Run(ctx, "rm -f /etc/systemd/system/wg-relay.service"); err != nil {
		return fmt.Errorf("failed to remove wg-relay.service: %w", err)
	}
	if _, err := exec.Run(ctx, "systemctl daemon-reload || true"); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}
	if _, err := exec.Run(ctx, "rm -rf /etc/envoy"); err != nil {
		return fmt.Errorf("failed to remove envoy dir: %w", err)
	}

	// Sysctl drop-in installed during enrollment
	if _, err := exec.Run(ctx, "rm -f /etc/sysctl.d/99-tunnel.conf"); err != nil {
		return fmt.Errorf("failed to remove sysctl drop-in: %w", err)
	}

	// Operator state (state.json, vps.priv)
	if _, err := exec.Run(ctx, "rm -rf /etc/tunnel"); err != nil {
		return fmt.Errorf("failed to remove tunnel dir: %w", err)
	}

	return nil
}
