package provision

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/achetronic/tunnel/internal/sshexec"
)

// statusReport mirrors the JSON document tunnelctl prints on "status". Only the
// fields the operator consumes are decoded.
type statusReport struct {
	Ready bool `json:"ready"`
	Peers []struct {
		PublicKey     string `json:"publicKey"`
		LastHandshake string `json:"lastHandshake,omitempty"`
	} `json:"peers"`
}

// CheckHealth queries the VPS for the status of envoy and the WireGuard relay.
// The relay state comes from "tunnelctl status", which prints a JSON report and
// exits non-zero when the interface is not ready; both the report and the exit
// code are observations, not failures, so a not-ready relay (or a not-yet-
// installed tunnelctl on the first enrollment) is reported as RelayHealthy=false
// rather than erroring. Transport/network failures are still returned as errors
// so callers can distinguish an unreachable VPS from an unhealthy service. The
// context bounds every remote command and cancels any pending retry backoff.
func CheckHealth(ctx context.Context, exec sshexec.Executor) (*HealthStatus, error) {
	status := &HealthStatus{
		Handshakes: make(map[string]time.Time),
	}

	out, err := runWithRetry(ctx, exec, "systemctl is-active envoy")
	if err != nil && !isExitError(err) {
		return nil, fmt.Errorf("failed to query envoy status: %w", err)
	}
	status.EnvoyHealthy = (err == nil && strings.TrimSpace(out) == serviceActive)

	// tunnelctl status exits non-zero when the relay is not ready (or absent),
	// but still prints its JSON report. A missing binary/config on the first
	// enrollment also surfaces as an exit error, which we treat as not-healthy.
	out, err = runWithRetry(ctx, exec, fmt.Sprintf("%s status --config %s", tunnelctlBinPath, relayDocumentPath))
	if err != nil && !isExitError(err) {
		return nil, fmt.Errorf("failed to query relay status: %w", err)
	}
	parseRelayStatus(out, status)

	return status, nil
}

// parseRelayStatus decodes the tunnelctl status JSON into the HealthStatus,
// filling RelayHealthy from the report's readiness and the Handshakes map from
// its peers. Unparseable output (for example a "command not found" message
// before tunnelctl is installed) leaves the relay marked unhealthy.
func parseRelayStatus(out string, status *HealthStatus) {
	out = strings.TrimSpace(out)
	if out == "" {
		return
	}
	var report statusReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		return
	}
	status.RelayHealthy = report.Ready
	for _, p := range report.Peers {
		if p.LastHandshake == "" {
			continue
		}
		ts, err := time.Parse(time.RFC3339, p.LastHandshake)
		if err != nil {
			continue
		}
		status.Handshakes[p.PublicKey] = ts
	}
}
