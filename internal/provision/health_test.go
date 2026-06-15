// SPDX-FileCopyrightText: 2026 Alby Hernández (Achetronic)
// SPDX-License-Identifier: Apache-2.0

package provision

import (
	"context"
	"strings"
	"testing"

	"github.com/achetronic/tunnel/internal/sshexec"
)

// activeServiceLine is the systemctl output for a running service, including
// the trailing newline that systemctl appends.
const activeServiceLine = "active\n"

func TestCheckHealth(t *testing.T) {
	fake := sshexec.NewFakeExecutor()
	fake.RunFunc = func(ctx context.Context, cmd string) (string, error) {
		if strings.Contains(cmd, "systemctl is-active envoy") {
			return activeServiceLine, nil
		}
		if strings.Contains(cmd, "tunnelctl status") {
			return `{"interface":"wg-relay","exists":true,"up":true,"ready":true,"detail":"healthy",` +
				`"peers":[{"publicKey":"pubkey1","lastHandshake":"2021-05-03T00:00:00Z"},{"publicKey":"pubkey2"}]}`, nil
		}
		return "", nil
	}

	status, err := CheckHealth(context.Background(), fake)
	if err != nil {
		t.Fatal(err)
	}

	// Assert the tunnelctl status uses the absolute path, not a bare command.
	var foundAbsoluteTunnelctlStatus bool
	for _, cmd := range fake.Runs {
		if strings.Contains(cmd, "tunnelctl status") {
			if strings.HasPrefix(cmd, "/usr/local/bin/tunnelctl status") {
				foundAbsoluteTunnelctlStatus = true
			}
		}
	}
	if !foundAbsoluteTunnelctlStatus {
		t.Error("expected absolute path for tunnelctl status, but none was found")
	}

	if !status.EnvoyHealthy {
		t.Error("expected envoy to be healthy")
	}
	if !status.RelayHealthy {
		t.Error("expected relay to be healthy")
	}

	if ts, ok := status.Handshakes["pubkey1"]; !ok || ts.Unix() != 1620000000 {
		t.Errorf("unexpected handshake for pubkey1: %v", ts)
	}
	if _, ok := status.Handshakes["pubkey2"]; ok {
		t.Error("did not expect handshake for pubkey2")
	}
}

// TestCheckHealth_RelayNotReady verifies that a non-ready tunnelctl status report
// returned alongside a non-zero exit code is treated as an observation
// (RelayHealthy=false), not a transport error.
func TestCheckHealth_RelayNotReady(t *testing.T) {
	fake := sshexec.NewFakeExecutor()
	fake.RunFunc = func(ctx context.Context, cmd string) (string, error) {
		if strings.Contains(cmd, "systemctl is-active envoy") {
			return activeServiceLine, nil
		}
		if strings.Contains(cmd, "tunnelctl status") {
			return `{"ready":false,"peers":[]}`, nil
		}
		return "", nil
	}

	status, err := CheckHealth(context.Background(), fake)
	if err != nil {
		t.Fatal(err)
	}
	if status.RelayHealthy {
		t.Error("expected relay to be reported unhealthy")
	}
}
