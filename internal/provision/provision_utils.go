// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package provision

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/achetronic/tunnel/internal/sshexec"
	"golang.org/x/crypto/ssh"
)

const (
	// retryAttempts is how many times runWithRetry runs a command before
	// giving up on transient SSH/network failures.
	retryAttempts = 3
	// retryBaseDelay is the first backoff delay; it doubles each attempt.
	retryBaseDelay = 500 * time.Millisecond
	// retryMaxDelay caps the exponential backoff.
	retryMaxDelay = 4 * time.Second
	// serviceActive is the systemctl output string for a running service.
	serviceActive = "active"
)

// runWithRetry executes cmd, retrying transient SSH/network failures with
// exponential backoff. A command that runs but exits non-zero (*ssh.ExitError)
// is returned immediately, since retrying would not change the outcome. The
// backoff respects ctx so a shutdown cancels the wait instead of blocking.
// On exhaustion it returns the last output together with the last error.
func runWithRetry(ctx context.Context, exec sshexec.Executor, cmd string) (string, error) {
	var lastOut string
	var lastErr error
	delay := retryBaseDelay

	for attempt := range retryAttempts {
		out, err := exec.Run(ctx, cmd)
		if err == nil {
			return out, nil
		}
		if isExitError(err) {
			return out, err
		}
		lastOut, lastErr = out, err

		if attempt == retryAttempts-1 {
			break
		}
		select {
		case <-ctx.Done():
			return lastOut, fmt.Errorf("retry of %q cancelled: %w", cmd, ctx.Err())
		case <-time.After(delay):
		}
		if delay *= 2; delay > retryMaxDelay {
			delay = retryMaxDelay
		}
	}
	return lastOut, fmt.Errorf("command %q failed after %d attempts: %w", cmd, retryAttempts, lastErr)
}

// isExitError reports whether err is an SSH remote command exit error (the
// command ran but returned a non-zero status), as opposed to a transport or
// network failure.
func isExitError(err error) bool {
	var exitErr *ssh.ExitError
	return errors.As(err, &exitErr)
}
