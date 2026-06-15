// SPDX-FileCopyrightText: 2026 Alby Hernández (Achetronic)
// SPDX-License-Identifier: Apache-2.0

package sshexec

import "context"

// Executor is the single boundary for interacting with the VPS over SSH.
// Every method takes a context so callers can bound and cancel each remote
// operation independently. Implementations must honour ctx cancellation:
// when ctx is done they have to abort the in-flight command and return
// ctx.Err() wrapped with operational context.
type Executor interface {
	// Run executes cmd on the VPS and returns its combined stdout/stderr.
	// It must return promptly when ctx is cancelled, even if the remote
	// command is still hanging.
	Run(ctx context.Context, cmd string) (string, error)

	// Put writes content to the remote path atomically. It must abort and
	// clean up when ctx is cancelled.
	Put(ctx context.Context, path string, content []byte) error
}
