// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package sshexec

import (
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Config holds the parameters needed to open an SSH connection to the VPS.
type Config struct {
	// Host is the VPS address (IP or DNS name).
	Host string
	// Port is the SSH TCP port.
	Port int32
	// User is the SSH login user.
	User string
	// Password is an optional password used when PrivateKey is empty.
	Password string
	// PrivateKey is an optional PEM-encoded private key for public key auth.
	PrivateKey string
	// Passphrase decrypts PrivateKey when it is encrypted.
	Passphrase string

	// KnownHosts is the OpenSSH known_hosts content used to verify the VPS host
	// key (e.g. the output of "ssh-keyscan").
	KnownHosts string

	// InsecureSkipHostKeyVerification disables host key verification. It is only
	// honoured when KnownHosts is empty.
	InsecureSkipHostKeyVerification bool

	// ConnectTimeout bounds the TCP/SSH dial. A zero value means no timeout.
	ConnectTimeout time.Duration

	// KeepaliveInterval is how often a "keepalive@openssh.com" request is sent
	// to detect half-dead connections. A zero value applies a sane default.
	KeepaliveInterval time.Duration

	// CommandTimeout is the default per-command deadline applied when the
	// caller's context has no deadline of its own. A zero value applies a
	// sane default.
	CommandTimeout time.Duration
}

// SSHExecutor is the real Executor implementation backed by a live SSH
// connection to the VPS. It is the only place in the operator that performs
// real IO against the remote host.
type SSHExecutor struct {
	client            *ssh.Client
	keepaliveInterval time.Duration
	commandTimeout    time.Duration

	// stop signals the keepalive goroutine to exit when the executor closes.
	stop chan struct{}
	// closeOnce guards Close so the stop channel is only closed once.
	closeOnce sync.Once
}
