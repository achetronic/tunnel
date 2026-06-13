package sshexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// syncBuffer is a bytes.Buffer safe for concurrent use. The SSH library copies
// the remote stdout/stderr into it from its own goroutines while Run may read
// it after cancelling the session, so every access has to be synchronised to
// avoid a data race.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// Write appends p to the buffer under the lock.
func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// String returns the buffered contents under the lock.
func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

const (
	// defaultKeepaliveInterval is how often keepalive requests probe the
	// connection when Config.KeepaliveInterval is zero.
	defaultKeepaliveInterval = 15 * time.Second

	// defaultCommandTimeout bounds a single Run/Put when neither the caller's
	// context nor Config.CommandTimeout provides a deadline.
	defaultCommandTimeout = 5 * time.Minute
)

// NewSSHExecutor connects to the VPS via SSH and returns a ready Executor.
// It starts a background keepalive loop so half-dead connections (NAT
// timeouts, a rebooted VPS) surface as errors instead of hanging forever.
// The caller owns the returned executor and must Close it.
func NewSSHExecutor(cfg Config) (*SSHExecutor, error) {
	var auth []ssh.AuthMethod
	if cfg.PrivateKey != "" {
		var signer ssh.Signer
		var err error
		if cfg.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(cfg.PrivateKey), []byte(cfg.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(cfg.PrivateKey))
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	} else if cfg.Password != "" {
		auth = append(auth, ssh.Password(cfg.Password))
	}

	hostKeyCb, err := hostKeyCallback(cfg)
	if err != nil {
		return nil, err
	}

	config := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            auth,
		HostKeyCallback: hostKeyCb,
		Timeout:         cfg.ConnectTimeout,
	}

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, fmt.Errorf("failed to dial SSH %s: %w", addr, err)
	}

	keepalive := cfg.KeepaliveInterval
	if keepalive <= 0 {
		keepalive = defaultKeepaliveInterval
	}
	cmdTimeout := cfg.CommandTimeout
	if cmdTimeout <= 0 {
		cmdTimeout = defaultCommandTimeout
	}

	e := &SSHExecutor{
		client:            client,
		keepaliveInterval: keepalive,
		commandTimeout:    cmdTimeout,
		stop:              make(chan struct{}),
	}
	go e.keepaliveLoop()
	return e, nil
}

// keepaliveLoop periodically sends an OpenSSH keepalive request so a dead
// peer is detected within a couple of intervals. It exits when the executor
// is closed or when a keepalive request fails (the connection is gone).
func (e *SSHExecutor) keepaliveLoop() {
	ticker := time.NewTicker(e.keepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-ticker.C:
			if _, _, err := e.client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				return
			}
		}
	}
}

// Close stops the keepalive loop and closes the underlying SSH connection.
// It is safe to call more than once.
func (e *SSHExecutor) Close() error {
	e.closeOnce.Do(func() {
		close(e.stop)
	})
	return e.client.Close()
}

// Run executes cmd on the VPS and returns its combined stdout/stderr.
// The command runs in its own session, which is closed when the bounded
// context is done so a hanging remote command cannot block the caller
// forever. A failing command surfaces stderr wrapped with %w.
func (e *SSHExecutor) Run(ctx context.Context, cmd string) (out string, err error) {
	ctx, cancel := e.withTimeout(ctx)
	defer cancel()

	session, err := e.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to open SSH session: %w", err)
	}
	defer func() {
		if cerr := session.Close(); cerr != nil && !errors.Is(cerr, io.EOF) {
			err = errors.Join(err, fmt.Errorf("failed to close SSH session: %w", cerr))
		}
	}()

	var buf syncBuffer
	session.Stdout = &buf
	session.Stderr = &buf

	done := make(chan error, 1)
	go func() {
		done <- session.Run(cmd)
	}()

	select {
	case <-ctx.Done():
		// Closing the session unblocks the goroutine's session.Run.
		_ = session.Close()
		e.awaitOrTeardown(done)
		return buf.String(), fmt.Errorf("command %q cancelled: %w", cmd, ctx.Err())
	case runErr := <-done:
		if runErr != nil {
			return "", fmt.Errorf("command %q failed: %s: %w", cmd, buf.String(), runErr)
		}
		return buf.String(), nil
	}
}

// Put writes content to the remote path atomically. It streams to a private
// temporary file created with mktemp (umask 077) and then moves it into place
// with a single mv, so a partial transfer never leaves a truncated config in
// the live path. The error of closing the session is combined with the return.
func (e *SSHExecutor) Put(ctx context.Context, path string, content []byte) (err error) {
	if verr := validateRemotePath(path); verr != nil {
		return verr
	}

	ctx, cancel := e.withTimeout(ctx)
	defer cancel()

	session, err := e.client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to open SSH session for %s: %w", path, err)
	}
	defer func() {
		if cerr := session.Close(); cerr != nil && !errors.Is(cerr, io.EOF) {
			err = errors.Join(err, fmt.Errorf("failed to close SSH session for %s: %w", path, cerr))
		}
	}()

	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to open remote stdin for %s: %w", path, err)
	}

	// Create a private temp file next to the target, stream into it, verify the
	// byte count, and move it atomically into place.
	script := fmt.Sprintf(
		"set -e; d=$(dirname %[1]s); tmp=$(umask 077 && mktemp \"$d/.tunnel.XXXXXX\"); cat > \"$tmp\"; mv -f \"$tmp\" %[1]s",
		shellQuote(path),
	)
	if err := session.Start(script); err != nil {
		return fmt.Errorf("failed to start remote write for %s: %w", path, err)
	}

	copyErr := make(chan error, 1)
	go func() {
		_, cerr := io.Copy(stdin, bytes.NewReader(content))
		if closeErr := stdin.Close(); closeErr != nil && cerr == nil {
			cerr = closeErr
		}
		copyErr <- cerr
	}()

	select {
	case <-ctx.Done():
		_ = session.Close()
		e.awaitOrTeardown(copyErr)
		return fmt.Errorf("write to %s cancelled: %w", path, ctx.Err())
	case cerr := <-copyErr:
		if cerr != nil {
			_ = session.Close()
			return fmt.Errorf("failed to stream content to %s: %w", path, cerr)
		}
	}

	waitErr := make(chan error, 1)
	go func() {
		waitErr <- session.Wait()
	}()

	select {
	case <-ctx.Done():
		_ = session.Close()
		e.awaitOrTeardown(waitErr)
		return fmt.Errorf("write to %s cancelled: %w", path, ctx.Err())
	case werr := <-waitErr:
		if werr != nil {
			return fmt.Errorf("remote write of %s failed: %w", path, werr)
		}
	}
	return nil
}

// withTimeout returns ctx unchanged when it already carries a deadline,
// otherwise it derives one bounded by the executor's commandTimeout so a
// missing deadline never lets a remote command hang indefinitely.
func (e *SSHExecutor) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, e.commandTimeout)
}

// teardownGrace bounds how long a cancelled command waits for its session
// goroutine after session.Close. Close only sends MSG_CHANNEL_CLOSE over the
// wire; against a silently dead peer (a NAT-dropped connection with no RST)
// the mux read otherwise blocks until the kernel TCP retransmission timeout,
// holding the caller far beyond its context deadline.
const teardownGrace = 10 * time.Second

// awaitOrTeardown waits for the session goroutine to finish after a
// cancellation. If it does not finish within teardownGrace, the whole client
// connection is closed to tear down the SSH mux, which unblocks every pending
// read and write. The forced close sacrifices the executor for further use,
// which is acceptable because the controller builds one executor per reconcile
// and closes it afterwards.
func (e *SSHExecutor) awaitOrTeardown(ch <-chan error) {
	select {
	case <-ch:
	case <-time.After(teardownGrace):
		_ = e.Close()
		<-ch
	}
}
