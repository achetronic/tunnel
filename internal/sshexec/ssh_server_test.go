package sshexec

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// execHandler decides how the test SSH server answers a single "exec" request.
// It receives the requested command and the channel; it returns the exit
// status to send back. Returning a non-zero status makes the client observe an
// *ssh.ExitError.
type execHandler func(t *testing.T, cmd string, ch ssh.Channel) uint32

// testSSHServer is a minimal in-memory SSH server used to exercise the real
// Run/Put code paths (sessions, exec, stdin streaming, exit codes) without a
// VPS.
type testSSHServer struct {
	listener net.Listener
	config   *ssh.ServerConfig
	handler  execHandler
	wg       sync.WaitGroup
}

// newTestSSHServer starts a server on localhost that authenticates any client
// and dispatches exec requests to handler. The returned Config dials it.
func newTestSSHServer(t *testing.T, handler execHandler) (Config, *testSSHServer) {
	t.Helper()

	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromSigner(hostPriv)
	if err != nil {
		t.Fatalf("failed to build host signer: %v", err)
	}

	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	srv := &testSSHServer{listener: ln, config: cfg, handler: handler}
	srv.wg.Add(1)
	go srv.serve(t)

	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to split addr: %v", err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("failed to parse port: %v", err)
	}

	clientCfg := Config{
		Host:                            host,
		Port:                            int32(port),
		InsecureSkipHostKeyVerification: true,
		ConnectTimeout:                  5 * time.Second,
		KeepaliveInterval:               50 * time.Millisecond,
		CommandTimeout:                  2 * time.Second,
	}
	return clientCfg, srv
}

// serve accepts a single connection and handles its channels.
func (s *testSSHServer) serve(t *testing.T) {
	defer s.wg.Done()
	conn, err := s.listener.Accept()
	if err != nil {
		return
	}
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.config)
	if err != nil {
		return
	}
	defer func() { _ = sshConn.Close() }()
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only session supported")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			return
		}
		go s.handleSession(t, ch, chReqs)
	}
}

// handleSession waits for an exec request and runs the configured handler.
func (s *testSSHServer) handleSession(t *testing.T, ch ssh.Channel, reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "exec":
			cmd := parseExecPayload(req.Payload)
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			status := s.handler(t, cmd, ch)
			sendExitStatus(ch, status)
			_ = ch.Close()
			return
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

// parseExecPayload extracts the command string from an exec request payload,
// which is a 4-byte length prefix followed by the command bytes.
func parseExecPayload(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	n := int(payload[0])<<24 | int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if 4+n > len(payload) {
		n = len(payload) - 4
	}
	return string(payload[4 : 4+n])
}

// sendExitStatus sends the SSH "exit-status" request so the client sees the
// command's exit code.
func sendExitStatus(ch ssh.Channel, status uint32) {
	payload := []byte{byte(status >> 24), byte(status >> 16), byte(status >> 8), byte(status)}
	_, _ = ch.SendRequest("exit-status", false, payload)
}

// Close shuts the server down.
func (s *testSSHServer) Close() {
	_ = s.listener.Close()
	s.wg.Wait()
}

func TestRunReturnsStdout(t *testing.T) {
	cfg, srv := newTestSSHServer(t, func(_ *testing.T, _ string, ch ssh.Channel) uint32 {
		_, _ = io.WriteString(ch, "hello world")
		return 0
	})
	defer srv.Close()

	exec, err := NewSSHExecutor(cfg)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = exec.Close() }()

	out, err := exec.Run(context.Background(), "echo hi")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "hello world" {
		t.Fatalf("unexpected output: %q", out)
	}
}

func TestRunWrapsExitError(t *testing.T) {
	cfg, srv := newTestSSHServer(t, func(_ *testing.T, _ string, ch ssh.Channel) uint32 {
		_, _ = io.WriteString(ch.Stderr(), "boom on stderr")
		return 7
	})
	defer srv.Close()

	exec, err := NewSSHExecutor(cfg)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = exec.Close() }()

	_, err = exec.Run(context.Background(), "false")
	if err == nil {
		t.Fatal("expected error for non-zero exit")
	}
	if !strings.Contains(err.Error(), "boom on stderr") {
		t.Fatalf("expected stderr in error, got: %v", err)
	}
	var exitErr *ssh.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected wrapped *ssh.ExitError, got: %v", err)
	}
}

func TestRunHonoursContextCancellation(t *testing.T) {
	release := make(chan struct{})
	cfg, srv := newTestSSHServer(t, func(_ *testing.T, _ string, _ ssh.Channel) uint32 {
		<-release // hang until the test releases us
		return 0
	})
	defer srv.Close()
	defer close(release)

	exec, err := NewSSHExecutor(cfg)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = exec.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = exec.Run(ctx, "sleep forever")
	if err == nil {
		t.Fatal("expected cancellation error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("Run did not return promptly on cancellation: %v", time.Since(start))
	}
}

func TestPutStreamsContentAtomically(t *testing.T) {
	var gotCmd string
	var gotContent []byte
	cfg, srv := newTestSSHServer(t, func(_ *testing.T, cmd string, ch ssh.Channel) uint32 {
		gotCmd = cmd
		b, _ := io.ReadAll(ch)
		gotContent = b
		return 0
	})
	defer srv.Close()

	exec, err := NewSSHExecutor(cfg)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = exec.Close() }()

	if err := exec.Put(context.Background(), "/etc/wireguard/wg-relay.conf", []byte("data")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(gotContent) != "data" {
		t.Fatalf("unexpected streamed content: %q", gotContent)
	}
	if !strings.Contains(gotCmd, "mktemp") || !strings.Contains(gotCmd, "mv -f") {
		t.Fatalf("expected atomic mktemp/mv write, got: %q", gotCmd)
	}
}

func TestPutWrapsRemoteFailure(t *testing.T) {
	cfg, srv := newTestSSHServer(t, func(_ *testing.T, _ string, ch ssh.Channel) uint32 {
		_, _ = io.ReadAll(ch)
		return 1
	})
	defer srv.Close()

	exec, err := NewSSHExecutor(cfg)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = exec.Close() }()

	err = exec.Put(context.Background(), "/etc/envoy/lds.yaml", []byte("x"))
	if err == nil {
		t.Fatal("expected error for failing remote write")
	}
	if !strings.Contains(err.Error(), "/etc/envoy/lds.yaml") {
		t.Fatalf("expected path in error, got: %v", err)
	}
}

func TestPutRejectsUnsafePath(t *testing.T) {
	cfg, srv := newTestSSHServer(t, func(_ *testing.T, _ string, _ ssh.Channel) uint32 {
		return 0
	})
	defer srv.Close()

	exec, err := NewSSHExecutor(cfg)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = exec.Close() }()

	for _, bad := range []string{"relative/path", "/etc/$(reboot)", "/etc/../../escape"} {
		if err := exec.Put(context.Background(), bad, []byte("x")); err == nil {
			t.Fatalf("expected rejection of unsafe path %q", bad)
		}
	}
}
