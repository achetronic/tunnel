package sshexec

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"testing"

	"golang.org/x/crypto/ssh"
)

func newHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("failed to build ssh public key: %v", err)
	}
	return sshPub
}

func knownHostsLine(host string, key ssh.PublicKey) string {
	return fmt.Sprintf("%s %s", host, string(ssh.MarshalAuthorizedKey(key)))
}

func TestKnownHostsCallbackAcceptsMatchingKey(t *testing.T) {
	key := newHostKey(t)
	cb, err := knownHostsCallback([]byte(knownHostsLine("203.0.113.10", key)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := cb("203.0.113.10:22", &net.TCPAddr{}, key); err != nil {
		t.Fatalf("expected matching key to be accepted, got: %v", err)
	}
}

func TestKnownHostsCallbackRejectsMismatch(t *testing.T) {
	pinned := newHostKey(t)
	other := newHostKey(t)
	cb, err := knownHostsCallback([]byte(knownHostsLine("203.0.113.10", pinned)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := cb("203.0.113.10:22", &net.TCPAddr{}, other); err == nil {
		t.Fatal("expected mismatching key to be rejected")
	}
}

func TestKnownHostsCallbackEmpty(t *testing.T) {
	if _, err := knownHostsCallback([]byte("\n  \n")); err == nil {
		t.Fatal("expected error for empty known_hosts data")
	}
}

func TestHostKeyCallbackRefusesWithoutKnownHosts(t *testing.T) {
	if _, err := hostKeyCallback(Config{}); err == nil {
		t.Fatal("expected refusal when no host key is provided and insecure is not opted in")
	}
}

func TestHostKeyCallbackInsecureOptIn(t *testing.T) {
	cb, err := hostKeyCallback(Config{InsecureSkipHostKeyVerification: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cb == nil {
		t.Fatal("expected a callback for the insecure opt-in path")
	}
}
