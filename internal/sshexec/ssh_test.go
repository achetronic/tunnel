// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package sshexec

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
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
	addr := &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 22}
	if err := cb("203.0.113.10:22", addr, key); err != nil {
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
	addr := &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 22}
	if err := cb("203.0.113.10:22", addr, other); err == nil {
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

func TestKnownHostsCallbackStrictHostname(t *testing.T) {
	k1 := newHostKey(t)
	k2 := newHostKey(t)

	// A blob with TWO entries: key K1 pinned for host "203.0.113.10" and K2 for "198.51.100.20"
	blob := knownHostsLine("203.0.113.10", k1) + "\n" + knownHostsLine("198.51.100.20", k2)

	cb, err := knownHostsCallback([]byte(blob))
	if err != nil {
		t.Fatalf("unexpected error initializing callback: %v", err)
	}

	addr1 := &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 22}
	addr2 := &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 22}

	// cb("203.0.113.10:22", addr1, K1) must be accepted
	if err := cb("203.0.113.10:22", addr1, k1); err != nil {
		t.Errorf("expected K1 to be accepted for host 203.0.113.10, got: %v", err)
	}

	// cb("198.51.100.20:22", addr2, K2) must be accepted
	if err := cb("198.51.100.20:22", addr2, k2); err != nil {
		t.Errorf("expected K2 to be accepted for host 198.51.100.20, got: %v", err)
	}

	// cb("198.51.100.20:22", addr2, K1) must be REJECTED (old code accepted it!)
	if err := cb("198.51.100.20:22", addr2, k1); err == nil {
		t.Error("expected K1 to be REJECTED for host 198.51.100.20, but it was accepted")
	}
}

func TestKnownHostsCallbackUnknownHost(t *testing.T) {
	k1 := newHostKey(t)
	blob := knownHostsLine("203.0.113.10", k1)

	cb, err := knownHostsCallback([]byte(blob))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	addrUnknown := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}
	// cb("192.0.2.1:22", addrUnknown, K1) must be rejected because even though K1 is in the blob,
	// it is not associated with 192.0.2.1
	if err := cb("192.0.2.1:22", addrUnknown, k1); err == nil {
		t.Error("expected key to be rejected for an unknown host, even though the key exists in the blob")
	}
}

func TestKnownHostsCallbackMalformed(t *testing.T) {
	// A line with malformed/unparseable host keys data
	malformedBlob := "203.0.113.10 invalid-key-type base64garbage"
	_, err := knownHostsCallback([]byte(malformedBlob))
	if err == nil {
		t.Fatal("expected error for malformed known_hosts data")
	}
	if !strings.Contains(err.Error(), "failed to parse knownHosts") {
		t.Errorf("expected error message to contain 'failed to parse knownHosts', got: %v", err)
	}
}

func TestKnownHostsCallbackKeyErrorInspectable(t *testing.T) {
	pinned := newHostKey(t)
	other := newHostKey(t)
	cb, err := knownHostsCallback([]byte(knownHostsLine("203.0.113.10", pinned)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	addr := &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 22}
	err = cb("203.0.113.10:22", addr, other)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var keyErr *knownhosts.KeyError
	if !errors.As(err, &keyErr) {
		t.Fatalf("expected error to wrap *knownhosts.KeyError, but it does not. Error was: %v", err)
	}

	// Ensure the KeyError has the expected structure
	if len(keyErr.Want) == 0 {
		t.Error("expected keyErr.Want to have elements")
	}
}
