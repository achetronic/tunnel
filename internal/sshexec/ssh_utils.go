package sshexec

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

// hostKeyCallback builds the SSH host key verification callback. When a
// known_hosts blob is provided the presented key must match one of its entries;
// otherwise verification is only skipped if explicitly opted in, and is
// refused by default to protect the enrollment channel.
func hostKeyCallback(cfg Config) (ssh.HostKeyCallback, error) {
	if cfg.KnownHosts != "" {
		return knownHostsCallback([]byte(cfg.KnownHosts))
	}
	if cfg.InsecureSkipHostKeyVerification {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	return nil, fmt.Errorf("no host key provided: set a \"knownHosts\" entry in the SSH Secret or enable insecureSkipHostKeyVerification")
}

// knownHostsCallback parses an OpenSSH known_hosts blob and returns a callback
// that accepts the connection only if the presented host key matches one of the
// pinned keys.
func knownHostsCallback(data []byte) (ssh.HostKeyCallback, error) {
	var keys []ssh.PublicKey
	rest := data
	for {
		_, _, pub, _, remaining, err := ssh.ParseKnownHosts(rest)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse knownHosts: %w", err)
		}
		keys = append(keys, pub)
		rest = remaining
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no host keys found in knownHosts data")
	}
	return func(hostname string, _ net.Addr, key ssh.PublicKey) error {
		for _, k := range keys {
			if bytes.Equal(k.Marshal(), key.Marshal()) {
				return nil
			}
		}
		return fmt.Errorf("ssh: host key verification failed for %s", hostname)
	}, nil
}

// safeRemotePath matches absolute paths made of conservative filename
// characters only. It deliberately rejects anything that could break out of an
// argument or inject a command (spaces, quotes, shell metacharacters).
var safeRemotePath = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)

// validateRemotePath rejects remote paths that are not absolute or contain
// characters outside a conservative whitelist. Today the operator only writes
// to internal constant paths, but the IO boundary must not assume that.
func validateRemotePath(path string) error {
	if !safeRemotePath.MatchString(path) {
		return fmt.Errorf("refusing to write to unsafe remote path %q", path)
	}
	if strings.Contains(path, "..") {
		return fmt.Errorf("refusing to write to remote path with traversal %q", path)
	}
	return nil
}

// shellQuote wraps s in single quotes for safe use inside a remote shell
// command, escaping any embedded single quotes.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
