package sshexec

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
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
// that accepts the connection only if the presented host key matches the pinned
// key for that hostname.
func knownHostsCallback(data []byte) (ssh.HostKeyCallback, error) {
	// Pre-validate the blob so malformed data or an empty entry set fails with an
	// explicit error before it reaches the temp file and knownhosts.New.
	var parsedAny bool
	rest := data
	for {
		_, _, _, _, remaining, err := ssh.ParseKnownHosts(rest)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse knownHosts: %w", err)
		}
		parsedAny = true
		rest = remaining
	}
	if !parsedAny {
		return nil, fmt.Errorf("no host keys found in knownHosts data")
	}

	// Because knownhosts.New requires a file path, we write the data to a temporary file.
	tmpFile, err := os.CreateTemp("", "tunnel-knownhosts-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file for known_hosts: %w", err)
	}
	tempPath := tmpFile.Name()
	defer func() {
		_ = os.Remove(tempPath)
	}()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return nil, fmt.Errorf("failed to write known_hosts to temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return nil, fmt.Errorf("failed to close temp file: %w", err)
	}

	khCallback, err := knownhosts.New(tempPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize known_hosts callback: %w", err)
	}

	// Remove the temp file immediately because knownhosts.New parses the file eagerly
	// into an in-memory database and does not need it on disk afterwards. Note that
	// public host keys are not secret material, so this brief disk write is acceptable.
	_ = os.Remove(tempPath)

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := khCallback(hostname, remote, key)
		if err != nil {
			return fmt.Errorf("ssh: host key verification failed for %s: key does not match any known_hosts entry for that host: %w", hostname, err)
		}
		return nil
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
