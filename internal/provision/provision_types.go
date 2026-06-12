package provision

import "time"

// State models the applied configuration hashes stored on the VPS in
// /etc/tunnel-operator/state.json. It lets Enroll skip work that is already
// in place, keeping the operation idempotent.
type State struct {
	// RelayDocumentHash is the hash of the last applied tunnelctl relay document
	// (/etc/tunnel-operator/relay.json), the native replacement for the old
	// wg-relay.conf flow.
	RelayDocumentHash string `json:"relayDocumentHash"`
	// TunnelctlHash is the SHA-256 of the tunnelctl binary last pushed to the
	// VPS. It lets Enroll re-push the binary only when it actually changes (a new
	// operator build), avoiding a redundant SSH copy on every reconcile.
	TunnelctlHash string `json:"tunnelctlHash"`
	// EnvoyVersion records the Envoy release last installed by enroll. Pre-existing
	// VPSes have it empty, which simply forces one full (idempotent) pass that backfills it.
	EnvoyVersion string `json:"envoyVersion"`
	// EnvoyLDSHash is the hash of the last applied Envoy LDS config.
	EnvoyLDSHash string `json:"envoyLdsHash"`
	// EnvoyCDSHash is the hash of the last applied Envoy CDS config.
	EnvoyCDSHash string `json:"envoyCdsHash"`
	// TLSHash is the hash of all TLS files pushed to the VPS. When it
	// changes the operator rewrites the affected files and reloads Envoy.
	TLSHash string `json:"tlsHash"`
}

// TLSFile pairs a VPS destination path with the raw file contents to write
// there. It is passed from the controller (which reads Kubernetes Secrets) into
// Enroll so that the provision layer never touches the API server.
type TLSFile struct {
	// Path is the absolute path on the VPS where Content will be written,
	// e.g. /etc/envoy/tls/myservice.crt.
	Path string
	// Content is the raw bytes to place at Path.
	Content []byte
}

// HealthStatus is the observed state of the VPS services as reported by
// CheckHealth.
type HealthStatus struct {
	// EnvoyHealthy is true when the envoy service is active.
	EnvoyHealthy bool
	// RelayHealthy is true when tunnelctl reports the relay WireGuard interface
	// present, up, and with a recent handshake.
	RelayHealthy bool
	// Handshakes maps each peer public key to its last WireGuard handshake time.
	Handshakes map[string]time.Time
}
