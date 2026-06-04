// Package wg applies and inspects a WireGuard device natively through netlink
// and wgctrl, so the host needs neither wireguard-tools nor wg-quick. The
// translation logic is pure and unit-tested; the netlink and wgctrl calls are
// kept in thin wrappers (Apply/Status) exercised against a real host.
package wg

import "time"

// State is the observed state of a WireGuard device.
type State struct {
	// Exists is true when the interface is present on the host.
	Exists bool
	// Up is true when the interface is administratively up.
	Up bool
	// Peers is the observed per-peer state reported by the kernel.
	Peers []PeerState
}

// PeerState is the observed state of a single WireGuard peer.
type PeerState struct {
	// PublicKey is the base64 public key of the peer.
	PublicKey string
	// LastHandshake is the time of the most recent handshake; zero means none.
	LastHandshake time.Time
	// Endpoint is the "host:port" the peer is currently reached at, if known.
	Endpoint string
}

// linkBackend abstracts creation and removal of the WireGuard link, so the
// in-kernel module is the default and a userspace data plane (wireguard-go) can
// slot in later as a fallback (.agents/TODO.md item 5).
type linkBackend interface {
	// Ensure makes sure a WireGuard link named name exists. It is idempotent.
	Ensure(name string) error
	// Remove deletes the link if present. A missing link is success.
	Remove(name string) error
}
