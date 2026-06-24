// SPDX-FileCopyrightText: 2026 Alby Hernández (Achetronic)
// SPDX-License-Identifier: Apache-2.0

package agentconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
)

// Decode parses the JSON document in data and disallows unknown fields, WITHOUT
// validating it. Use it when some field is injected after decoding (for example
// the uplink private key read from a mounted Secret) and Validate is called
// afterwards. Prefer Parse when the document is already complete.
func Decode(data []byte) (*Document, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var d Document
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("agentconfig: decode: %w", err)
	}
	return &d, nil
}

// Parse decodes the JSON document in data, disallows unknown fields, and
// validates the result. Unknown JSON fields cause an immediate decode error.
// Structural violations are returned as a wrapped validation error.
// Returns a non-nil Document on success.
func Parse(data []byte) (*Document, error) {
	d, err := Decode(data)
	if err != nil {
		return nil, err
	}
	if err := d.Validate(); err != nil {
		return nil, fmt.Errorf("agentconfig: validate: %w", err)
	}
	return d, nil
}

// Marshal encodes the document as deterministic indented JSON bytes.
// Determinism relies on the producer keeping slice order stable between calls;
// struct field order is fixed by encoding/json field declaration order.
func (d *Document) Marshal() ([]byte, error) {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("agentconfig: marshal: %w", err)
	}
	return b, nil
}

// Validate checks all consistency constraints of d. It returns the first
// violation found, naming the offending field. Validate never panics.
func (d *Document) Validate() error {
	if d == nil {
		return fmt.Errorf("document must not be nil")
	}
	if d.Version != CurrentVersion {
		return fmt.Errorf("version mismatch: document is %d, build requires %d", d.Version, CurrentVersion)
	}
	if err := validateInterface(d.WireGuard.Interface); err != nil {
		return err
	}
	for i, peer := range d.WireGuard.Peers {
		if err := validatePeer(i, peer); err != nil {
			return err
		}
	}
	if err := validateNftables(d.Nftables); err != nil {
		return err
	}
	if err := validateNetdev(d.Netdev); err != nil {
		return err
	}
	return nil
}

// validateInterface checks every field of a WireGuardInterface. It returns the
// first violation found, naming the offending field.
func validateInterface(iface WireGuardInterface) error {
	if iface.Name == "" {
		return fmt.Errorf("wireguard.interface.name must not be empty")
	}
	if iface.PrivateKey == "" {
		return fmt.Errorf("wireguard.interface.privateKey must not be empty")
	}
	if iface.Address == "" {
		return fmt.Errorf("wireguard.interface.address must not be empty")
	}
	if _, _, err := net.ParseCIDR(iface.Address); err != nil {
		return fmt.Errorf("wireguard.interface.address %q is not a valid CIDR: %w", iface.Address, err)
	}
	if iface.ListenPort != 0 && (iface.ListenPort < 1 || iface.ListenPort > 65535) {
		return fmt.Errorf("wireguard.interface.listenPort %d is out of range [1,65535]", iface.ListenPort)
	}
	if iface.MTU < 0 {
		return fmt.Errorf("wireguard.interface.mtu must be > 0 when set, got %d", iface.MTU)
	}
	return nil
}

// validatePeer checks every field of the WireGuardPeer at index i. It returns
// the first violation found, naming the offending field.
func validatePeer(i int, peer WireGuardPeer) error {
	if peer.PublicKey == "" {
		return fmt.Errorf("wireguard.peers[%d].publicKey must not be empty", i)
	}
	if len(peer.AllowedIPs) == 0 {
		return fmt.Errorf("wireguard.peers[%d].allowedIPs must have at least one entry", i)
	}
	for j, cidr := range peer.AllowedIPs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("wireguard.peers[%d].allowedIPs[%d] %q is not a valid CIDR: %w", i, j, cidr, err)
		}
	}
	if peer.PersistentKeepalive < 0 {
		return fmt.Errorf("wireguard.peers[%d].persistentKeepalive must be >= 0, got %d", i, peer.PersistentKeepalive)
	}
	if peer.Endpoint != "" {
		if _, _, err := net.SplitHostPort(peer.Endpoint); err != nil {
			return fmt.Errorf("wireguard.peers[%d].endpoint %q is not a valid host:port: %w", i, peer.Endpoint, err)
		}
	}
	return nil
}

// validateNftables checks the nftables section. It returns the first violation
// found, naming the offending field. A nil section is valid (edge nodes have no
// nftables).
func validateNftables(nft *NftablesConfig) error {
	if nft == nil {
		return nil
	}
	if nft.Interface == "" {
		return fmt.Errorf("nftables.interface must not be empty")
	}
	if _, _, err := net.ParseCIDR(nft.TunnelNetwork); err != nil {
		return fmt.Errorf("nftables.tunnelNetwork %q is not a valid CIDR: %w", nft.TunnelNetwork, err)
	}
	if nft.Metrics != nil {
		if nft.Metrics.Port < 1 || nft.Metrics.Port > 65535 {
			return fmt.Errorf("nftables.metrics.port %d is out of range [1,65535]", nft.Metrics.Port)
		}
		if net.ParseIP(nft.Metrics.RelayAddress) == nil {
			return fmt.Errorf("nftables.metrics.relayAddress %q is not a valid IP address", nft.Metrics.RelayAddress)
		}
	}
	for i, rule := range nft.Rules {
		if err := validateRule(i, rule); err != nil {
			return err
		}
	}
	return nil
}

// validateNetdev checks the netdev section. Both a nil section (the NIC is left
// untouched) and a present section are valid: the section carries only a boolean
// toggle, so there is nothing to constrain. It exists to keep the validation
// surface uniform and ready for future fields.
func validateNetdev(nd *NetdevConfig) error {
	_ = nd
	return nil
}

// validateRule checks every field of the NftablesRule at index i. It returns
// the first violation found, naming the offending field.
func validateRule(i int, rule NftablesRule) error {
	if rule.Protocol != "TCP" && rule.Protocol != "UDP" {
		return fmt.Errorf("nftables.rules[%d].protocol %q must be TCP or UDP", i, rule.Protocol)
	}
	if rule.ListenPort < 1 || rule.ListenPort > 65535 {
		return fmt.Errorf("nftables.rules[%d].listenPort %d is out of range [1,65535]", i, rule.ListenPort)
	}
	if rule.TargetPort < 1 || rule.TargetPort > 65535 {
		return fmt.Errorf("nftables.rules[%d].targetPort %d is out of range [1,65535]", i, rule.TargetPort)
	}
	if net.ParseIP(rule.TargetIP) == nil {
		return fmt.Errorf("nftables.rules[%d].targetIP %q is not a valid IP address", i, rule.TargetIP)
	}
	return nil
}
