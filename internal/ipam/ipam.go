package ipam

import (
	"fmt"
	"net/netip"
)

// New parses the CIDR and validates that it can be used for the tunnel.
// It rejects IPv6 networks and malformed CIDRs.
// Returns an error if networkCIDR is not a valid IPv4 prefix.
func New(networkCIDR string) (*IPAM, error) {
	prefix, err := netip.ParsePrefix(networkCIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid network CIDR %q: %w", networkCIDR, err)
	}

	if prefix.Addr().Is6() {
		return nil, fmt.Errorf("IPv6 networks are not supported, got %q", networkCIDR)
	}

	return &IPAM{prefix: prefix}, nil
}

// MaskBits returns the prefix length of the network (e.g. 24 for a /24).
// This avoids callers having to re-parse the CIDR string to extract the mask.
func (i *IPAM) MaskBits() int {
	return i.prefix.Bits()
}

// baseIP returns the network base address (the masked host-zero address).
func (i *IPAM) baseIP() netip.Addr {
	return i.prefix.Masked().Addr()
}

// RelayIP returns the IP address assigned to the VPS relay (base + .1).
// Returns an error if the derived address falls outside the network prefix,
// which happens with very small prefixes (e.g. /31, /32, or a /25 whose
// base is above .1).
func (i *IPAM) RelayIP() (string, error) {
	baseBytes := i.baseIP().As4()
	relayAddr := netip.AddrFrom4([4]byte{baseBytes[0], baseBytes[1], baseBytes[2], 1})

	if !i.prefix.Contains(relayAddr) {
		return "", fmt.Errorf("network %s does not contain the .1 relay IP", i.prefix.String())
	}

	return relayAddr.String(), nil
}

// ReplicaIP returns the IP address assigned to an uplink replica by its
// ordinal (base + .2 + ordinal). Ordinal 0 yields base.2, ordinal 1 yields
// base.3, and so on up to ordinal 252 (base.254).
// Returns an error if ordinal is negative, if the last octet would exceed 254,
// or if the derived address falls outside the network prefix.
func (i *IPAM) ReplicaIP(ordinal int32) (string, error) {
	if ordinal < 0 {
		return "", fmt.Errorf("ordinal cannot be negative, got %d", ordinal)
	}

	baseBytes := i.baseIP().As4()
	lastOctet := 2 + int(ordinal)

	if lastOctet > 254 {
		return "", fmt.Errorf("ordinal %d exceeds usable range for network %s", ordinal, i.prefix.String())
	}

	replicaAddr := netip.AddrFrom4([4]byte{baseBytes[0], baseBytes[1], baseBytes[2], byte(lastOctet)})
	if !i.prefix.Contains(replicaAddr) {
		return "", fmt.Errorf("network %s does not contain replica IP with ordinal %d", i.prefix.String(), ordinal)
	}

	return replicaAddr.String(), nil
}
