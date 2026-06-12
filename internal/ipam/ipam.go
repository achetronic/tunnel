package ipam

import (
	"encoding/binary"
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

// hostAt returns the address at the given host offset from the network base,
// computed over the full 32-bit address rather than the last octet alone, so
// non-.0-aligned bases and prefixes wider than /24 work (e.g. offset 300 in a
// /23 crosses an octet boundary correctly). It rejects offsets that fall
// outside the prefix or land on the broadcast address.
func (i *IPAM) hostAt(offset uint32) (netip.Addr, error) {
	base := binary.BigEndian.Uint32(func() []byte { b := i.prefix.Masked().Addr().As4(); return b[:] }())
	host := base + offset

	addrBytes := [4]byte{}
	binary.BigEndian.PutUint32(addrBytes[:], host)
	addr := netip.AddrFrom4(addrBytes)

	if !i.prefix.Contains(addr) {
		return netip.Addr{}, fmt.Errorf("network %s does not contain host offset %d", i.prefix.String(), offset)
	}

	// Reject the broadcast address (all host bits set). Prefixes narrower
	// than /31 reserve it; /31 and /32 have no broadcast semantics but are
	// already rejected by the offset checks of the callers.
	hostBits := 32 - i.prefix.Bits()
	if hostBits >= 2 {
		broadcast := base | (1<<uint(hostBits) - 1)
		if host == broadcast {
			return netip.Addr{}, fmt.Errorf("host offset %d is the broadcast address of %s", offset, i.prefix.String())
		}
	}

	return addr, nil
}

// RelayIP returns the IP address assigned to the VPS relay (network base + 1).
// Returns an error if the derived address falls outside the network prefix,
// which happens with very small prefixes (e.g. /31, /32).
func (i *IPAM) RelayIP() (string, error) {
	addr, err := i.hostAt(1)
	if err != nil {
		return "", fmt.Errorf("relay IP: %w", err)
	}
	return addr.String(), nil
}

// ReplicaIP returns the IP address assigned to an uplink replica by its
// ordinal (network base + 2 + ordinal). Ordinal 0 yields base+2, ordinal 1
// yields base+3, and so on. The offset is computed over the whole prefix, so
// networks wider than /24 can host more than 252 replicas and non-aligned
// bases work.
// Returns an error if ordinal is negative or the derived address falls
// outside the network prefix (or on its broadcast address).
func (i *IPAM) ReplicaIP(ordinal int32) (string, error) {
	if ordinal < 0 {
		return "", fmt.Errorf("ordinal cannot be negative, got %d", ordinal)
	}

	addr, err := i.hostAt(uint32(ordinal) + 2)
	if err != nil {
		return "", fmt.Errorf("replica IP for ordinal %d: %w", ordinal, err)
	}
	return addr.String(), nil
}
