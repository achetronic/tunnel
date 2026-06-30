// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

// Package ipam provides IP address management for tunnel overlay networks.
// It assigns a fixed relay IP (.1) and per-replica IPs (.2 + ordinal) within
// a given IPv4 CIDR, validating that all computed addresses actually fall
// inside the network prefix.
package ipam

import "net/netip"

// IPAM is responsible for validating the tunnel network and calculating
// overlay IP addresses for the VPS relay and uplink replicas.
// It assumes a network where the fourth octet ".1" is the relay,
// and ".2 + ordinal" is the replica.
type IPAM struct {
	prefix netip.Prefix
}
