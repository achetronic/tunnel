// SPDX-FileCopyrightText: 2026 Alby Hernández (Achetronic)
// SPDX-License-Identifier: Apache-2.0

// Package agentconfig defines the JSON "desired state" document consumed by
// the tunnelctl agent on both the VPS edge node and the uplink pods.
// It is the shared contract every other layer of the operator depends on.
package agentconfig

// CurrentVersion is the schema version this build understands. Apply must
// reject documents whose Version does not match CurrentVersion.
const CurrentVersion = 1

// Document is the full desired state applied to one node (VPS edge or uplink
// pod). WireGuard is always present; Nftables is present only on the uplink. A
// later iteration will add an optional Envoy section for the edge (see
// .agents/TODO.md item 4); keep the struct open for that without adding it now.
type Document struct {
	// Version is the schema version of this document (see CurrentVersion).
	Version int `json:"version"`
	// WireGuard is the WireGuard interface and peer configuration for this node.
	WireGuard WireGuardConfig `json:"wireguard"`
	// Nftables is the optional DNAT ruleset; set only on uplink nodes.
	Nftables *NftablesConfig `json:"nftables,omitempty"`
}

// WireGuardConfig describes the WireGuard device of a node: the local interface
// plus every peer it talks to.
type WireGuardConfig struct {
	// Interface is the local WireGuard device configuration.
	Interface WireGuardInterface `json:"interface"`
	// Peers is the list of peers. On the relay these are the uplink replicas;
	// on an uplink this is the single relay peer.
	Peers []WireGuardPeer `json:"peers"`
}

// WireGuardInterface is the local side of the WireGuard device.
type WireGuardInterface struct {
	// Name is the interface name, e.g. "wg-relay" or "wg-uplink".
	Name string `json:"name"`
	// PrivateKey is the base64 WireGuard private key of this node.
	PrivateKey string `json:"privateKey"`
	// ListenPort is the UDP port the device listens on. Zero (omitted) means the
	// device does not listen, used by uplinks that only dial out.
	ListenPort int `json:"listenPort,omitempty"`
	// Address is the overlay address with mask assigned to the interface, e.g.
	// "10.200.0.1/24" on the relay or "10.200.0.2/32" on an uplink.
	Address string `json:"address"`
	// MTU is the interface MTU. Zero (omitted) leaves the system default.
	MTU int `json:"mtu,omitempty"`
}

// WireGuardPeer is one peer of the WireGuard device.
type WireGuardPeer struct {
	// PublicKey is the base64 WireGuard public key of the peer.
	PublicKey string `json:"publicKey"`
	// AllowedIPs are the CIDRs routed to this peer, e.g. ["10.200.0.2/32"].
	AllowedIPs []string `json:"allowedIPs"`
	// Endpoint is the "host:port" the peer is reached at. Empty on the relay
	// (uplinks dial in); set to the relay endpoint on an uplink.
	Endpoint string `json:"endpoint,omitempty"`
	// PersistentKeepalive is the keepalive interval in seconds. Zero (omitted)
	// disables it; uplinks use 25 to keep NAT/firewall state open.
	PersistentKeepalive int `json:"persistentKeepalive,omitempty"`
}

// NftablesConfig is the DNAT ruleset applied on an uplink node. It is
// self-contained: it carries the tunnel interface and overlay network its rules
// reference, so apply needs nothing beyond this document.
type NftablesConfig struct {
	// Interface is the tunnel interface forwarded traffic arrives on, e.g. "wg-uplink".
	Interface string `json:"interface"`
	// TunnelNetwork is the overlay CIDR, used by the return masquerade rule.
	TunnelNetwork string `json:"tunnelNetwork"`
	// Metrics, when set, forwards inbound connections on its port to the relay's
	// Envoy admin over the tunnel (in-cluster metrics scraping).
	Metrics *NftablesMetrics `json:"metrics,omitempty"`
	// Rules is the list of port-forwarding rules to install.
	Rules []NftablesRule `json:"rules"`
}

// NftablesMetrics forwards inbound traffic on Port to RelayAddress:Port over the
// tunnel, so in-cluster scrapers reach the relay's Envoy admin interface.
type NftablesMetrics struct {
	// Port is the port both listened on and forwarded to, e.g. 40600.
	Port int `json:"port"`
	// RelayAddress is the relay tunnel IP the traffic is DNAT'd to, e.g. 10.200.0.1.
	RelayAddress string `json:"relayAddress"`
}

// NftablesRule is one DNAT mapping from an incoming tunnel port to a target.
type NftablesRule struct {
	// Protocol is "TCP" or "UDP".
	Protocol string `json:"protocol"`
	// ListenPort is the port arriving over the tunnel.
	ListenPort int `json:"listenPort"`
	// TargetIP is the in-cluster destination IP.
	TargetIP string `json:"targetIP"`
	// TargetPort is the in-cluster destination port.
	TargetPort int `json:"targetPort"`
}
