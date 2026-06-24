// SPDX-FileCopyrightText: 2026 Alby Hernández (Achetronic)
// SPDX-License-Identifier: Apache-2.0

// Package netdev applies host network-interface tuning natively, without
// shelling out to the ethtool CLI. Today it toggles the GRO/GSO offloads of the
// underlay NIC that carries the WireGuard transport. The underlay interface is
// resolved at apply time from the route to a public IP (not hardcoded, never the
// wg tunnel), so the same document applies on any host. The kernel IO is kept
// behind seams (resolve + feature controller) so the decision logic is unit
// tested without root.
package netdev

import (
	"fmt"
	"net"

	"github.com/safchain/ethtool"
	"github.com/vishvananda/netlink"

	"github.com/achetronic/tunnel/internal/agentconfig"
)

// offloadFeatureKeys are the kernel netdev feature names this package disables.
// They are the strings the kernel exposes in netdev_features_strings:
// "rx-gro" is NETIF_F_GRO_BIT (Generic Receive Offload) and
// "tx-generic-segmentation" is NETIF_F_GSO_BIT (Generic Segmentation Offload).
// Using the kernel feature names (resolved against the device's GSTRINGS by the
// ethtool library) is robust across kernel versions, unlike raw feature bits.
var offloadFeatureKeys = []string{"rx-gro", "tx-generic-segmentation"}

// underlayProbeIP is a public address used only to resolve which interface the
// host routes outbound traffic through. No packet is sent to it; the kernel's
// route lookup returns the outbound device, which is the underlay NIC carrying
// the WireGuard transport (never the wg tunnel, whose routes are tunnel /32s).
const underlayProbeIP = "1.1.1.1"

// relayInterfaceName is the WireGuard tunnel device on the relay. The underlay
// resolver guards against ever selecting it: tuning the tunnel device is never
// the intent, only the physical NIC beneath it.
const relayInterfaceName = "wg-relay"

// featureController is the IO seam over the host's offload features. Production
// uses safchain/ethtool over the SIOCETHTOOL ioctl; tests inject a fake.
type featureController interface {
	// Features returns the current offload features keyed by kernel name.
	Features(iface string) (map[string]bool, error)
	// Change requests the given features be set to the given on/off states.
	Change(iface string, config map[string]bool) error
}

// interfaceResolver is the IO seam that resolves the underlay interface name.
// Production resolves it via a netlink route lookup; tests inject a fake.
type interfaceResolver func() (string, error)

// Apply brings the host NIC to the desired state described by cfg. A section
// with DisableOffloads false is a no-op (offloads are never re-enabled here:
// presence-disables, absence/false leaves them untouched). When DisableOffloads
// is true it opens an ethtool handle, resolves the underlay interface and turns
// GRO/GSO off idempotently. Re-running with the same input is a no-op.
func Apply(cfg agentconfig.NetdevConfig) error {
	if !cfg.DisableOffloads {
		return nil
	}
	handle, err := ethtool.NewEthtool()
	if err != nil {
		return fmt.Errorf("netdev: open ethtool: %w", err)
	}
	defer handle.Close()
	return applyOffloads(resolveUnderlayInterface, handle, cfg)
}

// applyOffloads is the pure decision core behind Apply: it resolves the
// interface, reads its current offload features and only issues a Change for the
// features that are present and still enabled, so it is idempotent and never
// fails on a driver that does not expose one of the keys. It is split out so the
// logic is exercised in unit tests with injected seams (no root, no NIC).
func applyOffloads(resolve interfaceResolver, ctrl featureController, cfg agentconfig.NetdevConfig) error {
	if !cfg.DisableOffloads {
		return nil
	}
	iface, err := resolve()
	if err != nil {
		return fmt.Errorf("netdev: resolve underlay interface: %w", err)
	}

	current, err := ctrl.Features(iface)
	if err != nil {
		return fmt.Errorf("netdev: read features of %q: %w", iface, err)
	}

	desired := make(map[string]bool, len(offloadFeatureKeys))
	for _, key := range offloadFeatureKeys {
		// A feature the driver does not report cannot be disabled; skip it
		// rather than asking the kernel to change an unknown feature.
		if enabled, ok := current[key]; ok && enabled {
			desired[key] = false
		}
	}
	if len(desired) == 0 {
		// Already off (or unsupported): nothing to do, stay idempotent.
		return nil
	}

	if err := ctrl.Change(iface, desired); err != nil {
		return fmt.Errorf("netdev: disable offloads on %q: %w", iface, err)
	}
	return nil
}

// resolveUnderlayInterface returns the name of the interface the host uses to
// reach the public internet, by asking the kernel for the route to a public IP
// and mapping the outbound link index to a name. It deliberately skips the wg
// tunnel device so the offload toggle always lands on the physical NIC beneath
// it. No traffic is sent; only the routing table is consulted.
func resolveUnderlayInterface() (string, error) {
	ip := net.ParseIP(underlayProbeIP)
	if ip == nil {
		return "", fmt.Errorf("invalid probe IP %q", underlayProbeIP)
	}
	routes, err := netlink.RouteGet(ip)
	if err != nil {
		return "", fmt.Errorf("route get to %s: %w", underlayProbeIP, err)
	}
	for _, r := range routes {
		if r.LinkIndex <= 0 {
			continue
		}
		link, err := netlink.LinkByIndex(r.LinkIndex)
		if err != nil {
			return "", fmt.Errorf("look up link index %d: %w", r.LinkIndex, err)
		}
		name := link.Attrs().Name
		if name == "" || name == relayInterfaceName {
			continue
		}
		return name, nil
	}
	return "", fmt.Errorf("no outbound underlay interface found for %s", underlayProbeIP)
}
