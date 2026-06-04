// Package nftables programs the uplink DNAT and masquerade ruleset natively
// through netlink (github.com/google/nftables), so the uplink needs no `nft`
// binary. It is the structured equivalent of the legacy text ruleset rendered
// by internal/render/nft.go. The kernel rule semantics are validated against a
// real uplink; the helpers that translate config into expressions are pure.
package nftables

import (
	"fmt"
	"net"

	nft "github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"github.com/achetronic/tunnel/internal/agentconfig"
)

// tableName is the name of the ip table this package owns and rebuilds.
const tableName = "uplink"

// ifnameSize is the kernel interface-name buffer length (IFNAMSIZ) that an
// iifname/oifname comparison is matched against.
const ifnameSize = 16

// Apply rebuilds "table ip uplink" from the desired config idempotently: it
// ensures the table exists, flushes it, recreates the prerouting (DNAT) and
// postrouting (masquerade) chains and their rules, and commits atomically.
// Re-running with the same input converges to the same ruleset.
func Apply(cfg agentconfig.NftablesConfig) error {
	if cfg.Interface == "" {
		return fmt.Errorf("nftables: interface must not be empty")
	}
	_, network, err := net.ParseCIDR(cfg.TunnelNetwork)
	if err != nil {
		return fmt.Errorf("nftables: tunnel network %q: %w", cfg.TunnelNetwork, err)
	}

	conn, err := nft.New()
	if err != nil {
		return fmt.Errorf("nftables: open netlink: %w", err)
	}

	table := conn.AddTable(&nft.Table{Family: nft.TableFamilyIPv4, Name: tableName})
	conn.FlushTable(table)

	prerouting := conn.AddChain(&nft.Chain{
		Name:     "prerouting",
		Table:    table,
		Type:     nft.ChainTypeNAT,
		Hooknum:  nft.ChainHookPrerouting,
		Priority: nft.ChainPriorityNATDest,
	})
	postrouting := conn.AddChain(&nft.Chain{
		Name:     "postrouting",
		Table:    table,
		Type:     nft.ChainTypeNAT,
		Hooknum:  nft.ChainHookPostrouting,
		Priority: nft.ChainPriorityNATSource,
	})

	// Metrics scraping from the cluster: traffic NOT arriving on the tunnel is
	// DNAT'd to the relay admin over the tunnel.
	if cfg.Metrics != nil {
		relay := net.ParseIP(cfg.Metrics.RelayAddress).To4()
		if relay == nil {
			return fmt.Errorf("nftables: metrics relay address %q is not IPv4", cfg.Metrics.RelayAddress)
		}
		conn.AddRule(&nft.Rule{
			Table: table,
			Chain: prerouting,
			Exprs: dnatExprs(cfg.Interface, false, unix.IPPROTO_TCP, cfg.Metrics.Port, relay, cfg.Metrics.Port),
		})
	}

	// Forwarded ports: traffic arriving on the tunnel is DNAT'd to its target.
	for _, rule := range cfg.Rules {
		proto, err := protoNumber(rule.Protocol)
		if err != nil {
			return err
		}
		target := net.ParseIP(rule.TargetIP).To4()
		if target == nil {
			return fmt.Errorf("nftables: rule target IP %q is not IPv4", rule.TargetIP)
		}
		conn.AddRule(&nft.Rule{
			Table: table,
			Chain: prerouting,
			Exprs: dnatExprs(cfg.Interface, true, proto, rule.ListenPort, target, rule.TargetPort),
		})
	}

	// Return path for cluster-originated traffic, and outbound over the tunnel.
	conn.AddRule(&nft.Rule{Table: table, Chain: postrouting, Exprs: saddrMasqExprs(network, cfg.Interface)})
	conn.AddRule(&nft.Rule{Table: table, Chain: postrouting, Exprs: oifMasqExprs(cfg.Interface)})

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("nftables: apply ruleset: %w", err)
	}
	return nil
}

// protoNumber maps a config protocol string to its IP protocol number.
func protoNumber(protocol string) (int, error) {
	switch protocol {
	case "TCP":
		return unix.IPPROTO_TCP, nil
	case "UDP":
		return unix.IPPROTO_UDP, nil
	default:
		return 0, fmt.Errorf("nftables: protocol %q must be TCP or UDP", protocol)
	}
}

// ifname returns the interface name zero-padded to the kernel buffer length, as
// expected by an iifname/oifname register comparison.
func ifname(name string) []byte {
	buf := make([]byte, ifnameSize)
	copy(buf, name)
	return buf
}

// dnatExprs builds the expressions for "iifname [!=] <iface> <proto> dport
// <dport> dnat to <target>:<tport>". iifEqual chooses == or != on the interface.
func dnatExprs(iface string, iifEqual bool, proto, dport int, target net.IP, tport int) []expr.Any {
	op := expr.CmpOpEq
	if !iifEqual {
		op = expr.CmpOpNeq
	}
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: op, Register: 1, Data: ifname(iface)},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(proto)}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(dport))},
		&expr.Immediate{Register: 1, Data: target.To4()},
		&expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(uint16(tport))},
		&expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV4, RegAddrMin: 1, RegProtoMin: 2},
	}
}

// saddrMasqExprs builds "ip saddr <network> oifname != <iface> masquerade", the
// return-path masquerade for cluster-originated traffic.
func saddrMasqExprs(network *net.IPNet, iface string) []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: net.IP(network.Mask).To4(), Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: network.IP.To4()},
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: ifname(iface)},
		&expr.Masq{},
	}
}

// oifMasqExprs builds "oifname <iface> masquerade", masquerading traffic that
// leaves over the tunnel so the relay can reply.
func oifMasqExprs(iface string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(iface)},
		&expr.Masq{},
	}
}
