package wg

import (
	"fmt"
	"net"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/achetronic/tunnel/internal/agentconfig"
)

// backend is the link backend used by Apply and Status. It is a package
// variable so tests can replace it; the in-kernel module is the default.
var backend linkBackend = kernelBackend{}

// buildDeviceConfig translates a desired WireGuard configuration into the
// wgtypes.Config consumed by wgctrl. It is pure (no IO) so it is unit-tested.
func buildDeviceConfig(cfg agentconfig.WireGuardConfig) (wgtypes.Config, error) {
	priv, err := wgtypes.ParseKey(cfg.Interface.PrivateKey)
	if err != nil {
		return wgtypes.Config{}, fmt.Errorf("parse private key: %w", err)
	}

	out := wgtypes.Config{
		PrivateKey:   &priv,
		ReplacePeers: true,
	}
	if cfg.Interface.ListenPort > 0 {
		port := cfg.Interface.ListenPort
		out.ListenPort = &port
	}

	for i, peer := range cfg.Peers {
		pub, err := wgtypes.ParseKey(peer.PublicKey)
		if err != nil {
			return wgtypes.Config{}, fmt.Errorf("peer %d: parse public key: %w", i, err)
		}
		pc := wgtypes.PeerConfig{
			PublicKey:         pub,
			ReplaceAllowedIPs: true,
		}
		for _, cidr := range peer.AllowedIPs {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				return wgtypes.Config{}, fmt.Errorf("peer %d: allowed IP %q: %w", i, cidr, err)
			}
			pc.AllowedIPs = append(pc.AllowedIPs, *ipnet)
		}
		if peer.Endpoint != "" {
			addr, err := net.ResolveUDPAddr("udp", peer.Endpoint)
			if err != nil {
				return wgtypes.Config{}, fmt.Errorf("peer %d: endpoint %q: %w", i, peer.Endpoint, err)
			}
			pc.Endpoint = addr
		}
		if peer.PersistentKeepalive > 0 {
			keepalive := time.Duration(peer.PersistentKeepalive) * time.Second
			pc.PersistentKeepaliveInterval = &keepalive
		}
		out.Peers = append(out.Peers, pc)
	}
	return out, nil
}

// Apply brings the WireGuard device to the desired state idempotently: it
// ensures the link exists, configures keys, listen port and peers, sets the
// interface address and MTU, brings the link up, and installs a route for every
// peer allowed IP. Re-running it with the same input is a no-op.
func Apply(cfg agentconfig.WireGuardConfig) error {
	name := cfg.Interface.Name
	if err := backend.Ensure(name); err != nil {
		return err
	}

	devCfg, err := buildDeviceConfig(cfg)
	if err != nil {
		return err
	}
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("open wgctrl: %w", err)
	}
	defer func() { _ = client.Close() }()
	if err := client.ConfigureDevice(name, devCfg); err != nil {
		return fmt.Errorf("configure device %q: %w", name, err)
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("look up link %q: %w", name, err)
	}

	addr, err := netlink.ParseAddr(cfg.Interface.Address)
	if err != nil {
		return fmt.Errorf("parse interface address %q: %w", cfg.Interface.Address, err)
	}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("set address %q: %w", cfg.Interface.Address, err)
	}

	if cfg.Interface.MTU > 0 {
		if err := netlink.LinkSetMTU(link, cfg.Interface.MTU); err != nil {
			return fmt.Errorf("set mtu %d: %w", cfg.Interface.MTU, err)
		}
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring link %q up: %w", name, err)
	}

	for _, peer := range cfg.Peers {
		for _, cidr := range peer.AllowedIPs {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				return fmt.Errorf("route for %q: %w", cidr, err)
			}
			route := &netlink.Route{
				LinkIndex: link.Attrs().Index,
				Dst:       ipnet,
				Scope:     netlink.SCOPE_LINK,
			}
			if err := netlink.RouteReplace(route); err != nil {
				return fmt.Errorf("install route %q: %w", cidr, err)
			}
		}
	}
	return nil
}

// Status reports the observed state of the device. A missing link yields
// State{Exists: false} with a nil error, since "not applied yet" is a valid
// observation rather than a failure.
func Status(cfg agentconfig.WireGuardConfig) (State, error) {
	name := cfg.Interface.Name
	link, err := netlink.LinkByName(name)
	if err != nil {
		return State{Exists: false}, nil
	}
	state := State{
		Exists: true,
		Up:     link.Attrs().Flags&net.FlagUp != 0,
	}

	client, err := wgctrl.New()
	if err != nil {
		return state, fmt.Errorf("open wgctrl: %w", err)
	}
	defer func() { _ = client.Close() }()
	device, err := client.Device(name)
	if err != nil {
		return state, fmt.Errorf("read device %q: %w", name, err)
	}
	for _, peer := range device.Peers {
		ps := PeerState{
			PublicKey:     peer.PublicKey.String(),
			LastHandshake: peer.LastHandshakeTime,
		}
		if peer.Endpoint != nil {
			ps.Endpoint = peer.Endpoint.String()
		}
		state.Peers = append(state.Peers, ps)
	}
	return state, nil
}
