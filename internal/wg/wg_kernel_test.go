package wg

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/achetronic/tunnel/internal/agentconfig"
)

// TestSyncRoutes_Kernel exercises the netlink glue of route reconciliation
// against a real dummy interface: RouteReplace, the RouteListFiltered OIF
// filter, RouteDel, and the kernel-proto guard with a genuine kernel route
// (the one the kernel installs when the address is assigned).
//
// It needs CAP_NET_ADMIN (run as root: `sudo go test ./internal/wg/`). When
// unprivileged it skips, so the default `go test ./...` and unprivileged CI
// stay green; a CI job that wants this coverage runs the package under sudo.
// Addresses are from TEST-NET-2 (198.51.100.0/24, RFC 5737) so nothing real
// is ever routed, and the dummy link teardown removes every route with it.
func TestSyncRoutes_Kernel(t *testing.T) {
	linkName := fmt.Sprintf("tnltest%d", os.Getpid()%10000)

	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: linkName}}
	if err := netlink.LinkAdd(link); err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("SKIPPED, NOT TESTED: the kernel-route reconciliation was NOT "+
				"exercised because creating a network interface requires root "+
				"(CAP_NET_ADMIN). Run `sudo go test ./internal/wg/ -run TestSyncRoutes_Kernel -v` "+
				"to get this coverage (CI runners with passwordless sudo can do it as a step): %v", err)
		}
		t.Fatalf("create dummy link: %v", err)
	}
	t.Logf("root privileges found: exercising real netlink route reconciliation "+
		"against the throwaway dummy interface %q (TEST-NET-2 addresses, deleted on cleanup)", linkName)
	t.Cleanup(func() { _ = netlink.LinkDel(link) })

	addr, err := netlink.ParseAddr("198.51.100.1/24")
	if err != nil {
		t.Fatalf("parse addr: %v", err)
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		t.Fatalf("assign addr: %v", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatalf("link up: %v", err)
	}

	cfgWith := func(allowedIPs ...string) agentconfig.WireGuardConfig {
		peers := make([]agentconfig.WireGuardPeer, 0, len(allowedIPs))
		for _, ip := range allowedIPs {
			peers = append(peers, agentconfig.WireGuardPeer{AllowedIPs: []string{ip}})
		}
		return agentconfig.WireGuardConfig{Peers: peers}
	}

	routesOn := func() map[string]bool {
		t.Helper()
		installed, err := netlink.RouteListFiltered(netlink.FAMILY_ALL,
			&netlink.Route{LinkIndex: link.Attrs().Index}, netlink.RT_FILTER_OIF)
		if err != nil {
			t.Fatalf("list routes: %v", err)
		}
		out := make(map[string]bool)
		for _, r := range installed {
			if r.Dst != nil {
				out[r.Dst.String()] = true
			}
		}
		return out
	}

	// Scale up: three replicas.
	if err := syncRoutes(link, cfgWith("198.51.100.2/32", "198.51.100.3/32", "198.51.100.4/32")); err != nil {
		t.Fatalf("sync (3 replicas): %v", err)
	}
	routes := routesOn()
	for _, want := range []string{"198.51.100.2/32", "198.51.100.3/32", "198.51.100.4/32"} {
		if !routes[want] {
			t.Errorf("route %s missing after sync, have %v", want, routes)
		}
	}
	if !routes["198.51.100.0/24"] {
		t.Fatalf("expected the kernel subnet route to exist, have %v", routes)
	}

	// Scale down: replica .4 removed. Its route must go; the kernel subnet
	// route (RTPROT_KERNEL, claimed by no peer) must survive.
	if err := syncRoutes(link, cfgWith("198.51.100.2/32", "198.51.100.3/32")); err != nil {
		t.Fatalf("sync (2 replicas): %v", err)
	}
	routes = routesOn()
	if routes["198.51.100.4/32"] {
		t.Error("stale route 198.51.100.4/32 survived the scale-down")
	}
	for _, want := range []string{"198.51.100.2/32", "198.51.100.3/32"} {
		if !routes[want] {
			t.Errorf("route %s lost on scale-down, have %v", want, routes)
		}
	}
	if !routes["198.51.100.0/24"] {
		t.Error("the kernel subnet route was wrongly deleted")
	}

	// Idempotency: re-running with the same config changes nothing.
	if err := syncRoutes(link, cfgWith("198.51.100.2/32", "198.51.100.3/32")); err != nil {
		t.Fatalf("idempotent re-sync: %v", err)
	}
	after := routesOn()
	if len(after) != len(routes) {
		t.Errorf("idempotent re-sync changed routes: before %v, after %v", routes, after)
	}
}
