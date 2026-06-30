// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package netdev

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/safchain/ethtool"
	"github.com/vishvananda/netlink"

	"github.com/achetronic/tunnel/internal/agentconfig"
)

// TestApplyOffloads_Kernel exercises the real ethtool IO path against a throwaway
// dummy interface: it opens the SIOCETHTOOL handle, reads the device offload
// features and best-effort disables GRO/GSO through applyOffloads with the dummy
// pinned as the underlay.
//
// It needs CAP_NET_ADMIN (run as root: `sudo go test ./internal/netdev/`).
// It self-skips with an explicit "SKIPPED, NOT TESTED" message when unprivileged,
// and also when the kernel/dummy driver does not expose the offload features
// (dummy interfaces frequently report a fixed feature set that cannot be
// toggled), so the default `go test ./...` and unprivileged CI stay green while a
// sudo CI step provides the coverage.
func TestApplyOffloads_Kernel(t *testing.T) {
	handle, err := ethtool.NewEthtool()
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("SKIPPED, NOT TESTED: the ethtool offload path was NOT exercised "+
				"because opening the SIOCETHTOOL socket requires root (CAP_NET_ADMIN). "+
				"Run `sudo go test ./internal/netdev/ -run TestApplyOffloads_Kernel -v` "+
				"to get this coverage (CI runners with passwordless sudo can do it as a step): %v", err)
		}
		t.Skipf("SKIPPED, NOT TESTED: ethtool is unavailable in this environment: %v", err)
	}
	defer handle.Close()

	linkName := fmt.Sprintf("tnlnd%d", os.Getpid()%10000)
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: linkName}}
	if err := netlink.LinkAdd(link); err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("SKIPPED, NOT TESTED: the offload toggle was NOT exercised because "+
				"creating a network interface requires root (CAP_NET_ADMIN). "+
				"Run `sudo go test ./internal/netdev/ -run TestApplyOffloads_Kernel -v` "+
				"to get this coverage: %v", err)
		}
		t.Fatalf("create dummy link: %v", err)
	}
	t.Logf("root privileges found: exercising real ethtool offload toggling "+
		"against the throwaway dummy interface %q (deleted on cleanup)", linkName)
	t.Cleanup(func() { _ = netlink.LinkDel(link) })

	features, err := handle.Features(linkName)
	if err != nil {
		t.Skipf("SKIPPED, NOT TESTED: the dummy interface %q does not support reading "+
			"ethtool features in this environment, so the offload toggle could not be "+
			"exercised (this is expected for dummy drivers): %v", linkName, err)
	}

	togglable := false
	for _, key := range offloadFeatureKeys {
		if _, ok := features[key]; ok {
			togglable = true
			break
		}
	}
	if !togglable {
		t.Skipf("SKIPPED, NOT TESTED: the dummy interface %q exposes none of %v, so the "+
			"offload toggle could not be exercised (dummy drivers report a fixed feature "+
			"set); run this on a host with a real NIC for full coverage", linkName, offloadFeatureKeys)
	}

	resolve := staticResolver(linkName)
	if err := applyOffloads(resolve, handle, agentconfig.NetdevConfig{DisableOffloads: true}); err != nil {
		t.Skipf("SKIPPED, NOT TESTED: the dummy interface %q does not allow toggling the "+
			"offload features (drivers may pin them), so the change could not be applied: %v", linkName, err)
	}

	// Idempotency: re-running with the features now off must not error.
	if err := applyOffloads(resolve, handle, agentconfig.NetdevConfig{DisableOffloads: true}); err != nil {
		t.Fatalf("idempotent re-apply failed: %v", err)
	}

	after, err := handle.Features(linkName)
	if err != nil {
		t.Fatalf("re-read features: %v", err)
	}
	for _, key := range offloadFeatureKeys {
		if enabled, ok := after[key]; ok && enabled {
			t.Errorf("feature %q is still enabled after disabling offloads", key)
		}
	}
}
