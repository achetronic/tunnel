// SPDX-FileCopyrightText: 2026 Alby Hernández (Achetronic)
// SPDX-License-Identifier: Apache-2.0

package netdev

import (
	"fmt"
	"maps"
	"testing"

	"github.com/achetronic/tunnel/internal/agentconfig"
)

// fakeController is an in-memory featureController for unit tests. It records the
// Change calls so a test can assert exactly which features were toggled.
type fakeController struct {
	features    map[string]bool
	featuresErr error
	changeErr   error
	changes     []map[string]bool
}

// Features returns the canned feature map (or the canned error).
func (f *fakeController) Features(string) (map[string]bool, error) {
	if f.featuresErr != nil {
		return nil, f.featuresErr
	}
	out := make(map[string]bool, len(f.features))
	maps.Copy(out, f.features)
	return out, nil
}

// Change records the requested change (or returns the canned error).
func (f *fakeController) Change(_ string, config map[string]bool) error {
	if f.changeErr != nil {
		return f.changeErr
	}
	f.changes = append(f.changes, config)
	return nil
}

// staticResolver returns a fixed interface name, standing in for the netlink
// route lookup so unit tests need no real NIC.
func staticResolver(name string) interfaceResolver {
	return func() (string, error) { return name, nil }
}

// TestApplyOffloads covers the decision core across every meaningful shape:
// disabled section is a no-op, both offloads on get turned off, already-off and
// unsupported features are left alone, and read/change errors are wrapped.
func TestApplyOffloads(t *testing.T) {
	t.Run("disable offloads false is a no-op", func(t *testing.T) {
		ctrl := &fakeController{features: map[string]bool{"rx-gro": true}}
		if err := applyOffloads(staticResolver("eth0"), ctrl, agentconfig.NetdevConfig{DisableOffloads: false}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ctrl.changes) != 0 {
			t.Fatalf("no change expected when DisableOffloads is false, got %v", ctrl.changes)
		}
	})

	t.Run("both offloads on are turned off", func(t *testing.T) {
		ctrl := &fakeController{features: map[string]bool{
			"rx-gro":                  true,
			"tx-generic-segmentation": true,
			"tx-checksum-ip-generic":  true,
		}}
		if err := applyOffloads(staticResolver("eth0"), ctrl, agentconfig.NetdevConfig{DisableOffloads: true}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ctrl.changes) != 1 {
			t.Fatalf("expected exactly one Change call, got %d", len(ctrl.changes))
		}
		got := ctrl.changes[0]
		if len(got) != 2 || got["rx-gro"] != false || got["tx-generic-segmentation"] != false {
			t.Fatalf("expected GRO+GSO disabled only, got %v", got)
		}
	})

	t.Run("already off is idempotent no-op", func(t *testing.T) {
		ctrl := &fakeController{features: map[string]bool{
			"rx-gro":                  false,
			"tx-generic-segmentation": false,
		}}
		if err := applyOffloads(staticResolver("eth0"), ctrl, agentconfig.NetdevConfig{DisableOffloads: true}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ctrl.changes) != 0 {
			t.Fatalf("no change expected when offloads already off, got %v", ctrl.changes)
		}
	})

	t.Run("unsupported feature is skipped", func(t *testing.T) {
		// The driver only reports GSO; GRO is absent and must not be requested.
		ctrl := &fakeController{features: map[string]bool{"tx-generic-segmentation": true}}
		if err := applyOffloads(staticResolver("eth0"), ctrl, agentconfig.NetdevConfig{DisableOffloads: true}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ctrl.changes) != 1 {
			t.Fatalf("expected one Change call, got %d", len(ctrl.changes))
		}
		got := ctrl.changes[0]
		if len(got) != 1 || got["tx-generic-segmentation"] != false {
			t.Fatalf("expected only GSO disabled, got %v", got)
		}
		if _, ok := got["rx-gro"]; ok {
			t.Fatal("unsupported rx-gro must not be requested")
		}
	})

	t.Run("read features error is wrapped", func(t *testing.T) {
		ctrl := &fakeController{featuresErr: fmt.Errorf("boom")}
		err := applyOffloads(staticResolver("eth0"), ctrl, agentconfig.NetdevConfig{DisableOffloads: true})
		if err == nil {
			t.Fatal("expected an error when reading features fails")
		}
	})

	t.Run("change error is wrapped", func(t *testing.T) {
		ctrl := &fakeController{features: map[string]bool{"rx-gro": true}, changeErr: fmt.Errorf("denied")}
		err := applyOffloads(staticResolver("eth0"), ctrl, agentconfig.NetdevConfig{DisableOffloads: true})
		if err == nil {
			t.Fatal("expected an error when Change fails")
		}
	})

	t.Run("resolver error is wrapped", func(t *testing.T) {
		failing := func() (string, error) { return "", fmt.Errorf("no route") }
		ctrl := &fakeController{features: map[string]bool{"rx-gro": true}}
		err := applyOffloads(failing, ctrl, agentconfig.NetdevConfig{DisableOffloads: true})
		if err == nil {
			t.Fatal("expected an error when interface resolution fails")
		}
	})
}
