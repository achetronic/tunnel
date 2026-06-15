// SPDX-FileCopyrightText: 2026 Alby Hernández (Achetronic)
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/achetronic/tunnel/api/v1alpha1"
)

// appliedBindingKeys feeds EdgeNodeStatus.AppliedBindings, the field the
// PortBindingReconciler reads to set Ready honestly. Keys must be
// namespace/name, sorted (deterministic status for the DeepEqual no-op
// skip), and nil for no bindings (so an empty plan clears the field).
func TestAppliedBindingKeys(t *testing.T) {
	pb := func(ns, name string) v1alpha1.PortBinding {
		return v1alpha1.PortBinding{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
	}

	got := appliedBindingKeys([]v1alpha1.PortBinding{
		pb("zoo", "b"),
		pb("app", "z"),
		pb("app", "a"),
	})
	want := []string{"app/a", "app/z", "zoo/b"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("key %d: got %q, want %q", i, got[i], want[i])
		}
	}

	if got := appliedBindingKeys(nil); got != nil {
		t.Errorf("no bindings: expected nil, got %v", got)
	}
}
