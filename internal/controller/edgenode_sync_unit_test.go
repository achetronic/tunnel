/*
Copyright 2026 achetronic.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
