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

package uplink

import (
	"testing"

	"github.com/achetronic/tunnel/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// testOwnerNamespace is the EdgeNode namespace used across the uplink label tests.
const testOwnerNamespace = "tenant-a"

// TestLabelsForNode verifies that LabelsForNode returns the owner namespace label
// in addition to the standard node labels.
func TestLabelsForNode(t *testing.T) {
	node := &v1alpha1.EdgeNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-node",
			Namespace: testOwnerNamespace,
		},
	}

	labels := LabelsForNode(node)
	if labels["tunnel.achetronic.com/owner-namespace"] != testOwnerNamespace {
		t.Errorf("expected owner namespace label to be tenant-a, got %s", labels["tunnel.achetronic.com/owner-namespace"])
	}
}

// TestBuildHeadlessService verifies that the headless service has the owner label
// in its metadata but excludes it from the selector to ensure immutability.
func TestBuildHeadlessService(t *testing.T) {
	node := &v1alpha1.EdgeNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-node",
			Namespace: testOwnerNamespace,
		},
		Spec: v1alpha1.EdgeNodeSpec{
			Uplink: v1alpha1.UplinkSpec{
				Namespace: "tunnel",
			},
		},
	}

	svc := BuildHeadlessService(node)
	if svc.Labels["tunnel.achetronic.com/owner-namespace"] != testOwnerNamespace {
		t.Errorf("expected service metadata owner label to be tenant-a, got %s", svc.Labels["tunnel.achetronic.com/owner-namespace"])
	}

	if _, exists := svc.Spec.Selector["tunnel.achetronic.com/owner-namespace"]; exists {
		t.Error("expected owner label to be excluded from service selector")
	}
}

// TestBuildStatefulSet verifies that the StatefulSet has the owner label in its
// metadata and pod template, but excludes it from the selector to ensure immutability.
func TestBuildStatefulSet(t *testing.T) {
	node := &v1alpha1.EdgeNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-node",
			Namespace: testOwnerNamespace,
		},
		Spec: v1alpha1.EdgeNodeSpec{
			Uplink: v1alpha1.UplinkSpec{
				Namespace: "tunnel",
			},
		},
	}

	sts := BuildStatefulSet(node, "test-image", corev1.PullIfNotPresent)
	if sts.Labels["tunnel.achetronic.com/owner-namespace"] != testOwnerNamespace {
		t.Errorf("expected statefulset metadata owner label to be tenant-a, got %s", sts.Labels["tunnel.achetronic.com/owner-namespace"])
	}

	if sts.Spec.Template.Labels["tunnel.achetronic.com/owner-namespace"] != testOwnerNamespace {
		t.Errorf("expected pod template owner label to be tenant-a, got %s", sts.Spec.Template.Labels["tunnel.achetronic.com/owner-namespace"])
	}

	if _, exists := sts.Spec.Selector.MatchLabels["tunnel.achetronic.com/owner-namespace"]; exists {
		t.Error("expected owner label to be excluded from statefulset selector")
	}

	term := sts.Spec.Template.Spec.Affinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution[0]
	if _, exists := term.LabelSelector.MatchLabels["tunnel.achetronic.com/owner-namespace"]; exists {
		t.Error("expected owner label to be excluded from pod anti-affinity label selector")
	}
}
