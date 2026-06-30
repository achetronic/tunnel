// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tunnelv1alpha1 "github.com/achetronic/tunnel/api/v1alpha1"
)

var _ = Describe("PortBinding Controller", func() {
	ctx := context.Background()

	newReconciler := func() *PortBindingReconciler {
		return &PortBindingReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}
	}

	It("should not error when the PortBinding does not exist", func() {
		_, err := newReconciler().Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "does-not-exist", Namespace: "default"},
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should map a PortBinding to its referenced EdgeNode", func() {
		pb := &tunnelv1alpha1.PortBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "pb-map", Namespace: "default"},
			Spec: tunnelv1alpha1.PortBindingSpec{
				EdgeNodeRef: tunnelv1alpha1.ObjectReference{Name: "some-node"},
			},
		}
		en := &EdgeNodeReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		reqs := en.mapPortBindingToEdgeNode(ctx, pb)
		Expect(reqs).To(ConsistOf(reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "some-node", Namespace: "default"},
		}))

		By("honouring an explicit EdgeNodeRef namespace")
		pb.Spec.EdgeNodeRef.Namespace = "infra"
		reqs = en.mapPortBindingToEdgeNode(ctx, pb)
		Expect(reqs).To(ConsistOf(reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "some-node", Namespace: "infra"},
		}))

		By("mapping nothing when the ref name is empty")
		pb.Spec.EdgeNodeRef = tunnelv1alpha1.ObjectReference{}
		Expect(en.mapPortBindingToEdgeNode(ctx, pb)).To(BeEmpty())
	})

	It("should publish conditions without writing to the EdgeNode", func() {
		By("creating an EdgeNode the binding references")
		node := &tunnelv1alpha1.EdgeNode{
			ObjectMeta: metav1.ObjectMeta{Name: "cond-node", Namespace: "default"},
			Spec: tunnelv1alpha1.EdgeNodeSpec{
				Address: "envtest-fake",
				SSH: tunnelv1alpha1.SSHSpec{
					SecretRef: tunnelv1alpha1.SecretReference{Name: "fake-secret"},
				},
			},
		}
		Expect(k8sClient.Create(ctx, node)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, node) })
		nodeVersionBefore := node.ResourceVersion

		By("creating a PortBinding referencing the node")
		pb := &tunnelv1alpha1.PortBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "pb-cond", Namespace: "default"},
			Spec: tunnelv1alpha1.PortBindingSpec{
				EdgeNodeRef: tunnelv1alpha1.ObjectReference{Name: "cond-node"},
				Bindings: []tunnelv1alpha1.PortBindingDefinition{
					{
						Name:       "test-port",
						Protocol:   "TCP",
						ListenPort: 8080,
						Target:     tunnelv1alpha1.BindingTarget{Address: "127.0.0.1", Port: 80},
					},
				},
			},
		}
		Expect(k8sClient.Create(ctx, pb)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, pb) })

		pbKey := types.NamespacedName{Name: "pb-cond", Namespace: "default"}

		By("reconciling the PortBinding")
		_, err := newReconciler().Reconcile(ctx, reconcile.Request{NamespacedName: pbKey})
		Expect(err).NotTo(HaveOccurred())

		By("verifying no finalizer was added")
		updatedPB := &tunnelv1alpha1.PortBinding{}
		Expect(k8sClient.Get(ctx, pbKey, updatedPB)).To(Succeed())
		Expect(controllerutil.ContainsFinalizer(updatedPB, portBindingFinalizer)).To(BeFalse())

		By("verifying the conditions were published")
		programmed := findCondition(updatedPB.Status.Conditions, "Programmed")
		Expect(programmed).NotTo(BeNil())
		Expect(programmed.Status).To(Equal(metav1.ConditionTrue))
		ready := findCondition(updatedPB.Status.Conditions, "Ready")
		Expect(ready).NotTo(BeNil())
		Expect(ready.Reason).To(Equal("NotYetApplied"))

		By("verifying the EdgeNode object was not mutated")
		updatedNode := &tunnelv1alpha1.EdgeNode{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "cond-node", Namespace: "default"}, updatedNode)).To(Succeed())
		Expect(updatedNode.ResourceVersion).To(Equal(nodeVersionBefore))
	})

	It("should remove a lingering finalizer so deletion completes", func() {
		By("creating a PortBinding that carries the finalizer")
		pb := &tunnelv1alpha1.PortBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "pb-del",
				Namespace:  "default",
				Finalizers: []string{portBindingFinalizer},
			},
			Spec: tunnelv1alpha1.PortBindingSpec{
				EdgeNodeRef: tunnelv1alpha1.ObjectReference{Name: "del-node"},
				Bindings: []tunnelv1alpha1.PortBindingDefinition{
					{
						Name:       "p",
						Protocol:   "TCP",
						ListenPort: 9090,
						Target:     tunnelv1alpha1.BindingTarget{Address: "127.0.0.1", Port: 80},
					},
				},
			},
		}
		Expect(k8sClient.Create(ctx, pb)).To(Succeed())
		pbKey := types.NamespacedName{Name: "pb-del", Namespace: "default"}

		By("deleting the PortBinding (finalizer keeps it around)")
		Expect(k8sClient.Delete(ctx, pb)).To(Succeed())

		By("reconciling the deletion")
		_, err := newReconciler().Reconcile(ctx, reconcile.Request{NamespacedName: pbKey})
		Expect(err).NotTo(HaveOccurred())

		By("verifying the PortBinding is fully gone after the finalizer is removed")
		gone := &tunnelv1alpha1.PortBinding{}
		err = k8sClient.Get(ctx, pbKey, gone)
		Expect(errors.IsNotFound(err)).To(BeTrue())
	})
})

// findCondition returns the condition with the given type or nil when absent.
func findCondition(conditions []metav1.Condition, condType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == condType {
			return &conditions[i]
		}
	}
	return nil
}
