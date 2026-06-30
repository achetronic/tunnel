// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tunnelv1alpha1 "github.com/achetronic/tunnel/api/v1alpha1"
)

// The Programmed/Ready pair (TODO #17): Programmed records the trigger,
// Ready only goes True once the EdgeNode reports the binding inside its
// applied plan via status.appliedBindings. The reconcilers communicate
// exclusively through the API server.
var _ = Describe("PortBinding conditions", func() {
	ctx := context.Background()

	newReconciler := func() *PortBindingReconciler {
		return &PortBindingReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}
	}

	makeNode := func(name string) *tunnelv1alpha1.EdgeNode {
		return &tunnelv1alpha1.EdgeNode{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec: tunnelv1alpha1.EdgeNodeSpec{
				Address: "envtest-fake",
				SSH: tunnelv1alpha1.SSHSpec{
					SecretRef: tunnelv1alpha1.SecretReference{Name: "fake-secret"},
				},
			},
		}
	}

	makeBinding := func(name, nodeName string, port int32) *tunnelv1alpha1.PortBinding {
		return &tunnelv1alpha1.PortBinding{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec: tunnelv1alpha1.PortBindingSpec{
				EdgeNodeRef: tunnelv1alpha1.ObjectReference{Name: nodeName},
				Bindings: []tunnelv1alpha1.PortBindingDefinition{
					{
						Name:       "p",
						Protocol:   "TCP",
						ListenPort: port,
						Target:     tunnelv1alpha1.BindingTarget{Address: "127.0.0.1", Port: 80},
					},
				},
			},
		}
	}

	It("sets Programmed=True and Ready=False before the plan is applied", func() {
		node := makeNode("cond-node-pending")
		Expect(k8sClient.Create(ctx, node)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, node) })

		pb := makeBinding("pb-cond-pending", "cond-node-pending", 8181)
		Expect(k8sClient.Create(ctx, pb)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, pb) })

		pbKey := types.NamespacedName{Name: "pb-cond-pending", Namespace: "default"}
		_, err := newReconciler().Reconcile(ctx, reconcile.Request{NamespacedName: pbKey})
		Expect(err).NotTo(HaveOccurred())

		updated := &tunnelv1alpha1.PortBinding{}
		Expect(k8sClient.Get(ctx, pbKey, updated)).To(Succeed())

		programmed := meta.FindStatusCondition(updated.Status.Conditions, "Programmed")
		Expect(programmed).NotTo(BeNil())
		Expect(programmed.Status).To(Equal(metav1.ConditionTrue))

		ready := meta.FindStatusCondition(updated.Status.Conditions, "Ready")
		Expect(ready).NotTo(BeNil())
		Expect(ready.Status).To(Equal(metav1.ConditionFalse))
		Expect(ready.Reason).To(Equal("NotYetApplied"))
	})

	It("sets Ready=True once the EdgeNode reports the binding as applied", func() {
		node := makeNode("cond-node-applied")
		Expect(k8sClient.Create(ctx, node)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, node) })

		pb := makeBinding("pb-cond-applied", "cond-node-applied", 8282)
		Expect(k8sClient.Create(ctx, pb)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, pb) })

		By("simulating the EdgeNodeReconciler reporting the binding in the applied plan")
		current := &tunnelv1alpha1.EdgeNode{}
		nodeKey := types.NamespacedName{Name: "cond-node-applied", Namespace: "default"}
		Expect(k8sClient.Get(ctx, nodeKey, current)).To(Succeed())
		current.Status.AppliedBindings = []string{"default/pb-cond-applied"}
		Expect(k8sClient.Status().Update(ctx, current)).To(Succeed())

		pbKey := types.NamespacedName{Name: "pb-cond-applied", Namespace: "default"}
		_, err := newReconciler().Reconcile(ctx, reconcile.Request{NamespacedName: pbKey})
		Expect(err).NotTo(HaveOccurred())

		updated := &tunnelv1alpha1.PortBinding{}
		Expect(k8sClient.Get(ctx, pbKey, updated)).To(Succeed())

		ready := meta.FindStatusCondition(updated.Status.Conditions, "Ready")
		Expect(ready).NotTo(BeNil())
		Expect(ready.Status).To(Equal(metav1.ConditionTrue))
		Expect(ready.Reason).To(Equal("Applied"))
	})

	It("sets Ready=False with EdgeNodeNotFound when the referenced node is gone", func() {
		pb := makeBinding("pb-cond-orphan", "cond-node-never-existed", 8383)
		Expect(k8sClient.Create(ctx, pb)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, pb) })

		pbKey := types.NamespacedName{Name: "pb-cond-orphan", Namespace: "default"}
		_, err := newReconciler().Reconcile(ctx, reconcile.Request{NamespacedName: pbKey})
		Expect(err).NotTo(HaveOccurred())

		updated := &tunnelv1alpha1.PortBinding{}
		Expect(k8sClient.Get(ctx, pbKey, updated)).To(Succeed())

		ready := meta.FindStatusCondition(updated.Status.Conditions, "Ready")
		Expect(ready).NotTo(BeNil())
		Expect(ready.Status).To(Equal(metav1.ConditionFalse))
		Expect(ready.Reason).To(Equal("EdgeNodeNotFound"))
	})

	It("maps EdgeNode events to requests for exactly its referencing bindings", func() {
		node := makeNode("cond-node-map")
		Expect(k8sClient.Create(ctx, node)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, node) })

		mine := makeBinding("pb-map-mine", "cond-node-map", 8484)
		Expect(k8sClient.Create(ctx, mine)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, mine) })

		other := makeBinding("pb-map-other", "some-other-node", 8585)
		Expect(k8sClient.Create(ctx, other)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, other) })

		reqs := newReconciler().bindingsForEdgeNode(ctx, node)
		names := make([]string, 0, len(reqs))
		for _, r := range reqs {
			names = append(names, r.Name)
		}
		Expect(names).To(ContainElement("pb-map-mine"))
		Expect(names).NotTo(ContainElement("pb-map-other"))
	})
})
