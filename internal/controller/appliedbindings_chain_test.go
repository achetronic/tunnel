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
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tunnelv1alpha1 "github.com/achetronic/tunnel/api/v1alpha1"
	"github.com/achetronic/tunnel/internal/sshexec"
)

// End-to-end chain for the Programmed/Ready pair (TODO #17), with the SSH
// boundary faked but every other layer real: the EdgeNode reconcile runs the
// full sync (plan build, enroll against the FakeExecutor, uplink workload,
// status write) and must publish status.appliedBindings; the PortBinding
// reconcile then reads it and flips Ready to True. This closes the gap the
// unit specs in portbinding_conditions_test.go leave open, where
// appliedBindings was planted by hand.
var _ = Describe("AppliedBindings end-to-end chain", func() {
	ctx := context.Background()

	const nodeName = "chain-node"
	const pbName = "chain-binding"

	nodeKey := types.NamespacedName{Name: nodeName, Namespace: "default"}
	pbKey := types.NamespacedName{Name: pbName, Namespace: "default"}

	BeforeEach(func() {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "chain-ssh-secret", Namespace: "default"},
			Data:       map[string][]byte{"password": []byte("test")},
		}
		if err := k8sClient.Create(ctx, secret); err != nil && !errors.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}

		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tunnel"}}
		if err := k8sClient.Create(ctx, ns); err != nil && !errors.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}

		node := &tunnelv1alpha1.EdgeNode{
			ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: "default"},
			Spec: tunnelv1alpha1.EdgeNodeSpec{
				Address: "198.51.100.20",
				SSH: tunnelv1alpha1.SSHSpec{
					SecretRef: tunnelv1alpha1.SecretReference{Name: "chain-ssh-secret"},
				},
				Uplink: tunnelv1alpha1.UplinkSpec{Namespace: "tunnel", Replicas: 1},
			},
		}
		Expect(k8sClient.Create(ctx, node)).To(Succeed())

		pb := &tunnelv1alpha1.PortBinding{
			ObjectMeta: metav1.ObjectMeta{Name: pbName, Namespace: "default"},
			Spec: tunnelv1alpha1.PortBindingSpec{
				EdgeNodeRef: tunnelv1alpha1.ObjectReference{Name: nodeName},
				Bindings: []tunnelv1alpha1.PortBindingDefinition{
					{
						Name:       "web",
						Protocol:   "TCP",
						ListenPort: 8443,
						Target:     tunnelv1alpha1.BindingTarget{Address: "10.0.0.10", Port: 443},
					},
				},
			},
		}
		Expect(k8sClient.Create(ctx, pb)).To(Succeed())
	})

	AfterEach(func() {
		pb := &tunnelv1alpha1.PortBinding{}
		if err := k8sClient.Get(ctx, pbKey, pb); err == nil {
			pb.Finalizers = nil
			_ = k8sClient.Update(ctx, pb)
			_ = k8sClient.Delete(ctx, pb)
		}
		node := &tunnelv1alpha1.EdgeNode{}
		if err := k8sClient.Get(ctx, nodeKey, node); err == nil {
			node.Finalizers = nil
			_ = k8sClient.Update(ctx, node)
			_ = k8sClient.Delete(ctx, node)
		}
	})

	It("publishes appliedBindings after a successful sync and flips the PortBinding to Ready", func() {
		edgeReconciler := &EdgeNodeReconciler{
			Client:       k8sClient,
			Scheme:       k8sClient.Scheme(),
			TunnelctlDir: tunnelctlTestDir,
			ExecutorFactory: func(ctx context.Context, node *tunnelv1alpha1.EdgeNode, secret *corev1.Secret) (sshexec.Executor, error) {
				return healthyFakeExecutor(), nil
			},
		}
		pbReconciler := &PortBindingReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}

		By("reconciling the PortBinding first: Ready must be honestly False")
		_, err := pbReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: pbKey})
		Expect(err).NotTo(HaveOccurred())

		pb := &tunnelv1alpha1.PortBinding{}
		Expect(k8sClient.Get(ctx, pbKey, pb)).To(Succeed())
		ready := meta.FindStatusCondition(pb.Status.Conditions, "Ready")
		Expect(ready).NotTo(BeNil())
		Expect(ready.Status).To(Equal(metav1.ConditionFalse))
		Expect(ready.Reason).To(Equal("NotYetApplied"))

		By("running the full EdgeNode sync (enroll via fake SSH)")
		_, err = edgeReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nodeKey})
		Expect(err).NotTo(HaveOccurred())

		By("verifying the sync published the binding in status.appliedBindings")
		node := &tunnelv1alpha1.EdgeNode{}
		Expect(k8sClient.Get(ctx, nodeKey, node)).To(Succeed())
		Expect(node.Status.AppliedBindings).To(ContainElement("default/" + pbName))

		By("re-reconciling the PortBinding: Ready must now be True")
		_, err = pbReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: pbKey})
		Expect(err).NotTo(HaveOccurred())

		Expect(k8sClient.Get(ctx, pbKey, pb)).To(Succeed())
		ready = meta.FindStatusCondition(pb.Status.Conditions, "Ready")
		Expect(ready).NotTo(BeNil())
		Expect(ready.Status).To(Equal(metav1.ConditionTrue))
		Expect(ready.Reason).To(Equal("Applied"))
	})

	It("records appliedBindings even when an in-cluster step fails after a successful enroll", func() {
		// Pre-create the uplink StatefulSet with a selector that differs from the
		// one the operator renders. A StatefulSet selector is immutable, so the
		// reconcile's createOrUpdateStatefulSet fails AFTER the SSH enroll has
		// already materialized the binding on the VPS. The status must still carry
		// appliedBindings so the PortBinding can reach Ready and the next reconcile
		// does not see a phantom drift.
		// A StatefulSet selector is immutable, so an existing uplink StatefulSet
		// with a foreign selector makes the reconcile's createOrUpdateStatefulSet
		// fail AFTER the SSH enroll already materialized the binding on the VPS.
		// Remove any uplink StatefulSet a prior spec left behind so this case owns
		// a clean slate, then plant the conflicting one.
		stsKey := types.NamespacedName{Name: nodeName + "-uplink", Namespace: "tunnel"}
		stale := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: stsKey.Name, Namespace: stsKey.Namespace}}
		_ = k8sClient.Delete(ctx, stale)
		Eventually(func() bool {
			return errors.IsNotFound(k8sClient.Get(ctx, stsKey, &appsv1.StatefulSet{}))
		}, "10s", "200ms").Should(BeTrue())

		conflicting := &appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Name: stsKey.Name, Namespace: stsKey.Namespace},
			Spec: appsv1.StatefulSetSpec{
				ServiceName: nodeName + "-uplink",
				Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"foreign": "selector"}},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"foreign": "selector"}},
					Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "busybox"}}},
				},
			},
		}
		Expect(k8sClient.Create(ctx, conflicting)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, conflicting) })

		edgeReconciler := &EdgeNodeReconciler{
			Client:       k8sClient,
			Scheme:       k8sClient.Scheme(),
			TunnelctlDir: tunnelctlTestDir,
			ExecutorFactory: func(ctx context.Context, node *tunnelv1alpha1.EdgeNode, secret *corev1.Secret) (sshexec.Executor, error) {
				return healthyFakeExecutor(), nil
			},
		}

		By("running the EdgeNode sync: the StatefulSet update must fail after enroll")
		_, err := edgeReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: nodeKey})
		Expect(err).To(HaveOccurred())

		By("verifying appliedBindings was still persisted despite the later failure")
		node := &tunnelv1alpha1.EdgeNode{}
		Expect(k8sClient.Get(ctx, nodeKey, node)).To(Succeed())
		Expect(node.Status.AppliedBindings).To(ContainElement("default/" + pbName))
		Expect(node.Status.AppliedConfigHash).NotTo(BeEmpty())
	})
})
