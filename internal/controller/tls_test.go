// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tunnelv1alpha1 "github.com/achetronic/tunnel/api/v1alpha1"
	"github.com/achetronic/tunnel/internal/sshexec"
)

// tlsSecretIncompleteReasonValue mirrors the Ready reason emitted when a TLS
// Secret is missing or incomplete, kept local to the test to avoid coupling.
const tlsSecretIncompleteReasonValue = "TLSSecretIncomplete"

var _ = Describe("EdgeNode Controller TLS", func() {
	const nodeName = "tls-node"

	ctx := context.Background()
	nodeKey := types.NamespacedName{Name: nodeName, Namespace: "default"}

	// healthyFactory injects a healthy fake executor so reconciliation reaches
	// the TLS handling without dialing a real host.
	healthyFactory := func(ctx context.Context, node *tunnelv1alpha1.EdgeNode, secret *corev1.Secret) (sshexec.Executor, error) {
		return healthyFakeExecutor(), nil
	}

	// newReconciler builds an EdgeNodeReconciler wired to the healthy fake.
	newReconciler := func() *EdgeNodeReconciler {
		return &EdgeNodeReconciler{
			Client:          k8sClient,
			Scheme:          k8sClient.Scheme(),
			TunnelctlDir:    tunnelctlTestDir,
			ExecutorFactory: healthyFactory,
		}
	}

	// makeEdgeNode creates the EdgeNode plus its SSH secret if absent.
	makeEdgeNode := func() {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tunnel"}}
		if err := k8sClient.Create(ctx, ns); err != nil && !errors.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tls-ssh-secret", Namespace: "default"},
			Data:       map[string][]byte{"password": []byte("test")},
		}
		if err := k8sClient.Create(ctx, secret); err != nil && !errors.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}
		node := &tunnelv1alpha1.EdgeNode{
			ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: "default"},
			Spec: tunnelv1alpha1.EdgeNodeSpec{
				Address: "198.51.100.20",
				SSH:     tunnelv1alpha1.SSHSpec{SecretRef: tunnelv1alpha1.SecretReference{Name: "tls-ssh-secret"}},
				Uplink:  tunnelv1alpha1.UplinkSpec{Namespace: "tunnel", Replicas: 1},
			},
		}
		if err := k8sClient.Create(ctx, node); err != nil && !errors.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}
	}

	// makePortBinding creates a PortBinding with one TLS TCP binding pointing at
	// the given secret name in the default namespace.
	makePortBinding := func(pbName string, mode, secretName string) {
		tls := &tunnelv1alpha1.TLSConfig{Mode: mode}
		if secretName != "" {
			tls.SecretRef = &tunnelv1alpha1.SecretReference{Name: secretName, Namespace: "default"}
		}
		pb := &tunnelv1alpha1.PortBinding{
			ObjectMeta: metav1.ObjectMeta{Name: pbName, Namespace: "default"},
			Spec: tunnelv1alpha1.PortBindingSpec{
				EdgeNodeRef: tunnelv1alpha1.ObjectReference{Name: nodeName, Namespace: "default"},
				Bindings: []tunnelv1alpha1.PortBindingDefinition{
					{
						Name:       "https",
						Protocol:   "TCP",
						ListenPort: 8443,
						TLS:        tls,
						Target: tunnelv1alpha1.BindingTarget{
							Address: "10.96.0.20",
							Port:    8443,
						},
					},
				},
			},
		}
		Expect(k8sClient.Create(ctx, pb)).To(Succeed())
	}

	BeforeEach(func() {
		makeEdgeNode()
	})

	AfterEach(func() {
		// Remove PortBindings, the EdgeNode (skipping SSH teardown) and any TLS
		// secrets so each spec starts clean.
		pbList := &tunnelv1alpha1.PortBindingList{}
		Expect(k8sClient.List(ctx, pbList)).To(Succeed())
		for i := range pbList.Items {
			pb := &pbList.Items[i]
			pb.Finalizers = nil
			_ = k8sClient.Update(ctx, pb)
			_ = k8sClient.Delete(ctx, pb)
		}

		node := &tunnelv1alpha1.EdgeNode{}
		if err := k8sClient.Get(ctx, nodeKey, node); err == nil {
			if node.Annotations == nil {
				node.Annotations = map[string]string{}
			}
			node.Annotations["tunnel.achetronic.com/skip-deprovision"] = annotationTrue
			_ = k8sClient.Update(ctx, node)
			_ = k8sClient.Delete(ctx, node)
			_, _ = newReconciler().Reconcile(ctx, reconcile.Request{NamespacedName: nodeKey})
			fresh := &tunnelv1alpha1.EdgeNode{}
			if err := k8sClient.Get(ctx, nodeKey, fresh); err == nil {
				fresh.Finalizers = nil
				_ = k8sClient.Update(ctx, fresh)
				_ = k8sClient.Delete(ctx, fresh)
			}
		}
	})

	It("reconciles an offload binding when the TLS secret is complete", func() {
		Expect(k8sClient.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "offload-tls", Namespace: "default"},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{"tls.crt": []byte("CERT"), "tls.key": []byte("KEY")},
		})).To(Succeed())
		makePortBinding("pb-offload", "offload", "offload-tls")

		_, err := newReconciler().Reconcile(ctx, reconcile.Request{NamespacedName: nodeKey})
		Expect(err).NotTo(HaveOccurred())

		updated := &tunnelv1alpha1.EdgeNode{}
		Expect(k8sClient.Get(ctx, nodeKey, updated)).To(Succeed())
		cond := meta.FindStatusCondition(updated.Status.Conditions, "Ready")
		Expect(cond).NotTo(BeNil())
		Expect(cond.Reason).NotTo(Equal(tlsSecretIncompleteReasonValue))
	})

	It("marks Ready False with TLSSecretIncomplete when the TLS secret is absent", func() {
		makePortBinding("pb-missing", "offload", "does-not-exist")

		_, err := newReconciler().Reconcile(ctx, reconcile.Request{NamespacedName: nodeKey})
		Expect(err).To(HaveOccurred())

		updated := &tunnelv1alpha1.EdgeNode{}
		Expect(k8sClient.Get(ctx, nodeKey, updated)).To(Succeed())
		cond := meta.FindStatusCondition(updated.Status.Conditions, "Ready")
		Expect(cond).NotTo(BeNil())
		Expect(cond.Status).To(Equal(metav1.ConditionFalse))
		Expect(cond.Reason).To(Equal(tlsSecretIncompleteReasonValue))
	})

	It("marks Ready False with TLSSecretIncomplete when a mutual binding lacks ca.crt", func() {
		Expect(k8sClient.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "mutual-tls", Namespace: "default"},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{"tls.crt": []byte("CERT"), "tls.key": []byte("KEY")},
		})).To(Succeed())
		makePortBinding("pb-mutual", "mutual", "mutual-tls")

		_, err := newReconciler().Reconcile(ctx, reconcile.Request{NamespacedName: nodeKey})
		Expect(err).To(HaveOccurred())

		updated := &tunnelv1alpha1.EdgeNode{}
		Expect(k8sClient.Get(ctx, nodeKey, updated)).To(Succeed())
		cond := meta.FindStatusCondition(updated.Status.Conditions, "Ready")
		Expect(cond).NotTo(BeNil())
		Expect(cond.Reason).To(Equal(tlsSecretIncompleteReasonValue))
	})

	It("maps a referenced TLS secret to the owning EdgeNode and ignores unrelated ones", func() {
		makePortBinding("pb-map", "offload", "mapped-tls")

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "mapped-tls", Namespace: "default"},
		}
		reqs := newReconciler().mapSecretToEdgeNodes(ctx, secret)
		Expect(reqs).To(ContainElement(reconcile.Request{NamespacedName: nodeKey}))

		unrelated := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "nobody-references-me", Namespace: "default"},
		}
		Expect(newReconciler().mapSecretToEdgeNodes(ctx, unrelated)).To(BeEmpty())
	})
})
