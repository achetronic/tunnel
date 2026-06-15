// SPDX-FileCopyrightText: 2026 Alby Hernández (Achetronic)
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tunnelv1alpha1 "github.com/achetronic/tunnel/api/v1alpha1"
	"github.com/achetronic/tunnel/internal/sshexec"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// activeServiceOutput is the systemctl output for a running service.
const activeServiceOutput = "active\n"

// statusWriteCountingClient wraps a client.Client and counts how many times
// Status().Update() is invoked. The envtest apiserver silently no-ops updates
// whose content is identical (the ResourceVersion does not change), so counting
// the calls at the client boundary is the only honest way to assert that the
// reconciler skipped the status write rather than relying on the apiserver to
// absorb it.
type statusWriteCountingClient struct {
	client.Client
	statusUpdates *int
}

func (c *statusWriteCountingClient) Status() client.SubResourceWriter {
	return &countingSubResourceWriter{SubResourceWriter: c.Client.Status(), count: c.statusUpdates}
}

type countingSubResourceWriter struct {
	client.SubResourceWriter
	count *int
}

func (w *countingSubResourceWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	*w.count++
	return w.SubResourceWriter.Update(ctx, obj, opts...)
}

// healthyFakeExecutor returns a FakeExecutor whose RunFunc answers the probes
// issued during provisioning with a healthy VPS.
func healthyFakeExecutor() *sshexec.FakeExecutor {
	fake := sshexec.NewFakeExecutor()
	fake.RunFunc = func(ctx context.Context, cmd string) (string, error) {
		switch {
		case strings.Contains(cmd, "which apt"):
			return "/usr/bin/apt", nil
		case strings.Contains(cmd, "uname -m"):
			return "x86_64", nil
		case strings.Contains(cmd, "tunnelctl status"):
			return `{"interface":"wg-relay","exists":true,"up":true,"ready":true,"detail":"healthy","peers":[]}`, nil
		case strings.Contains(cmd, "systemctl is-active"):
			return activeServiceOutput, nil
		case strings.Contains(cmd, "state.json"):
			return "{}", nil
		case strings.Contains(cmd, "vps.pub"):
			return "fakevpspublickey", nil
		case strings.Contains(cmd, "vps.priv"):
			return "fakevpsprivatekey", nil
		default:
			return "", nil
		}
	}
	return fake
}

// envoyFailedFakeExecutor returns a FakeExecutor that lets enrollment proceed
// but reports the envoy unit as failed, simulating a crash-looping proxy (for
// example a bad config). The reconciler must surface this as a provisioning
// failure instead of certifying a dead proxy.
func envoyFailedFakeExecutor() *sshexec.FakeExecutor {
	fake := sshexec.NewFakeExecutor()
	fake.RunFunc = func(ctx context.Context, cmd string) (string, error) {
		switch {
		case strings.Contains(cmd, "which apt"):
			return "/usr/bin/apt", nil
		case strings.Contains(cmd, "uname -m"):
			return "x86_64", nil
		case strings.TrimSpace(cmd) == "systemctl is-active envoy":
			return "failed\n", nil
		case strings.Contains(cmd, "tunnelctl status"):
			return `{"interface":"wg-relay","exists":true,"up":true,"ready":true,"detail":"healthy","peers":[]}`, nil
		case strings.Contains(cmd, "systemctl is-active"):
			return activeServiceOutput, nil
		case strings.Contains(cmd, "state.json"):
			return "{}", nil
		case strings.Contains(cmd, "vps.pub"):
			return "fakevpspublickey", nil
		case strings.Contains(cmd, "vps.priv"):
			return "fakevpsprivatekey", nil
		default:
			return "", nil
		}
	}
	return fake
}

var _ = Describe("EdgeNode Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default",
		}
		edgenode := &tunnelv1alpha1.EdgeNode{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind EdgeNode")
			err := k8sClient.Get(ctx, typeNamespacedName, edgenode)
			if err != nil && errors.IsNotFound(err) {
				secret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "fake-secret",
						Namespace: "default",
					},
					Data: map[string][]byte{
						"password": []byte("test"),
					},
				}
				if err := k8sClient.Create(ctx, secret); err != nil && !errors.IsAlreadyExists(err) {
					Expect(err).NotTo(HaveOccurred())
				}

				ns := &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "tunnel",
					},
				}
				err := k8sClient.Create(ctx, ns)
				if err != nil && !errors.IsAlreadyExists(err) {
					Expect(err).NotTo(HaveOccurred())
				}

				resource := &tunnelv1alpha1.EdgeNode{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: "default",
					},
					Spec: tunnelv1alpha1.EdgeNodeSpec{
						Address: "198.51.100.10",
						SSH: tunnelv1alpha1.SSHSpec{
							SecretRef: tunnelv1alpha1.SecretReference{
								Name: "fake-secret",
							},
						},
						Uplink: tunnelv1alpha1.UplinkSpec{
							Namespace: "tunnel",
							Replicas:  1,
						},
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			resource := &tunnelv1alpha1.EdgeNode{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			if errors.IsNotFound(err) {
				return
			}
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance EdgeNode")
			if resource.Annotations == nil {
				resource.Annotations = map[string]string{}
			}
			resource.Annotations["tunnel.achetronic.com/skip-deprovision"] = annotationTrue
			Expect(k8sClient.Update(ctx, resource)).To(Succeed())
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())

			cleanupReconciler := &EdgeNodeReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			_, _ = cleanupReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})

			cleanup := &tunnelv1alpha1.EdgeNode{}
			if err := k8sClient.Get(ctx, typeNamespacedName, cleanup); err == nil {
				cleanup.Finalizers = nil
				_ = k8sClient.Update(ctx, cleanup)
				_ = k8sClient.Delete(ctx, cleanup)
			}
		})

		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource with a healthy fake executor")
			controllerReconciler := &EdgeNodeReconciler{
				Client:       k8sClient,
				Scheme:       k8sClient.Scheme(),
				TunnelctlDir: tunnelctlTestDir,
				ExecutorFactory: func(ctx context.Context, node *tunnelv1alpha1.EdgeNode, secret *corev1.Secret) (sshexec.Executor, error) {
					return healthyFakeExecutor(), nil
				},
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			updated := &tunnelv1alpha1.EdgeNode{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updated)).To(Succeed())
			Expect(updated.Status.ObservedGeneration).To(Equal(updated.Generation))
			cond := meta.FindStatusCondition(updated.Status.Conditions, "Ready")
			Expect(cond).NotTo(BeNil())
		})

		It("should mark Ready False with SSHConnectionFailed when the SSH secret is absent", func() {
			By("pointing the EdgeNode at a non-existent SSH secret")
			node := &tunnelv1alpha1.EdgeNode{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, node)).To(Succeed())
			node.Spec.SSH.SecretRef.Name = "does-not-exist"
			Expect(k8sClient.Update(ctx, node)).To(Succeed())

			controllerReconciler := &EdgeNodeReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).To(HaveOccurred())

			updated := &tunnelv1alpha1.EdgeNode{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updated)).To(Succeed())
			cond := meta.FindStatusCondition(updated.Status.Conditions, "Ready")
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionFalse))
			Expect(cond.Reason).To(Equal("SSHConnectionFailed"))
		})

		It("should mark Ready False with ProvisioningFailed when envoy does not come up", func() {
			By("Reconciling with a fake executor whose envoy unit stays failed")
			controllerReconciler := &EdgeNodeReconciler{
				Client:       k8sClient,
				Scheme:       k8sClient.Scheme(),
				TunnelctlDir: tunnelctlTestDir,
				ExecutorFactory: func(ctx context.Context, node *tunnelv1alpha1.EdgeNode, secret *corev1.Secret) (sshexec.Executor, error) {
					return envoyFailedFakeExecutor(), nil
				},
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).To(HaveOccurred())

			updated := &tunnelv1alpha1.EdgeNode{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updated)).To(Succeed())
			cond := meta.FindStatusCondition(updated.Status.Conditions, "Ready")
			Expect(cond).NotTo(BeNil())
			Expect(cond.Status).To(Equal(metav1.ConditionFalse))
			Expect(cond.Reason).To(Equal("ProvisioningFailed"))
		})

		It("should tear down via the fake executor on deletion with a finalizer", func() {
			By("first reconciling so the finalizer is added")
			controllerReconciler := &EdgeNodeReconciler{
				Client:       k8sClient,
				Scheme:       k8sClient.Scheme(),
				TunnelctlDir: tunnelctlTestDir,
				ExecutorFactory: func(ctx context.Context, node *tunnelv1alpha1.EdgeNode, secret *corev1.Secret) (sshexec.Executor, error) {
					return healthyFakeExecutor(), nil
				},
			}
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred())

			By("deleting the EdgeNode and reconciling the teardown")
			node := &tunnelv1alpha1.EdgeNode{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, node)).To(Succeed())
			Expect(k8sClient.Delete(ctx, node)).To(Succeed())

			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred())

			gone := &tunnelv1alpha1.EdgeNode{}
			err = k8sClient.Get(ctx, typeNamespacedName, gone)
			Expect(errors.IsNotFound(err)).To(BeTrue())
		})

		It("should consume the restart-envoy annotation on reconcile", func() {
			By("annotating the EdgeNode to request an Envoy restart")
			node := &tunnelv1alpha1.EdgeNode{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, node)).To(Succeed())
			if node.Annotations == nil {
				node.Annotations = map[string]string{}
			}
			node.Annotations["tunnel.achetronic.com/restart-envoy"] = annotationTrue
			Expect(k8sClient.Update(ctx, node)).To(Succeed())

			controllerReconciler := &EdgeNodeReconciler{
				Client:       k8sClient,
				Scheme:       k8sClient.Scheme(),
				TunnelctlDir: tunnelctlTestDir,
				ExecutorFactory: func(ctx context.Context, node *tunnelv1alpha1.EdgeNode, secret *corev1.Secret) (sshexec.Executor, error) {
					return healthyFakeExecutor(), nil
				},
			}
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred())

			By("verifying the annotation was consumed (removed) by the operator")
			updated := &tunnelv1alpha1.EdgeNode{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updated)).To(Succeed())
			_, present := updated.Annotations["tunnel.achetronic.com/restart-envoy"]
			Expect(present).To(BeFalse())
		})

		It("should skip the status write on a second reconcile when status did not change", func() {
			By("Reconciling the resource for the first time")
			statusUpdates := 0
			controllerReconciler := &EdgeNodeReconciler{
				Client:       &statusWriteCountingClient{Client: k8sClient, statusUpdates: &statusUpdates},
				Scheme:       k8sClient.Scheme(),
				TunnelctlDir: tunnelctlTestDir,
				ExecutorFactory: func(ctx context.Context, node *tunnelv1alpha1.EdgeNode, secret *corev1.Secret) (sshexec.Executor, error) {
					return healthyFakeExecutor(), nil
				},
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Asserting the first reconcile persisted the status")
			Expect(statusUpdates).To(BeNumerically(">=", 1))

			By("Reconciling a second time with no changes and asserting no status write happens")
			statusUpdates = 0
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(statusUpdates).To(BeZero())
		})

		It("asserts the predicate composition behaves as intended", func() {
			By("setting up EdgeNodes for the update event")
			oldNode := &tunnelv1alpha1.EdgeNode{
				ObjectMeta: metav1.ObjectMeta{
					Generation: 1,
					Annotations: map[string]string{
						"foo": "bar",
					},
					Labels: map[string]string{
						"app": "tunnel",
					},
				},
			}

			By("1. Testing status-only update event (same generation, same annotations, same labels)")
			newNodeStatusOnly := oldNode.DeepCopy()
			newNodeStatusOnly.Status.ObservedGeneration = 1
			// Status updates do not bump generation, annotations, or labels
			updateStatusOnly := event.UpdateEvent{
				ObjectOld: oldNode,
				ObjectNew: newNodeStatusOnly,
			}
			Expect(edgeNodeEventPredicate.Update(updateStatusOnly)).To(BeFalse())

			By("2. Testing generation bump (spec change)")
			newNodeGenBump := oldNode.DeepCopy()
			newNodeGenBump.Generation = 2
			updateGenBump := event.UpdateEvent{
				ObjectOld: oldNode,
				ObjectNew: newNodeGenBump,
			}
			Expect(edgeNodeEventPredicate.Update(updateGenBump)).To(BeTrue())

			By("3. Testing annotation change")
			newNodeAnnotationChange := oldNode.DeepCopy()
			newNodeAnnotationChange.Annotations["foo"] = "qux"
			updateAnnotationChange := event.UpdateEvent{
				ObjectOld: oldNode,
				ObjectNew: newNodeAnnotationChange,
			}
			Expect(edgeNodeEventPredicate.Update(updateAnnotationChange)).To(BeTrue())

			By("4. Testing label change")
			// Labels carry no plan input: PortBinding changes reach the
			// reconciler through the direct PortBinding watch, so a label
			// mutation must not re-enqueue the EdgeNode.
			newNodeLabelChange := oldNode.DeepCopy()
			newNodeLabelChange.Labels["app"] = "different"
			updateLabelChange := event.UpdateEvent{
				ObjectOld: oldNode,
				ObjectNew: newNodeLabelChange,
			}
			Expect(edgeNodeEventPredicate.Update(updateLabelChange)).To(BeFalse())
		})
	})
})

var _ = Describe("ensureUplinkKeys", func() {
	ctx := context.Background()
	const ns = "tunnel"

	newReconciler := func() *EdgeNodeReconciler {
		return &EdgeNodeReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
	}
	newNode := func(name string) *tunnelv1alpha1.EdgeNode {
		return &tunnelv1alpha1.EdgeNode{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: tunnelv1alpha1.EdgeNodeSpec{
				Uplink: tunnelv1alpha1.UplinkSpec{Namespace: ns},
			},
		}
	}

	BeforeEach(func() {
		nsObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}
		if err := k8sClient.Create(ctx, nsObj); err != nil && !errors.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}
	})

	It("adds keys on scale up and prunes them on scale down without rotating existing ones", func() {
		r := newReconciler()
		node := newNode("scale-test")

		By("creating the secret with a single replica")
		sec, err := r.ensureUplinkKeys(ctx, node, 1, ns)
		Expect(err).NotTo(HaveOccurred())
		Expect(sec.Data).To(HaveKey("priv-0"))
		Expect(sec.Data).NotTo(HaveKey("priv-1"))
		original := string(sec.Data["priv-0"])

		By("scaling up to three replicas")
		sec, err = r.ensureUplinkKeys(ctx, node, 3, ns)
		Expect(err).NotTo(HaveOccurred())
		Expect(sec.Data).To(HaveKey("priv-0"))
		Expect(sec.Data).To(HaveKey("priv-1"))
		Expect(sec.Data).To(HaveKey("priv-2"))
		Expect(string(sec.Data["priv-0"])).To(Equal(original), "an existing ordinal must keep its key")

		By("resolving public keys for every replica (the bug surfaced here)")
		_, err = r.resolveUplinkPublicKeys(sec, 3)
		Expect(err).NotTo(HaveOccurred())

		By("scaling back down to two replicas")
		sec, err = r.ensureUplinkKeys(ctx, node, 2, ns)
		Expect(err).NotTo(HaveOccurred())
		Expect(sec.Data).To(HaveKey("priv-0"))
		Expect(sec.Data).To(HaveKey("priv-1"))
		Expect(sec.Data).NotTo(HaveKey("priv-2"))
		Expect(string(sec.Data["priv-0"])).To(Equal(original))
	})
})

var _ = Describe("collectBindings namespace isolation", func() {
	ctx := context.Background()

	newReconciler := func() *EdgeNodeReconciler {
		return &EdgeNodeReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
	}
	node := func(name, namespace string) *tunnelv1alpha1.EdgeNode {
		return &tunnelv1alpha1.EdgeNode{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}
	}

	It("does not aggregate PortBindings of an EdgeNode that only shares the name in another namespace", func() {
		r := newReconciler()

		By("creating two namespaces")
		for _, n := range []string{"cb-nsa", "cb-nsb"} {
			nsObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}}
			if err := k8sClient.Create(ctx, nsObj); err != nil && !errors.IsAlreadyExists(err) {
				Expect(err).NotTo(HaveOccurred())
			}
		}

		By("creating a PortBinding in cb-nsa targeting EdgeNode \"shared\" (ref namespace defaults to the PB's)")
		pb := &tunnelv1alpha1.PortBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "pb-ns", Namespace: "cb-nsa"},
			Spec: tunnelv1alpha1.PortBindingSpec{
				EdgeNodeRef: tunnelv1alpha1.ObjectReference{Name: "shared"},
				Bindings: []tunnelv1alpha1.PortBindingDefinition{
					{
						Name:       "b1",
						Protocol:   "TCP",
						ListenPort: 8443,
						Target:     tunnelv1alpha1.BindingTarget{Address: "10.0.0.5", Port: 443},
					},
				},
			},
		}
		Expect(k8sClient.Create(ctx, pb)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, pb) })

		By("the EdgeNode in cb-nsa picks up the binding")
		got, err := r.collectBindings(ctx, node("shared", "cb-nsa"))
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(HaveLen(1))

		By("the same-named EdgeNode in cb-nsb does NOT pick up the cross-namespace binding")
		got, err = r.collectBindings(ctx, node("shared", "cb-nsb"))
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(BeEmpty())
	})
})

var _ = Describe("EdgeNode uplink namespace ownership collision check", func() {
	ctx := context.Background()

	const sharedUplinkNamespace = "tunnel"

	BeforeEach(func() {
		// Ensure namespaces exist
		for _, n := range []string{"tenant-a", "tenant-b", sharedUplinkNamespace} {
			nsObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}}
			if err := k8sClient.Create(ctx, nsObj); err != nil && !errors.IsAlreadyExists(err) {
				Expect(err).NotTo(HaveOccurred())
			}
		}
	})

	It("fails reconciliation with UplinkNamespaceCollision and does not overwrite existing resources if owner namespace mismatch", func() {
		nodeName := "col-node"

		privKey, _ := wgtypes.GeneratePrivateKey()

		// Pre-create the keys Secret in the shared namespace "tunnel", owned by "tenant-a"
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      nodeName + "-uplink-keys",
				Namespace: sharedUplinkNamespace,
				Labels: map[string]string{
					"tunnel.achetronic.com/owner-namespace": "tenant-a",
				},
			},
			StringData: map[string]string{
				"priv-0": privKey.String(),
			},
		}
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, secret) })

		// Create EdgeNode in namespace "tenant-b" targeting the same "tunnel" uplink namespace
		edgeNodeTenantB := &tunnelv1alpha1.EdgeNode{
			ObjectMeta: metav1.ObjectMeta{
				Name:      nodeName,
				Namespace: "tenant-b",
			},
			Spec: tunnelv1alpha1.EdgeNodeSpec{
				Address: "198.51.100.11",
				SSH: tunnelv1alpha1.SSHSpec{
					SecretRef: tunnelv1alpha1.SecretReference{
						Name: "fake-secret", // Not actually used since preflight fails before SSH dialing
					},
				},
				Uplink: tunnelv1alpha1.UplinkSpec{
					Namespace: sharedUplinkNamespace,
					Replicas:  1,
				},
			},
		}
		Expect(k8sClient.Create(ctx, edgeNodeTenantB)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, edgeNodeTenantB) })

		// Reconcile tenant-b EdgeNode
		r := &EdgeNodeReconciler{
			Client:       k8sClient,
			Scheme:       k8sClient.Scheme(),
			TunnelctlDir: tunnelctlTestDir,
		}

		_, err := r.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      nodeName,
				Namespace: "tenant-b",
			},
		})
		Expect(err).NotTo(HaveOccurred())

		// Fetch the reconciled EdgeNode and assert condition
		reconciledB := &tunnelv1alpha1.EdgeNode{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nodeName, Namespace: "tenant-b"}, reconciledB)).To(Succeed())

		cond := meta.FindStatusCondition(reconciledB.Status.Conditions, "Ready")
		Expect(cond).NotTo(BeNil())
		Expect(cond.Status).To(Equal(metav1.ConditionFalse))
		Expect(cond.Reason).To(Equal("UplinkNamespaceCollision"))
		Expect(cond.Message).To(ContainSubstring("tenant-a"))

		// Check that the secret was NOT modified (contains original data)
		fetchedSecret := &corev1.Secret{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nodeName + "-uplink-keys", Namespace: sharedUplinkNamespace}, fetchedSecret)).To(Succeed())
		Expect(string(fetchedSecret.Data["priv-0"])).To(Equal(privKey.String()))
	})

	It("succeeds reconciliation if the owner namespace matches", func() {
		nodeName := "col-node-match"

		privKey, _ := wgtypes.GeneratePrivateKey()

		// Pre-create the keys Secret in the shared namespace "tunnel", owned by "tenant-a"
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      nodeName + "-uplink-keys",
				Namespace: sharedUplinkNamespace,
				Labels: map[string]string{
					"tunnel.achetronic.com/owner-namespace": "tenant-a",
				},
			},
			StringData: map[string]string{
				"priv-0": privKey.String(),
			},
		}
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, secret) })

		// Create SSH secret for "tenant-a"
		sshSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "fake-secret",
				Namespace: "tenant-a",
			},
			Data: map[string][]byte{
				"password": []byte("test"),
			},
		}
		Expect(k8sClient.Create(ctx, sshSecret)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, sshSecret) })

		// Create EdgeNode in namespace "tenant-a" targeting "tunnel" uplink namespace
		edgeNodeTenantA := &tunnelv1alpha1.EdgeNode{
			ObjectMeta: metav1.ObjectMeta{
				Name:      nodeName,
				Namespace: "tenant-a",
			},
			Spec: tunnelv1alpha1.EdgeNodeSpec{
				Address: "198.51.100.12",
				SSH: tunnelv1alpha1.SSHSpec{
					SecretRef: tunnelv1alpha1.SecretReference{
						Name: "fake-secret",
					},
				},
				Uplink: tunnelv1alpha1.UplinkSpec{
					Namespace: sharedUplinkNamespace,
					Replicas:  1,
				},
			},
		}
		Expect(k8sClient.Create(ctx, edgeNodeTenantA)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, edgeNodeTenantA) })

		// Reconcile tenant-a EdgeNode (with fake executor to let provision proceed)
		r := &EdgeNodeReconciler{
			Client:       k8sClient,
			Scheme:       k8sClient.Scheme(),
			TunnelctlDir: tunnelctlTestDir,
			ExecutorFactory: func(ctx context.Context, node *tunnelv1alpha1.EdgeNode, secret *corev1.Secret) (sshexec.Executor, error) {
				return healthyFakeExecutor(), nil
			},
		}

		_, err := r.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      nodeName,
				Namespace: "tenant-a",
			},
		})
		Expect(err).NotTo(HaveOccurred())

		// Fetch the reconciled EdgeNode and assert condition is Ready (or at least not UplinkNamespaceCollision)
		reconciledA := &tunnelv1alpha1.EdgeNode{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nodeName, Namespace: "tenant-a"}, reconciledA)).To(Succeed())

		cond := meta.FindStatusCondition(reconciledA.Status.Conditions, "Ready")
		Expect(cond).NotTo(BeNil())
		Expect(cond.Reason).NotTo(Equal("UplinkNamespaceCollision"))
	})

	It("does not delete uplink resources owned by another EdgeNode during teardown", func() {
		nodeName := "col-del-node"

		// A keys Secret in the shared namespace owned by an EdgeNode in tenant-a.
		foreignSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      nodeName + "-uplink-keys",
				Namespace: sharedUplinkNamespace,
				Labels: map[string]string{
					"tunnel.achetronic.com/owner-namespace": "tenant-a",
				},
			},
			StringData: map[string]string{"priv-0": "keepme"},
		}
		Expect(k8sClient.Create(ctx, foreignSecret)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, foreignSecret) })

		// A same-named EdgeNode in tenant-b tearing down must not delete tenant-a's Secret.
		nodeB := &tunnelv1alpha1.EdgeNode{
			ObjectMeta: metav1.ObjectMeta{Name: nodeName, Namespace: "tenant-b"},
			Spec: tunnelv1alpha1.EdgeNodeSpec{
				Uplink: tunnelv1alpha1.UplinkSpec{Namespace: sharedUplinkNamespace, Replicas: 1},
			},
		}
		r := &EdgeNodeReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		Expect(r.deleteUplinkResources(ctx, nodeB)).To(Succeed())

		// The foreign Secret must still exist.
		kept := &corev1.Secret{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: nodeName + "-uplink-keys", Namespace: sharedUplinkNamespace}, kept)).To(Succeed())
		Expect(kept.Labels["tunnel.achetronic.com/owner-namespace"]).To(Equal("tenant-a"))
	})
})
