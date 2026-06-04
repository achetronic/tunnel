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

	It("should not error when the referenced EdgeNode is not found", func() {
		pb := &tunnelv1alpha1.PortBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "pb-missing-node", Namespace: "default"},
			Spec: tunnelv1alpha1.PortBindingSpec{
				EdgeNodeRef: tunnelv1alpha1.ObjectReference{Name: "absent-node"},
			},
		}
		Expect(newReconciler().triggerEdgeNode(ctx, pb)).To(Succeed())
	})

	It("should add a finalizer and trigger the referenced EdgeNode on create", func() {
		By("creating an EdgeNode to be triggered")
		node := &tunnelv1alpha1.EdgeNode{
			ObjectMeta: metav1.ObjectMeta{Name: "trigger-node", Namespace: "default"},
			Spec: tunnelv1alpha1.EdgeNodeSpec{
				Address: "envtest-fake",
				SSH: tunnelv1alpha1.SSHSpec{
					SecretRef: tunnelv1alpha1.SecretReference{Name: "fake-secret"},
				},
			},
		}
		Expect(k8sClient.Create(ctx, node)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, node) })

		By("creating a PortBinding referencing the node")
		pb := &tunnelv1alpha1.PortBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "pb-trigger", Namespace: "default"},
			Spec: tunnelv1alpha1.PortBindingSpec{
				EdgeNodeRef: tunnelv1alpha1.ObjectReference{Name: "trigger-node"},
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

		pbKey := types.NamespacedName{Name: "pb-trigger", Namespace: "default"}

		By("reconciling the PortBinding")
		_, err := newReconciler().Reconcile(ctx, reconcile.Request{NamespacedName: pbKey})
		Expect(err).NotTo(HaveOccurred())

		By("verifying the finalizer was added")
		updatedPB := &tunnelv1alpha1.PortBinding{}
		Expect(k8sClient.Get(ctx, pbKey, updatedPB)).To(Succeed())
		Expect(controllerutil.ContainsFinalizer(updatedPB, portBindingFinalizer)).To(BeTrue())

		By("verifying the trigger label was applied on the node")
		updatedNode := &tunnelv1alpha1.EdgeNode{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "trigger-node", Namespace: "default"}, updatedNode)).To(Succeed())
		Expect(updatedNode.Labels).To(HaveKeyWithValue(portBindingTriggerLabel, "pb-trigger"))
	})

	It("should trigger the EdgeNode and drop the finalizer on deletion", func() {
		By("creating an EdgeNode")
		node := &tunnelv1alpha1.EdgeNode{
			ObjectMeta: metav1.ObjectMeta{Name: "del-node", Namespace: "default"},
			Spec: tunnelv1alpha1.EdgeNodeSpec{
				Address: "envtest-fake",
				SSH: tunnelv1alpha1.SSHSpec{
					SecretRef: tunnelv1alpha1.SecretReference{Name: "fake-secret"},
				},
			},
		}
		Expect(k8sClient.Create(ctx, node)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, node) })

		By("creating and reconciling a PortBinding so it gets the finalizer")
		pb := &tunnelv1alpha1.PortBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "pb-del", Namespace: "default"},
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
		_, err := newReconciler().Reconcile(ctx, reconcile.Request{NamespacedName: pbKey})
		Expect(err).NotTo(HaveOccurred())

		By("clearing the trigger label to observe it being re-applied on delete")
		current := &tunnelv1alpha1.EdgeNode{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "del-node", Namespace: "default"}, current)).To(Succeed())
		delete(current.Labels, portBindingTriggerLabel)
		Expect(k8sClient.Update(ctx, current)).To(Succeed())

		By("deleting the PortBinding (finalizer keeps it around)")
		Expect(k8sClient.Delete(ctx, pb)).To(Succeed())

		By("reconciling the deletion")
		_, err = newReconciler().Reconcile(ctx, reconcile.Request{NamespacedName: pbKey})
		Expect(err).NotTo(HaveOccurred())

		By("verifying the EdgeNode was triggered by the deletion")
		updatedNode := &tunnelv1alpha1.EdgeNode{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "del-node", Namespace: "default"}, updatedNode)).To(Succeed())
		Expect(updatedNode.Labels).To(HaveKeyWithValue(portBindingTriggerLabel, "pb-del"))

		By("verifying the PortBinding is fully gone after the finalizer is removed")
		gone := &tunnelv1alpha1.PortBinding{}
		err = k8sClient.Get(ctx, pbKey, gone)
		Expect(errors.IsNotFound(err)).To(BeTrue())
	})
})
