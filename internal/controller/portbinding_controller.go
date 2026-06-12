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

// Package controller contains the controllers for the Tunnel operator.
package controller

import (
	"context"
	"slices"

	"k8s.io/apimachinery/pkg/api/meta"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/achetronic/tunnel/api/v1alpha1"
)

// PortBindingReconciler reconciles a PortBinding object. It is fully
// independent from the EdgeNodeReconciler: the two only meet through the
// PortBinding's EdgeNodeRef. This reconciler never touches SSH, the uplink, or
// resolves targets; its sole job is to nudge the referenced EdgeNode so the
// EdgeNodeReconciler rebuilds the aggregate plan.
type PortBindingReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=tunnel.achetronic.com,resources=portbindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=tunnel.achetronic.com,resources=portbindings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=tunnel.achetronic.com,resources=portbindings/finalizers,verbs=update
// +kubebuilder:rbac:groups=tunnel.achetronic.com,resources=edgenodes,verbs=get;list;watch;update;patch

// Reconcile reconciles a PortBinding. On create/update it ensures a finalizer is
// present, triggers the referenced EdgeNode and refreshes the PortBinding
// status. On deletion it triggers the EdgeNode (so its listeners are dropped)
// and then removes the finalizer.
func (r *PortBindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var pb v1alpha1.PortBinding
	if err := r.Get(ctx, req.NamespacedName, &pb); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !pb.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&pb, portBindingFinalizer) {
			if err := r.triggerEdgeNode(ctx, &pb); err != nil {
				return ctrl.Result{}, err
			}
			controllerutil.RemoveFinalizer(&pb, portBindingFinalizer)
			if err := r.Update(ctx, &pb); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	if !controllerutil.ContainsFinalizer(&pb, portBindingFinalizer) {
		controllerutil.AddFinalizer(&pb, portBindingFinalizer)
		if err := r.Update(ctx, &pb); err != nil {
			return ctrl.Result{}, err
		}
	}

	if err := r.triggerEdgeNode(ctx, &pb); err != nil {
		return ctrl.Result{}, err
	}

	pb.Status.ObservedGeneration = pb.Generation
	// Programmed records that this reconciler did its part: the referenced
	// EdgeNode was nudged and will rebuild its aggregate plan. It says
	// nothing about the port being live on the edge; that is Ready's job.
	meta.SetStatusCondition(&pb.Status.Conditions, metav1.Condition{
		Type:               "Programmed",
		Status:             metav1.ConditionTrue,
		Reason:             "Synced",
		Message:            "PortBinding triggered EdgeNode",
		ObservedGeneration: pb.Generation,
	})
	// Ready is honest: True only once the EdgeNode's status reports this
	// binding inside the last successfully applied plan. GitOps tooling
	// (Argo/Flux) reads Ready as "operational", so it must track the edge,
	// not our trigger.
	ready, reason, msg := r.evaluateApplied(ctx, &pb)
	meta.SetStatusCondition(&pb.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             ready,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: pb.Generation,
	})
	if err := r.Status().Update(ctx, &pb); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// evaluateApplied checks whether this PortBinding is part of the plan the
// EdgeNodeReconciler last applied successfully, by reading the EdgeNode's
// status.appliedBindings. The two reconcilers stay decoupled: they only meet
// through the API server (this read here, and the EdgeNode watch in
// SetupWithManager that re-enqueues bindings when that status changes).
func (r *PortBindingReconciler) evaluateApplied(ctx context.Context, pb *v1alpha1.PortBinding) (metav1.ConditionStatus, string, string) {
	nodeNS := pb.Spec.EdgeNodeRef.Namespace
	if nodeNS == "" {
		nodeNS = pb.Namespace
	}
	var node v1alpha1.EdgeNode
	if err := r.Get(ctx, types.NamespacedName{Namespace: nodeNS, Name: pb.Spec.EdgeNodeRef.Name}, &node); err != nil {
		if apierrors.IsNotFound(err) {
			return metav1.ConditionFalse, "EdgeNodeNotFound", "Referenced EdgeNode does not exist"
		}
		return metav1.ConditionUnknown, "EdgeNodeUnreadable", "Failed to read the referenced EdgeNode"
	}
	if slices.Contains(node.Status.AppliedBindings, pb.Namespace+"/"+pb.Name) {
		return metav1.ConditionTrue, "Applied", "Binding is part of the plan applied on the edge"
	}
	return metav1.ConditionFalse, "NotYetApplied", "Binding is not yet part of the applied plan"
}

// SetupWithManager registers the PortBindingReconciler with the controller
// manager. Besides its own objects it watches EdgeNodes: when an EdgeNode's
// status changes (a new plan got applied), every PortBinding referencing it is
// re-enqueued so its Ready condition tracks the applied plan. Note this watch
// deliberately reacts to status updates; the EdgeNode controller's own For()
// filters them out to avoid self-loops, but here they are exactly the signal.
func (r *PortBindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.PortBinding{}).
		Watches(
			&v1alpha1.EdgeNode{},
			handler.EnqueueRequestsFromMapFunc(r.bindingsForEdgeNode),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		).
		Complete(r)
}

// bindingsForEdgeNode maps an EdgeNode event to reconcile requests for every
// PortBinding that references it.
func (r *PortBindingReconciler) bindingsForEdgeNode(ctx context.Context, obj client.Object) []ctrl.Request {
	node, ok := obj.(*v1alpha1.EdgeNode)
	if !ok {
		return nil
	}
	var pbList v1alpha1.PortBindingList
	if err := r.List(ctx, &pbList); err != nil {
		return nil
	}
	var reqs []ctrl.Request
	for _, pb := range pbList.Items {
		if pb.Spec.EdgeNodeRef.Name != node.Name {
			continue
		}
		refNS := pb.Spec.EdgeNodeRef.Namespace
		if refNS == "" {
			refNS = pb.Namespace
		}
		if refNS != node.Namespace {
			continue
		}
		reqs = append(reqs, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: pb.Namespace, Name: pb.Name}})
	}
	return reqs
}
