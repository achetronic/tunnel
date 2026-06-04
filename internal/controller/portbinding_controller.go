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

	"k8s.io/apimachinery/pkg/api/meta"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

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
	meta.SetStatusCondition(&pb.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "Synced",
		Message:            "PortBinding triggered EdgeNode",
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

// SetupWithManager registers the PortBindingReconciler with the controller manager.
func (r *PortBindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.PortBinding{}).
		Complete(r)
}
