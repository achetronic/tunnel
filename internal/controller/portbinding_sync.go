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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"

	"github.com/achetronic/tunnel/api/v1alpha1"
)

// portBindingFinalizer guards a PortBinding so its deletion can nudge the
// referenced EdgeNode to re-render (dropping the removed listeners) before the
// object actually disappears.
const portBindingFinalizer = "tunnel.achetronic.com/portbinding-finalizer"

// portBindingTriggerLabel is bumped on the referenced EdgeNode to trigger its
// reconciliation whenever a PortBinding that targets it changes.
const portBindingTriggerLabel = "tunnel.achetronic.com/last-portbinding-trigger"

// triggerEdgeNode finds the EdgeNode referenced by the PortBinding and bumps a
// trigger label so the EdgeNodeReconciler re-runs and rebuilds the aggregate
// plan. The read-modify-write is wrapped in RetryOnConflict to survive
// concurrent updates. If the referenced EdgeNode is not found the error is
// ignored, allowing the operator to progress when resources are created or
// deleted out of order.
func (r *PortBindingReconciler) triggerEdgeNode(ctx context.Context, pb *v1alpha1.PortBinding) error {
	nodeName := pb.Spec.EdgeNodeRef.Name
	if nodeName == "" {
		return nil
	}
	nodeNamespace := pb.Spec.EdgeNodeRef.Namespace
	if nodeNamespace == "" {
		nodeNamespace = pb.Namespace
	}

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var node v1alpha1.EdgeNode
		if err := r.Get(ctx, types.NamespacedName{Name: nodeName, Namespace: nodeNamespace}, &node); err != nil {
			if apierrors.IsNotFound(err) {
				return nil
			}
			return err
		}

		if node.Labels == nil {
			node.Labels = make(map[string]string)
		}
		node.Labels[portBindingTriggerLabel] = pb.Name
		return r.Update(ctx, &node)
	})
}
