// SPDX-FileCopyrightText: 2026 Alby Hernández (Achetronic)
// SPDX-License-Identifier: Apache-2.0

// Package controller contains the controllers for the Tunnel operator.
package controller

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	controllerruntime "sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/achetronic/tunnel/api/v1alpha1"
	"github.com/achetronic/tunnel/internal/provision"
	"github.com/achetronic/tunnel/internal/sshexec"
)

// edgeNodeEventPredicate defines the predicate rules for filtering EdgeNode reconcile events.
// Status-only updates must not re-enqueue to prevent reconciliation hot loops.
// Spec changes (generation) and annotations must trigger a reconcile;
// annotations carry the one-shot restart-envoy trigger.
var edgeNodeEventPredicate = predicate.Or(
	predicate.GenerationChangedPredicate{},
	predicate.AnnotationChangedPredicate{},
)

// EdgeNodeReconciler reconciles an EdgeNode object.
type EdgeNodeReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
	// ExecutorFactory builds the SSH executor for a node. When nil the
	// reconciler dials the real host via sshexec.NewSSHExecutor. Tests inject a
	// factory returning a FakeExecutor so production code never references the
	// fake.
	ExecutorFactory func(ctx context.Context, node *v1alpha1.EdgeNode, secret *corev1.Secret) (sshexec.Executor, error)
	// RequeueInterval is how often a healthy EdgeNode is re-reconciled for drift
	// detection and status refresh. Zero falls back to defaultRequeueInterval.
	RequeueInterval time.Duration
	// EnvoyVersion is the Envoy release installed on every VPS, set from the
	// manager's --envoy-version flag. Empty falls back to DefaultEnvoyVersion.
	EnvoyVersion string
	// TunnelctlDir is the local directory holding the static tunnelctl binaries
	// (tunnelctl-linux-<arch>) the operator pushes to every VPS over SSH, set from
	// the manager's --tunnelctl-dir flag. Empty falls back to DefaultTunnelctlDir.
	TunnelctlDir string
	// UplinkImage is the container image for the in-cluster uplink StatefulSet,
	// composed by the manager from --image-repo/--image-tag. Empty falls back to
	// DefaultUplinkImage.
	UplinkImage string
	// MaxConcurrentReconciles bounds how many EdgeNodes reconcile in parallel.
	// Each reconcile speaks SSH to its own VPS, so a single unreachable or
	// slow host would otherwise occupy the only worker and stall every other
	// node's reconcile (cert rotation, config rollout). Distinct EdgeNodes own
	// disjoint VPSs and uplink namespaces, so parallel reconciles do not race.
	// Zero falls back to defaultMaxConcurrentReconciles.
	MaxConcurrentReconciles int
}

// +kubebuilder:rbac:groups=tunnel.achetronic.com,resources=edgenodes,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=tunnel.achetronic.com,resources=edgenodes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=tunnel.achetronic.com,resources=edgenodes/finalizers,verbs=update
// +kubebuilder:rbac:groups=tunnel.achetronic.com,resources=portbindings,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;create;update;patch;delete

// Reconcile is the main reconcile loop for the EdgeNode resource. It handles
// fetching, finalizer setup/teardown and status updates, delegating the actual
// SSH provisioning, IPAM and resource configuration to handleReconciliation.
func (r *EdgeNodeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var node v1alpha1.EdgeNode
	if err := r.Get(ctx, req.NamespacedName, &node); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	prevStatus := node.Status.DeepCopy()

	skipDeprovision := node.Annotations[skipDeprovisionAnnotation] == annotationTrue

	if !node.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&node, edgeNodeFinalizer) {
			if !skipDeprovision {
				exec, err := r.getSSHExecutor(ctx, &node)
				if err != nil {
					logger.Error(err, "failed to connect for teardown, retry or set skip-deprovision")
					if r.Recorder != nil {
						r.Recorder.Event(&node, corev1.EventTypeWarning, "SSHConnectionFailed", "Failed to connect via SSH for teardown")
					}
					return ctrl.Result{RequeueAfter: 1 * time.Minute}, err
				}

				teardownCtx, cancel := context.WithTimeout(ctx, teardownTimeout)
				err = provision.Teardown(teardownCtx, exec)
				cancel()
				closeExecutor(exec, logger)
				if err != nil {
					logger.Error(err, "failed to tear down the VPS, retry or set skip-deprovision")
					if r.Recorder != nil {
						r.Recorder.Event(&node, corev1.EventTypeWarning, "ProvisioningFailed", "Failed to tear down the VPS")
					}
					return ctrl.Result{RequeueAfter: 1 * time.Minute}, err
				}
				if r.Recorder != nil {
					r.Recorder.Event(&node, corev1.EventTypeNormal, "TornDown", "VPS torn down successfully")
				}
			}

			// Clean up the in-cluster uplink resources. They live in
			// spec.uplink.namespace, which can differ from the EdgeNode
			// namespace, so cross-namespace owner-reference GC does not apply
			// and we must delete them explicitly.
			if err := r.deleteUplinkResources(ctx, &node); err != nil {
				logger.Error(err, "failed to delete uplink resources")
				return ctrl.Result{RequeueAfter: 1 * time.Minute}, err
			}

			controllerutil.RemoveFinalizer(&node, edgeNodeFinalizer)
			if err := r.Update(ctx, &node); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Consume the one-shot restart-envoy annotation together with the finalizer
	// in a single metadata update, before any status mutation, so removing it
	// cannot clobber the status written later. restartRequested is captured here
	// and honoured during handleReconciliation.
	restartRequested := node.Annotations[restartEnvoyAnnotation] == annotationTrue
	needsMetaUpdate := false
	if !controllerutil.ContainsFinalizer(&node, edgeNodeFinalizer) {
		controllerutil.AddFinalizer(&node, edgeNodeFinalizer)
		needsMetaUpdate = true
	}
	if restartRequested {
		delete(node.Annotations, restartEnvoyAnnotation)
		needsMetaUpdate = true
	}
	if needsMetaUpdate {
		if err := r.Update(ctx, &node); err != nil {
			return ctrl.Result{}, err
		}
	}

	isReady, reason, msg, err := r.handleReconciliation(ctx, &node, restartRequested)
	return r.updateStatusAndReturn(ctx, &node, prevStatus, isReady, reason, msg, err)
}

// tlsSecretShaped passes only Secrets that can plausibly be referenced by a
// PortBinding TLS SecretRef: the kubernetes.io/tls type or anything carrying a
// tls.crt key (cert-manager and hand-made certs alike). Without it, every
// Secret in the cluster (tokens, registry creds, helm releases) funnels
// through mapSecretToEdgeNodes and costs a PortBinding List per change.
// Note this trims reconcile churn, not manager memory: the informer cache
// still holds all Secrets because the reconciler reads SSH and uplink-key
// Secrets (Opaque) through the same cached client, so a cache-level selector
// would break those Gets.
var tlsSecretShaped = predicate.NewPredicateFuncs(func(obj client.Object) bool {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return false
	}
	if secret.Type == corev1.SecretTypeTLS {
		return true
	}
	_, hasCert := secret.Data[corev1.TLSCertKey]
	return hasCert
})

// SetupWithManager registers the EdgeNodeReconciler with the controller
// manager. It wires a default event recorder when none was injected; the
// ExecutorFactory is left nil so production reconciles dial the real host.
// A Watch on PortBinding drives plan rebuilding: any PortBinding create,
// spec change or deletion enqueues the EdgeNode it references, so the
// aggregate plan always reflects the live set of bindings. The generation
// predicate filters PortBinding status writes, which carry no plan input.
// A second Watch on corev1.Secret drives automatic TLS certificate rotation:
// when a Secret referenced by any PortBinding TLS SecretRef changes (e.g.
// cert-manager renews it), mapSecretToEdgeNodes returns the affected EdgeNodes
// so they are re-enqueued and the new cert is pushed to the VPS.
func (r *EdgeNodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Recorder == nil {
		// GetEventRecorderFor returns the record.EventRecorder this controller
		// uses. staticcheck flags it as deprecated in favour of the new events
		// API, but that API exposes a different interface that would cascade
		// into every Event call; the classic recorder remains supported.
		r.Recorder = mgr.GetEventRecorderFor("edgenode-controller") //nolint:staticcheck
	}
	maxConcurrent := r.MaxConcurrentReconciles
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrentReconciles
	}
	return ctrl.NewControllerManagedBy(mgr).
		WithOptions(controllerruntime.Options{MaxConcurrentReconciles: maxConcurrent}).
		For(&v1alpha1.EdgeNode{}, builder.WithPredicates(edgeNodeEventPredicate)).
		Watches(
			&v1alpha1.PortBinding{},
			handler.EnqueueRequestsFromMapFunc(r.mapPortBindingToEdgeNode),
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.mapSecretToEdgeNodes),
			builder.WithPredicates(tlsSecretShaped),
		).
		Complete(r)
}
