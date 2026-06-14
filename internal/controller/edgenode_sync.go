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
	"errors"
	"fmt"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/achetronic/tunnel/api/v1alpha1"
	"github.com/achetronic/tunnel/internal/ipam"
	"github.com/achetronic/tunnel/internal/planner"
	"github.com/achetronic/tunnel/internal/provision"
	"github.com/achetronic/tunnel/internal/sshexec"
	"github.com/achetronic/tunnel/internal/uplink"
)

// edgeNodeFinalizer is the finalizer key used to manage EdgeNode teardown.
const edgeNodeFinalizer = "tunnel.achetronic.com/finalizer"

// skipDeprovisionAnnotation lets an operator delete an EdgeNode without running
// the SSH teardown against the VPS (useful when the host is already gone).
const skipDeprovisionAnnotation = "tunnel.achetronic.com/skip-deprovision"

// restartEnvoyAnnotation, when set to "true" on an EdgeNode, makes the next
// reconcile restart Envoy on the VPS (to pick up a new binary, e.g. after an
// --envoy-version change). It is a one-shot trigger: the operator consumes and
// removes it, so the user stays in explicit control of when the proxy bounces.
const restartEnvoyAnnotation = "tunnel.achetronic.com/restart-envoy"

// annotationTrue is the truthy value the operator looks for on its boolean
// annotations (skip-deprovision, restart-envoy).
const annotationTrue = "true"

// Timeouts bounding the SSH operations driven from a single reconcile. They run
// against a remote VPS, so they must never block the reconcile loop forever.
const (
	// enrollTimeout bounds keypair generation, enrollment and install.
	enrollTimeout = 5 * time.Minute

	// healthTimeout bounds the VPS health probe.
	healthTimeout = 1 * time.Minute

	// teardownTimeout bounds the VPS teardown on deletion.
	teardownTimeout = 2 * time.Minute

	// defaultRequeueInterval is how often a healthy EdgeNode is re-reconciled when
	// nothing else triggers it, for drift detection and status refresh. It is a
	// middle ground: frequent enough to notice VPS drift and keep retrying, but far
	// from the per-30s hammering the watch-driven model replaced.
	defaultRequeueInterval = 3 * time.Minute

	// defaultMaxConcurrentReconciles bounds parallel EdgeNode reconciles when the
	// manager does not set --max-concurrent-reconciles. Each reconcile speaks SSH
	// to its own VPS, so one worker would let a single unreachable host stall all
	// other nodes; distinct EdgeNodes own disjoint VPSs and uplink namespaces, so
	// running several at once does not race.
	defaultMaxConcurrentReconciles = 5

	// DefaultEnvoyVersion is the Envoy release installed on the VPS when the manager
	// is not given an explicit --envoy-version. It is the single source of the
	// default, reused as the flag default in cmd/main.go.
	// Ref: https://github.com/envoyproxy/envoy/releases
	// Keep in lockstep with ENVOY_VERSION in Makefile.
	DefaultEnvoyVersion = "1.29.3"

	// DefaultTunnelctlDir is the directory the operator reads the static tunnelctl
	// binaries from when --tunnelctl-dir is unset. In the operator image the
	// Dockerfile copies tunnelctl-linux-<arch> here; under `make run` it is
	// overridden to a local build dir.
	DefaultTunnelctlDir = "/opt/tunnelctl"

	// DefaultUplinkImage is the uplink StatefulSet image used when the manager is
	// not given explicit image flags. It is the single source of the default,
	// reused to compose the flag defaults in cmd/main.go (DefaultImageRepo + the
	// "/uplink:" + DefaultImageTag convention).
	DefaultUplinkImage = DefaultImageRepo + "/uplink:" + DefaultImageTag

	// DefaultImageRepo is the base repository the operator derives its managed
	// images from (the uplink image is <repo>/uplink:<tag>, mirroring the operator's
	// own <repo>/controller:<tag>).
	DefaultImageRepo = "ghcr.io/achetronic/tunnel"

	// DefaultImageTag is the image tag used when none is provided. At release it is
	// set to the operator version so the uplink tag matches the operator.
	DefaultImageTag = "latest"
)

// k8sResolver resolves Kubernetes services to their ClusterIPs.
type k8sResolver struct {
	client.Client
	ctx context.Context
}

// ResolveService retrieves the ClusterIP of the specified service.
// Returns an error if the service is not found or has no ClusterIP.
func (r *k8sResolver) ResolveService(namespace, name string) (string, error) {
	var svc corev1.Service
	err := r.Get(r.ctx, types.NamespacedName{Name: name, Namespace: namespace}, &svc)
	if err != nil {
		return "", err
	}
	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == "None" {
		return "", fmt.Errorf("service %s/%s has no ClusterIP", namespace, name)
	}
	return svc.Spec.ClusterIP, nil
}

// getSSHExecutor builds the SSH executor for the EdgeNode. It reads the SSH
// credentials from the referenced secret and either delegates to the injected
// ExecutorFactory or dials the real host with sshexec.NewSSHExecutor.
func (r *EdgeNodeReconciler) getSSHExecutor(ctx context.Context, node *v1alpha1.EdgeNode) (sshexec.Executor, error) {
	var secret corev1.Secret
	ns := node.Spec.SSH.SecretRef.Namespace
	if ns == "" {
		ns = node.Namespace
	}
	if err := r.Get(ctx, types.NamespacedName{Name: node.Spec.SSH.SecretRef.Name, Namespace: ns}, &secret); err != nil {
		return nil, fmt.Errorf("failed to get SSH secret: %w", err)
	}

	if r.ExecutorFactory != nil {
		return r.ExecutorFactory(ctx, node, &secret)
	}

	user := node.Spec.SSH.User
	if user == "" {
		user = "root"
	}
	port := node.Spec.SSH.Port
	if port == 0 {
		port = 22
	}

	connectTimeout := 30 * time.Second
	if node.Spec.SSH.ConnectTimeout != "" {
		d, err := time.ParseDuration(node.Spec.SSH.ConnectTimeout)
		if err != nil {
			return nil, fmt.Errorf("invalid ssh.connectTimeout %q: %w", node.Spec.SSH.ConnectTimeout, err)
		}
		connectTimeout = d
	}

	return sshexec.NewSSHExecutor(sshexec.Config{
		Host:                            node.Spec.Address,
		Port:                            port,
		User:                            user,
		Password:                        string(secret.Data["password"]),
		PrivateKey:                      string(secret.Data["privateKey"]),
		Passphrase:                      string(secret.Data["passphrase"]),
		KnownHosts:                      string(secret.Data["knownHosts"]),
		InsecureSkipHostKeyVerification: node.Spec.SSH.InsecureSkipHostKeyVerification,
		ConnectTimeout:                  connectTimeout,
	})
}

// updateStatusAndReturn sets the Ready condition and the ObservedGeneration of
// the EdgeNode and persists the status if it has changed compared to prevStatus.
// On the happy path it requeues after requeueInterval so the operator periodically re-reconciles:
// this detects drift on the VPS, refreshes the reported health/handshake status, and keeps retrying
// transient conditions even when no watch event fires. A conflict on the status
// update is translated into a clean requeue.
func (r *EdgeNodeReconciler) updateStatusAndReturn(ctx context.Context, node *v1alpha1.EdgeNode, prevStatus *v1alpha1.EdgeNodeStatus, status metav1.ConditionStatus, reason, msg string, returnErr error) (ctrl.Result, error) {
	node.Status.ObservedGeneration = node.Generation
	meta.SetStatusCondition(&node.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             status,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: node.Generation,
	})

	if prevStatus != nil && equality.Semantic.DeepEqual(prevStatus, &node.Status) {
		// No change in status, skip Update to avoid reconciliation hot loops.
		if returnErr != nil {
			return ctrl.Result{}, returnErr
		}
		return ctrl.Result{RequeueAfter: r.requeueInterval()}, nil
	}

	if err := r.Status().Update(ctx, node); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		log.FromContext(ctx).Error(err, "failed to update EdgeNode status")
		if returnErr == nil {
			return ctrl.Result{}, fmt.Errorf("failed to update EdgeNode status: %w", err)
		}
		return ctrl.Result{}, fmt.Errorf("failed to update status: %v, original error: %w", err, returnErr)
	}

	// On error, return it so controller-runtime requeues with exponential
	// backoff. On success, requeue after a fixed interval for periodic drift
	// detection and status refresh.
	if returnErr != nil {
		return ctrl.Result{}, returnErr
	}
	return ctrl.Result{RequeueAfter: r.requeueInterval()}, nil
}

// requeueInterval returns the periodic reconcile interval, falling back to
// defaultRequeueInterval when the field is left unset.
func (r *EdgeNodeReconciler) requeueInterval() time.Duration {
	if r.RequeueInterval > 0 {
		return r.RequeueInterval
	}
	return defaultRequeueInterval
}

// envoyVersion returns the Envoy release to install, falling back to
// DefaultEnvoyVersion when the field is left unset.
func (r *EdgeNodeReconciler) envoyVersion() string {
	if r.EnvoyVersion != "" {
		return r.EnvoyVersion
	}
	return DefaultEnvoyVersion
}

// tunnelctlDir returns the directory the operator reads the tunnelctl binaries
// from, falling back to DefaultTunnelctlDir when the field is left unset.
func (r *EdgeNodeReconciler) tunnelctlDir() string {
	if r.TunnelctlDir != "" {
		return r.TunnelctlDir
	}
	return DefaultTunnelctlDir
}

// uplinkImage returns the uplink StatefulSet image, falling back to
// DefaultUplinkImage when the field is left unset.
func (r *EdgeNodeReconciler) uplinkImage() string {
	if r.UplinkImage != "" {
		return r.UplinkImage
	}
	return DefaultUplinkImage
}

// handleReconciliation performs the actual business logic: provisioning, VPN
// uplink configuration, IPAM, rendering of ConfigMaps/StatefulSets and the VPS
// health probe. It returns the Ready condition status, reason, message and any
// error. SSH and network IO is delegated to provision/sshexec.
func (r *EdgeNodeReconciler) handleReconciliation(ctx context.Context, node *v1alpha1.EdgeNode, forceEnvoyRestart bool) (status metav1.ConditionStatus, reason, msg string, err error) {
	logger := log.FromContext(ctx)
	logger.Info("reconciling EdgeNode", "address", node.Spec.Address, "generation", node.Generation)

	// The uplink namespace default is guaranteed by the CRD marker
	// (UplinkSpec.Namespace has +kubebuilder:default="tunnel").
	keysNamespace := node.Spec.Uplink.Namespace

	// Refuse to touch uplink resources that another EdgeNode already owns, so a
	// name clash in a shared uplink namespace fails loudly instead of silently
	// overwriting another tenant's StatefulSet and Secrets.
	if status, reason, msg, err, collision := r.checkUplinkOwnership(ctx, node, keysNamespace); collision {
		return status, reason, msg, err
	}

	logger.Info("connecting to the VPS over SSH", "address", node.Spec.Address)
	exec, err := r.getSSHExecutor(ctx, node)
	if err != nil {
		logger.Error(err, "failed to get SSH executor")
		if r.Recorder != nil {
			r.Recorder.Event(node, corev1.EventTypeWarning, "SSHConnectionFailed", "Failed to connect via SSH")
		}
		return metav1.ConditionFalse, "SSHConnectionFailed", fmt.Sprintf("Failed to connect via SSH: %v", err), err
	}
	defer closeExecutor(exec, logger)

	replicas := node.Spec.Uplink.Replicas
	if replicas <= 0 {
		replicas = 1
	}

	logger.Info("ensuring uplink WireGuard keys", "replicas", replicas, "namespace", keysNamespace)
	keysSecret, err := r.ensureUplinkKeys(ctx, node, replicas, keysNamespace)
	if err != nil {
		return metav1.ConditionFalse, "SecretError", fmt.Sprintf("Failed to ensure uplink keys: %v", err), err
	}

	uplinkKeys, err := r.resolveUplinkPublicKeys(keysSecret, replicas)
	if err != nil {
		var keyErr *uplinkKeyError
		if errors.As(err, &keyErr) {
			return metav1.ConditionFalse, keyErr.reason, keyErr.msg, err
		}
		return metav1.ConditionFalse, "IncompleteKeysSecret", err.Error(), err
	}

	logger.Info("ensuring VPS WireGuard keypair")
	vpsPubKey, vpsPrivKey, err := r.ensureVPSKeypair(ctx, node, keysNamespace)
	if err != nil {
		logger.Error(err, "failed to ensure VPS keypair")
		return metav1.ConditionFalse, "KeyGenerationFailed", fmt.Sprintf("Failed to ensure VPS keypair: %v", err), err
	}

	bindings, err := r.collectBindings(ctx, node)
	if err != nil {
		return metav1.ConditionFalse, "PortBindingListFailed", fmt.Sprintf("Failed to list PortBindings: %v", err), err
	}

	logger.Info("building desired plan", "portBindings", len(bindings))
	resolver := &k8sResolver{Client: r.Client, ctx: ctx}
	plan, err := planner.BuildPlan(node, bindings, resolver, vpsPrivKey, vpsPubKey, uplinkKeys)
	if err != nil {
		logger.Error(err, "failed to build plan")
		// A service that is not resolvable yet is a transient condition: it
		// will become ready once the referenced Service exists. BuildPlan wraps
		// the resolver error with %w, and apierrors.IsNotFound unwraps via
		// errors.As, so the NotFound status survives.
		if apierrors.IsNotFound(err) {
			return metav1.ConditionFalse, "ServiceNotFoundYet", fmt.Sprintf("Referenced service is not resolvable yet: %v", err), err
		}
		return metav1.ConditionFalse, "PlanBuildFailed", fmt.Sprintf("Failed to build plan: %v", err), err
	}
	// The Envoy version is an operator-level choice (manager flag), injected into
	// the plan here rather than derived by the pure planner.
	plan.EnvoyVersion = r.envoyVersion()
	// Likewise the tunnelctl binary directory is an install-time operator choice.
	plan.TunnelctlDir = r.tunnelctlDir()

	tlsFiles, tlsStatus, tlsReason, tlsMsg, tlsErr := r.collectTLSFiles(ctx, node, plan)
	if tlsErr != nil {
		if r.Recorder != nil {
			r.Recorder.Event(node, corev1.EventTypeWarning, tlsReason, tlsMsg)
		}
		return tlsStatus, tlsReason, tlsMsg, tlsErr
	}

	// Enroll installs packages and Envoy and applies the config over SSH. On a
	// first enrollment this downloads the Envoy binary and runs the package
	// manager, so it can take a few minutes; the milestone logs above and below
	// make that visible instead of looking stuck.
	logger.Info("enrolling the VPS over SSH (install + config); first run can take a few minutes")
	enrollCtx, cancel := context.WithTimeout(ctx, enrollTimeout)
	tlsApplied, err := provision.Enroll(enrollCtx, exec, plan, tlsFiles)
	cancel()
	if err != nil {
		logger.Error(err, "failed to provision host")
		if r.Recorder != nil {
			r.Recorder.Event(node, corev1.EventTypeWarning, "ProvisioningFailed", fmt.Sprintf("Failed to provision VPS: %v", err))
		}
		return metav1.ConditionFalse, "ProvisioningFailed", fmt.Sprintf("Failed to provision VPS: %v", err), err
	}
	logger.Info("VPS enrolled", "tlsApplied", tlsApplied)
	if r.Recorder != nil {
		r.Recorder.Event(node, corev1.EventTypeNormal, "Provisioned", "VPS enrolled and provisioned successfully")
	}

	// Record what the VPS now serves as soon as the enroll succeeds, before the
	// in-cluster uplink workload and the health check. These two fields describe
	// the plan materialized on the edge, so a later failure creating the uplink
	// ConfigMap/Service/StatefulSet or probing health must not leave them stale:
	// otherwise PortBindings stay stuck in NotYetApplied and the next reconcile
	// sees a phantom config drift and re-pushes over SSH needlessly.
	node.Status.AppliedConfigHash = appliedConfigHash(plan.PlanHash, tlsFiles)
	node.Status.AppliedBindings = appliedBindingKeys(bindings)

	// Honour a one-shot restart request (the restart-envoy annotation, already
	// consumed by Reconcile). This applies a new Envoy binary that the running
	// service would not otherwise pick up.
	if forceEnvoyRestart {
		logger.Info("restarting envoy on request (restart-envoy annotation)")
		restartCtx, cancelRestart := context.WithTimeout(ctx, healthTimeout)
		err = provision.RestartEnvoy(restartCtx, exec)
		cancelRestart()
		if err != nil {
			logger.Error(err, "failed to restart envoy")
			if r.Recorder != nil {
				r.Recorder.Event(node, corev1.EventTypeWarning, "EnvoyRestartFailed", fmt.Sprintf("Failed to restart Envoy: %v", err))
			}
			return metav1.ConditionFalse, "EnvoyRestartFailed", fmt.Sprintf("Failed to restart Envoy: %v", err), err
		}
		if r.Recorder != nil {
			r.Recorder.Event(node, corev1.EventTypeNormal, "EnvoyRestarted", "Envoy restarted on request")
		}
	}

	// Warn once, and only when the private keys were actually pushed this
	// reconcile, that key material left the cluster for edge termination.
	if tlsApplied && r.Recorder != nil {
		r.Recorder.Event(node, corev1.EventTypeWarning, "PrivateKeyOnEdge", privateKeyOnEdgeMessage(plan))
	}

	logger.Info("reconciling uplink workload (ConfigMap + StatefulSet)")
	cm := uplink.BuildConfigMap(node, plan.UplinkDocument)
	if err := r.createOrUpdateConfigMap(ctx, cm); err != nil {
		return metav1.ConditionFalse, "ConfigMapUpdateFailed", fmt.Sprintf("Failed to update ConfigMap: %v", err), err
	}

	// The headless Service backs the StatefulSet's spec.serviceName (per-pod
	// DNS identity); created here so the reference never dangles.
	svc := uplink.BuildHeadlessService(node)
	if err := r.createOrUpdateHeadlessService(ctx, svc); err != nil {
		return metav1.ConditionFalse, "ServiceUpdateFailed", fmt.Sprintf("Failed to update headless Service: %v", err), err
	}

	sts := uplink.BuildStatefulSet(node, r.uplinkImage(), corev1.PullIfNotPresent)
	if err := r.createOrUpdateStatefulSet(ctx, sts); err != nil {
		return metav1.ConditionFalse, "StatefulSetUpdateFailed", fmt.Sprintf("Failed to update StatefulSet: %v", err), err
	}

	logger.Info("checking VPS health")
	healthCtx, cancel := context.WithTimeout(ctx, healthTimeout)
	health, err := provision.CheckHealth(healthCtx, exec)
	cancel()
	if err != nil {
		logger.Error(err, "failed to check VPS health")
		return metav1.ConditionFalse, "HealthCheckFailed", fmt.Sprintf("Failed to check VPS health: %v", err), err
	}

	network := node.Spec.Tunnel.Network
	if network == "" {
		network = "10.200.0.0/24"
	}
	ipCalc, err := ipam.New(network)
	if err != nil {
		return metav1.ConditionFalse, "IPAMError", fmt.Sprintf("Failed to build IPAM for status: %v", err), err
	}

	newUplinks, err := r.buildUplinkStatuses(replicas, uplinkKeys, health, ipCalc)
	if err != nil {
		return metav1.ConditionFalse, "IPAMError", fmt.Sprintf("Failed to compute replica IP for status (%v)", err), err
	}

	node.Status.PublicKey = vpsPubKey
	node.Status.Uplink = newUplinks

	return r.evaluateReadiness(ctx, node, health, sts, replicas)
}

// appliedBindingKeys renders the PortBindings materialized in the applied plan
// as sorted "namespace/name" keys for EdgeNodeStatus.AppliedBindings. Sorted so
// the status is deterministic and DeepEqual-friendly for the no-op status
// update skip.
func appliedBindingKeys(bindings []v1alpha1.PortBinding) []string {
	if len(bindings) == 0 {
		return nil
	}
	keys := make([]string, 0, len(bindings))
	for _, pb := range bindings {
		keys = append(keys, pb.Namespace+"/"+pb.Name)
	}
	sort.Strings(keys)
	return keys
}
