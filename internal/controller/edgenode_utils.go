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
	"crypto/sha256"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/go-logr/logr"

	"github.com/achetronic/tunnel/api/v1alpha1"
	"github.com/achetronic/tunnel/internal/ipam"
	"github.com/achetronic/tunnel/internal/planner"
	"github.com/achetronic/tunnel/internal/provision"
	"github.com/achetronic/tunnel/internal/render"
	"github.com/achetronic/tunnel/internal/sshexec"
	"github.com/achetronic/tunnel/internal/uplink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ensureUplinkKeys returns the Secret holding the per-replica WireGuard private
// keys. It creates the Secret with freshly generated keys when it does not exist
// yet, and reconciles it to the current replica count otherwise: a key is added
// for every new ordinal (scale up) and keys beyond the replica count are dropped
// (scale down). Existing keys are never regenerated, so an ordinal keeps its
// identity across reconciles.
func (r *EdgeNodeReconciler) ensureUplinkKeys(ctx context.Context, node *v1alpha1.EdgeNode, replicas int32, namespace string) (*corev1.Secret, error) {
	var keysSecret corev1.Secret
	keysName := fmt.Sprintf("%s-uplink-keys", node.Name)

	err := r.Get(ctx, types.NamespacedName{Name: keysName, Namespace: namespace}, &keysSecret)
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("failed to read keys secret: %w", err)
	}

	// Create the Secret from scratch when it does not exist yet.
	if apierrors.IsNotFound(err) {
		keysMap := make(map[int32]string, replicas)
		for i := range replicas {
			priv, genErr := wgtypes.GeneratePrivateKey()
			if genErr != nil {
				return nil, fmt.Errorf("failed to generate uplink private key for replica %d: %w", i, genErr)
			}
			keysMap[i] = priv.String()
		}
		built := uplink.BuildKeysSecret(node, keysMap)
		if createErr := r.Create(ctx, built); createErr != nil {
			return nil, fmt.Errorf("failed to create keys secret: %w", createErr)
		}
		return built, nil
	}

	// The Secret exists: reconcile its keys to the current replica count.
	if keysSecret.Data == nil {
		keysSecret.Data = make(map[string][]byte)
	}
	expected := make(map[string]bool, replicas)
	changed := false

	// Add a freshly generated key for every ordinal that is missing one.
	for i := range replicas {
		name := fmt.Sprintf("priv-%d", i)
		expected[name] = true
		if len(keysSecret.Data[name]) > 0 {
			continue
		}
		priv, genErr := wgtypes.GeneratePrivateKey()
		if genErr != nil {
			return nil, fmt.Errorf("failed to generate uplink private key for replica %d: %w", i, genErr)
		}
		keysSecret.Data[name] = []byte(priv.String())
		changed = true
	}

	// Drop keys for ordinals that no longer exist after a scale down.
	for name := range keysSecret.Data {
		if strings.HasPrefix(name, "priv-") && !expected[name] {
			delete(keysSecret.Data, name)
			changed = true
		}
	}

	if changed {
		if updErr := r.Update(ctx, &keysSecret); updErr != nil {
			return nil, fmt.Errorf("failed to update keys secret: %w", updErr)
		}
	}
	return &keysSecret, nil
}

// ensureVPSKeypair returns the VPS WireGuard keypair (public, private). It is
// cached in an in-cluster Secret named "<node>-vps-key" so the keypair is
// generated once and reused. Generation happens locally with wgctrl/wgtypes
// (no command on the VPS), so the relay never needs wireguard-tools installed:
// tunnelctl applies the private key natively from its desired-state document.
func (r *EdgeNodeReconciler) ensureVPSKeypair(ctx context.Context, node *v1alpha1.EdgeNode, namespace string) (pub string, priv string, err error) {
	secretName := fmt.Sprintf("%s-vps-key", node.Name)

	var existing corev1.Secret
	getErr := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: namespace}, &existing)
	if getErr == nil {
		return string(existing.Data["pub"]), string(existing.Data["priv"]), nil
	}
	if !apierrors.IsNotFound(getErr) {
		return "", "", fmt.Errorf("failed to read VPS key secret: %w", getErr)
	}

	privKey, genErr := wgtypes.GeneratePrivateKey()
	if genErr != nil {
		return "", "", fmt.Errorf("failed to generate VPS private key: %w", genErr)
	}
	pub, priv = privKey.PublicKey().String(), privKey.String()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
			Labels:    uplink.LabelsForNode(node),
		},
		StringData: map[string]string{
			"pub":  pub,
			"priv": priv,
		},
	}
	if err := r.Create(ctx, secret); err != nil {
		return "", "", fmt.Errorf("failed to persist VPS key secret: %w", err)
	}
	return pub, priv, nil
}

// uplinkKeyError carries the Ready condition reason and message together with
// the error so the caller can surface the proper condition without leaking
// literals.
type uplinkKeyError struct {
	reason string
	msg    string
	err    error
}

func (e *uplinkKeyError) Error() string { return e.err.Error() }

func (e *uplinkKeyError) Unwrap() error { return e.err }

// resolveUplinkPublicKeys parses the per-replica WireGuard private keys stored in
// the uplink keys Secret and returns the matching public keys indexed by replica
// ordinal. A missing private key yields an IncompleteKeysSecret reason while an
// unparseable one yields InvalidKey; both are wrapped in uplinkKeyError so the
// caller maps them to the right Ready condition.
func (r *EdgeNodeReconciler) resolveUplinkPublicKeys(keysSecret *corev1.Secret, replicas int32) (map[int32]string, error) {
	uplinkKeys := make(map[int32]string)
	for i := range replicas {
		privStr := string(keysSecret.Data[fmt.Sprintf("priv-%d", i)])
		if privStr == "" {
			err := fmt.Errorf("uplink keys secret %s/%s is missing priv-%d", keysSecret.Namespace, keysSecret.Name, i)
			return nil, &uplinkKeyError{reason: "IncompleteKeysSecret", msg: err.Error(), err: err}
		}
		priv, err := wgtypes.ParseKey(privStr)
		if err != nil {
			msg := fmt.Sprintf("Invalid uplink private key for replica %d: %v", i, err)
			return nil, &uplinkKeyError{reason: "InvalidKey", msg: msg, err: err}
		}
		uplinkKeys[i] = priv.PublicKey().String()
	}
	return uplinkKeys, nil
}

// collectBindings lists all PortBindings and returns those that target the given
// EdgeNode via their spec.edgeNodeRef. The match is namespace-aware: a binding
// belongs to this node only when both the referenced name AND the resolved
// reference namespace equal the node's. EdgeNodeRef.Namespace defaults to the
// PortBinding's own namespace when empty, mirroring triggerEdgeNode and
// mapSecretToEdgeNodes, so two EdgeNodes that merely share a name in different
// namespaces never aggregate each other's bindings.
func (r *EdgeNodeReconciler) collectBindings(ctx context.Context, node *v1alpha1.EdgeNode) ([]v1alpha1.PortBinding, error) {
	var pbList v1alpha1.PortBindingList
	if err := r.List(ctx, &pbList); err != nil {
		return nil, err
	}
	var bindings []v1alpha1.PortBinding
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
		bindings = append(bindings, pb)
	}
	return bindings, nil
}

// buildUplinkStatuses assembles the per-replica UplinkStatus list from the
// computed IPAM addresses and uplink public keys, attaching the last WireGuard
// handshake timestamp reported by the VPS health probe when available.
func (r *EdgeNodeReconciler) buildUplinkStatuses(replicas int32, uplinkKeys map[int32]string, health *provision.HealthStatus, ipCalc *ipam.IPAM) ([]v1alpha1.UplinkStatus, error) {
	var newUplinks []v1alpha1.UplinkStatus
	for i := range replicas {
		pubKey := uplinkKeys[i]
		replicaIP, err := ipCalc.ReplicaIP(i)
		if err != nil {
			return nil, fmt.Errorf("ordinal %d: %w", i, err)
		}

		us := v1alpha1.UplinkStatus{
			Ordinal:   i,
			TunnelIP:  replicaIP,
			PublicKey: pubKey,
		}
		if health != nil {
			if ts, ok := health.Handshakes[pubKey]; ok {
				t := metav1.NewTime(ts)
				us.LastHandshake = &t
			}
		}
		newUplinks = append(newUplinks, us)
	}
	return newUplinks, nil
}

// evaluateReadiness decides the final Ready condition. It first checks the VPS
// service health (envoy/wireguard) and then the uplink StatefulSet readiness. A
// NotFound on the StatefulSet read is tolerated because it may not have surfaced
// yet; any other read error is surfaced via the returned error.
func (r *EdgeNodeReconciler) evaluateReadiness(ctx context.Context, node *v1alpha1.EdgeNode, health *provision.HealthStatus, sts *appsv1.StatefulSet, replicas int32) (metav1.ConditionStatus, string, string, error) {
	if health != nil && (!health.EnvoyHealthy || !health.RelayHealthy) {
		if r.Recorder != nil {
			r.Recorder.Event(node, corev1.EventTypeWarning, "VPSDegraded", "VPS services (envoy/wireguard) are not active")
		}
		return metav1.ConditionFalse, "VPSDegraded", "VPS services (envoy/wireguard) are not active", nil
	}

	var stsObj appsv1.StatefulSet
	if err := r.Get(ctx, types.NamespacedName{Name: sts.Name, Namespace: sts.Namespace}, &stsObj); err != nil {
		if !apierrors.IsNotFound(err) {
			return metav1.ConditionFalse, "StatefulSetReadFailed", fmt.Sprintf("Failed to read uplink StatefulSet status: %v", err), err
		}
	} else if stsObj.Status.ReadyReplicas < replicas {
		return metav1.ConditionFalse, "UplinksDegraded", fmt.Sprintf("%d/%d uplink pods are ready", stsObj.Status.ReadyReplicas, replicas), nil
	}

	return metav1.ConditionTrue, "AllHealthy", "VPS is fully synced and healthy", nil
}

// createOrUpdateConfigMap creates or updates the uplink nftables ConfigMap,
// using CreateOrUpdate so optimistic conflicts are handled by the helper.
func (r *EdgeNodeReconciler) createOrUpdateConfigMap(ctx context.Context, cm *corev1.ConfigMap) error {
	target := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: cm.Name, Namespace: cm.Namespace},
	}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, target, func() error {
		target.Labels = cm.Labels
		target.Data = cm.Data
		return nil
	})
	return err
}

// createOrUpdateHeadlessService creates or updates the headless Service the
// uplink StatefulSet's spec.serviceName references. ClusterIP is immutable on
// update, so only labels and selector are reconciled.
func (r *EdgeNodeReconciler) createOrUpdateHeadlessService(ctx context.Context, svc *corev1.Service) error {
	target := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: svc.Name, Namespace: svc.Namespace},
	}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, target, func() error {
		target.Labels = svc.Labels
		target.Spec.Selector = svc.Spec.Selector
		if target.CreationTimestamp.IsZero() {
			target.Spec.ClusterIP = svc.Spec.ClusterIP
		}
		return nil
	})
	return err
}

// createOrUpdateStatefulSet creates or updates the uplink StatefulSet, using
// CreateOrUpdate so optimistic conflicts are handled by the helper.
func (r *EdgeNodeReconciler) createOrUpdateStatefulSet(ctx context.Context, sts *appsv1.StatefulSet) error {
	target := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: sts.Name, Namespace: sts.Namespace},
	}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, target, func() error {
		target.Labels = sts.Labels
		target.Spec.Replicas = sts.Spec.Replicas
		target.Spec.Selector = sts.Spec.Selector
		target.Spec.ServiceName = sts.Spec.ServiceName
		target.Spec.Template = sts.Spec.Template
		return nil
	})
	return err
}

// uplinkOwnerNamespaceLabel records, on every in-cluster uplink resource, the
// namespace of the EdgeNode that owns it. The reconciler reads it to refuse
// adopting resources another EdgeNode created when two EdgeNodes of the same
// name share an uplink namespace.
const uplinkOwnerNamespaceLabel = "tunnel.achetronic.com/owner-namespace"

// checkUplinkOwnership verifies that the uplink StatefulSet and keys Secret in
// the target namespace, if they already exist, are owned by this EdgeNode. It
// returns collision=true with a Ready=False condition when an existing resource
// carries an owner-namespace label that differs from this EdgeNode's namespace,
// so a name clash in a shared uplink namespace fails loudly instead of silently
// overwriting another tenant's resources. Resources without the label predate
// this guard and are treated as owned, so an upgrade never trips a false alarm.
func (r *EdgeNodeReconciler) checkUplinkOwnership(ctx context.Context, node *v1alpha1.EdgeNode, namespace string) (status metav1.ConditionStatus, reason, msg string, err error, collision bool) {
	foreignOwner := func(labels map[string]string) (string, bool) {
		owner, ok := labels[uplinkOwnerNamespaceLabel]
		return owner, ok && owner != node.Namespace
	}

	var sts appsv1.StatefulSet
	stsErr := r.Get(ctx, types.NamespacedName{Name: fmt.Sprintf("%s-uplink", node.Name), Namespace: namespace}, &sts)
	if stsErr == nil {
		if owner, foreign := foreignOwner(sts.Labels); foreign {
			m := fmt.Sprintf("uplink StatefulSet in namespace %s is owned by an EdgeNode in namespace %s", namespace, owner)
			if r.Recorder != nil {
				r.Recorder.Event(node, corev1.EventTypeWarning, "UplinkNamespaceCollision", m)
			}
			return metav1.ConditionFalse, "UplinkNamespaceCollision", m, nil, true
		}
	} else if !apierrors.IsNotFound(stsErr) {
		return metav1.ConditionFalse, "StatefulSetReadFailed", fmt.Sprintf("Failed to read existing uplink StatefulSet: %v", stsErr), stsErr, true
	}

	var secret corev1.Secret
	secretErr := r.Get(ctx, types.NamespacedName{Name: fmt.Sprintf("%s-uplink-keys", node.Name), Namespace: namespace}, &secret)
	if secretErr == nil {
		if owner, foreign := foreignOwner(secret.Labels); foreign {
			m := fmt.Sprintf("uplink keys Secret in namespace %s is owned by an EdgeNode in namespace %s", namespace, owner)
			if r.Recorder != nil {
				r.Recorder.Event(node, corev1.EventTypeWarning, "UplinkNamespaceCollision", m)
			}
			return metav1.ConditionFalse, "UplinkNamespaceCollision", m, nil, true
		}
	} else if !apierrors.IsNotFound(secretErr) {
		return metav1.ConditionFalse, "SecretReadFailed", fmt.Sprintf("Failed to read existing uplink keys Secret: %v", secretErr), secretErr, true
	}

	return metav1.ConditionTrue, "", "", nil, false
}

// closeExecutor closes the SSH executor if it implements io.Closer, logging any
// error instead of silently discarding it.
func closeExecutor(exec sshexec.Executor, logger logr.Logger) {
	closer, ok := exec.(interface{ Close() error })
	if !ok {
		return
	}
	if err := closer.Close(); err != nil {
		logger.Error(err, "failed to close SSH executor")
	}
}

// deleteUplinkResources removes the in-cluster uplink workload created for the
// EdgeNode: the StatefulSet, the headless Service backing its spec.serviceName,
// the nftables ConfigMap, the WireGuard keys Secret and the cached VPS key
// Secret. A NotFound error is ignored so teardown stays idempotent.
func (r *EdgeNodeReconciler) deleteUplinkResources(ctx context.Context, node *v1alpha1.EdgeNode) error {
	objs := []client.Object{
		uplink.BuildStatefulSet(node, "", ""),
		uplink.BuildHeadlessService(node),
		uplink.BuildConfigMap(node, nil),
		uplink.BuildKeysSecret(node, nil),
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("%s-vps-key", node.Name),
				Namespace: node.Spec.Uplink.Namespace,
			},
		},
	}
	for _, obj := range objs {
		// Never delete a resource owned by a different EdgeNode. Two EdgeNodes of
		// the same name in different namespaces that share an uplink namespace map
		// to identical resource names; tearing one down must not destroy the
		// other's live uplink. Read the current object and skip it when its
		// owner-namespace label names another EdgeNode. Resources without the
		// label predate the guard and are treated as owned so upgrades still clean
		// up.
		if foreign, err := r.uplinkResourceForeign(ctx, obj, node.Namespace); err != nil {
			return err
		} else if foreign {
			if r.Recorder != nil {
				r.Recorder.Event(node, corev1.EventTypeWarning, "UplinkNamespaceCollision",
					fmt.Sprintf("skipped deleting %T %s/%s owned by another EdgeNode", obj, obj.GetNamespace(), obj.GetName()))
			}
			continue
		}
		if err := r.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete %T %s/%s: %w", obj, obj.GetNamespace(), obj.GetName(), err)
		}
	}
	return nil
}

// uplinkResourceForeign reports whether the existing object carries an
// owner-namespace label that names an EdgeNode namespace other than ownerNS.
// A missing object (NotFound) or one without the label is not foreign, so a
// normal teardown and an upgrade from before the label both proceed to delete.
func (r *EdgeNodeReconciler) uplinkResourceForeign(ctx context.Context, obj client.Object, ownerNS string) (bool, error) {
	var current client.Object
	switch obj.(type) {
	case *appsv1.StatefulSet:
		current = &appsv1.StatefulSet{}
	case *corev1.Service:
		current = &corev1.Service{}
	case *corev1.ConfigMap:
		current = &corev1.ConfigMap{}
	case *corev1.Secret:
		current = &corev1.Secret{}
	default:
		return false, nil
	}
	if err := r.Get(ctx, client.ObjectKeyFromObject(obj), current); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to read %T %s/%s before delete: %w", obj, obj.GetNamespace(), obj.GetName(), err)
	}
	owner, ok := current.GetLabels()[uplinkOwnerNamespaceLabel]
	return ok && owner != ownerNS, nil
}

// tlsSecretIncompleteReason is the Ready condition reason emitted when a
// TLS Secret referenced by a PortBinding is missing or lacks required keys.
const tlsSecretIncompleteReason = "TLSSecretIncomplete"

// privateKeyOnEdgeMessage builds the PrivateKeyOnEdge warning text, listing the
// bindings and Secrets whose private keys were copied to the VPS for edge TLS
// termination. It assumes the plan has at least one TLS material (offload or
// mutual); passthrough bindings never carry key material and are not listed.
func privateKeyOnEdgeMessage(plan *planner.Plan) string {
	refs := make([]string, 0, len(plan.TLSMaterials))
	for _, mat := range plan.TLSMaterials {
		refs = append(refs, fmt.Sprintf("%s (Secret %s, mode %s)", mat.BindingName, mat.SecretName, mat.Mode))
	}
	return fmt.Sprintf(
		"private key material has been copied to the VPS for edge TLS termination: %s",
		strings.Join(refs, ", "),
	)
}

// collectTLSFiles reads Kubernetes Secrets for every TLSMaterial in the plan
// and assembles the provision.TLSFile slice that Enroll will push to the VPS.
// It validates at runtime that each Secret has the keys demanded by the mode:
//
//   - offload: requires tls.crt and tls.key
//   - mutual:  requires tls.crt, tls.key, and ca.crt
//
// When a Secret is missing or a required key is absent the function returns a
// Ready=False condition with reason TLSSecretIncomplete so the controller can
// surface the problem without retrying endlessly. The PrivateKeyOnEdge warning
// is not emitted here (this runs on every reconcile); the caller emits it only
// when Enroll reports that the material was actually pushed to the VPS.
func (r *EdgeNodeReconciler) collectTLSFiles(
	ctx context.Context,
	node *v1alpha1.EdgeNode,
	plan *planner.Plan,
) (files []provision.TLSFile, status metav1.ConditionStatus, reason, msg string, err error) {
	for _, mat := range plan.TLSMaterials {
		ns := mat.SecretNamespace
		if ns == "" {
			ns = node.Namespace
		}

		var secret corev1.Secret
		if getErr := r.Get(ctx, types.NamespacedName{Name: mat.SecretName, Namespace: ns}, &secret); getErr != nil {
			message := fmt.Sprintf(
				"TLS Secret %s/%s for binding %q not found: %v",
				ns, mat.SecretName, mat.BindingName, getErr,
			)
			return nil, metav1.ConditionFalse, tlsSecretIncompleteReason, message, getErr
		}

		cert, hasCert := secret.Data["tls.crt"]
		key, hasKey := secret.Data["tls.key"]

		if !hasCert || !hasKey {
			message := fmt.Sprintf(
				"TLS Secret %s/%s for binding %q is missing tls.crt or tls.key",
				ns, mat.SecretName, mat.BindingName,
			)
			return nil, metav1.ConditionFalse, tlsSecretIncompleteReason, message,
				fmt.Errorf("%s", message)
		}

		sdsCfg := render.EnvoySDSConfig{
			Mode:           mat.Mode,
			CertSecretName: mat.CertSecretName,
			CertPEM:        cert,
			KeyPEM:         key,
		}

		if mat.Mode == "mutual" {
			ca, hasCA := secret.Data["ca.crt"]
			if !hasCA {
				message := fmt.Sprintf(
					"TLS Secret %s/%s for binding %q (mutual mode) is missing ca.crt",
					ns, mat.SecretName, mat.BindingName,
				)
				return nil, metav1.ConditionFalse, tlsSecretIncompleteReason, message,
					fmt.Errorf("%s", message)
			}
			sdsCfg.CASecretName = mat.CASecretName
			sdsCfg.CAPEM = ca
		}

		// Render the per-binding SDS document with the cert/key (and CA for
		// mutual) embedded inline, so the whole secret is swapped atomically as a
		// single file and Envoy hot-reloads it without a restart.
		sdsDoc, sdsErr := render.RenderEnvoySDS(sdsCfg)
		if sdsErr != nil {
			message := fmt.Sprintf(
				"failed to render SDS document for binding %q from Secret %s/%s: %v",
				mat.BindingName, ns, mat.SecretName, sdsErr,
			)
			return nil, metav1.ConditionFalse, tlsSecretIncompleteReason, message, sdsErr
		}
		files = append(files, provision.TLSFile{Path: mat.SDSPath, Content: sdsDoc})
	}
	return files, metav1.ConditionTrue, "", "", nil
}

// mapSecretToEdgeNodes maps a Secret object to the set of EdgeNodes that must
// be reconciled when that Secret changes. It lists all PortBindings and returns
// a reconcile.Request for every EdgeNode whose bindings reference the Secret via
// a TLS SecretRef. This drives automatic certificate rotation: when cert-manager
// renews a Secret the affected EdgeNodes are re-enqueued and the new cert is
// pushed to the VPS without manual intervention.
//
// The function avoids reconcile loops by only matching Secrets that are actually
// referenced in a TLS SecretRef; unrelated Secrets are silently ignored.
func (r *EdgeNodeReconciler) mapSecretToEdgeNodes(ctx context.Context, obj client.Object) []reconcile.Request {
	secretName := obj.GetName()
	secretNamespace := obj.GetNamespace()

	var pbList v1alpha1.PortBindingList
	if err := r.List(ctx, &pbList); err != nil {
		// Losing this event silently would mean a missed certificate
		// rotation: the renewed Secret never reaches the VPS and the edge
		// keeps serving the old cert until something else re-enqueues the
		// node. The mapping cannot retry, so at minimum leave a trace.
		log.FromContext(ctx).Error(err, "failed to list PortBindings while mapping a Secret event; a TLS rotation may be missed",
			"secret", secretNamespace+"/"+secretName)
		return nil
	}

	seen := make(map[string]struct{})
	var requests []reconcile.Request

	for _, pb := range pbList.Items {
		for _, def := range pb.Spec.Bindings {
			if def.TLS == nil || def.TLS.SecretRef == nil {
				continue
			}
			ref := def.TLS.SecretRef
			refNS := ref.Namespace
			if refNS == "" {
				refNS = pb.Namespace
			}
			if ref.Name != secretName || refNS != secretNamespace {
				continue
			}
			// This PortBinding references the changed Secret.
			nodeName := pb.Spec.EdgeNodeRef.Name
			// EdgeNodeRef.Namespace defaults to the PortBinding namespace when
			// empty, mirroring mapPortBindingToEdgeNode so the enqueued request
			// targets the same EdgeNode the rest of the controller resolves.
			nodeNS := pb.Spec.EdgeNodeRef.Namespace
			if nodeNS == "" {
				nodeNS = pb.Namespace
			}
			key := nodeNS + "/" + nodeName
			if _, already := seen[key]; already {
				continue
			}
			seen[key] = struct{}{}
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      nodeName,
					Namespace: nodeNS,
				},
			})
		}
	}
	return requests
}

// mapPortBindingToEdgeNode maps a PortBinding event to a reconcile.Request for
// the EdgeNode it references. Create, spec-change and delete events all funnel
// through here, so the EdgeNodeReconciler rebuilds the aggregate plan from the
// live set of PortBindings without any cross-object write. An empty
// EdgeNodeRef.Namespace defaults to the PortBinding's namespace, matching the
// resolution used everywhere else in the controller. A missing ref name maps
// to nothing (the binding cannot be planned anyway).
func (r *EdgeNodeReconciler) mapPortBindingToEdgeNode(_ context.Context, obj client.Object) []reconcile.Request {
	pb, ok := obj.(*v1alpha1.PortBinding)
	if !ok {
		return nil
	}
	name := pb.Spec.EdgeNodeRef.Name
	if name == "" {
		return nil
	}
	ns := pb.Spec.EdgeNodeRef.Namespace
	if ns == "" {
		ns = pb.Namespace
	}
	return []reconcile.Request{{
		NamespacedName: types.NamespacedName{Name: name, Namespace: ns},
	}}
}

// appliedConfigHash combines the plan hash with the hash of the TLS material
// pushed alongside it, producing the value stored in
// EdgeNodeStatus.AppliedConfigHash. Folding the TLS hash in makes the status
// reflect certificate rotations: the SDS documents change the edge state even
// though the rendered plan artifacts stay identical.
func appliedConfigHash(planHash string, tlsFiles []provision.TLSFile) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(planHash+provision.HashTLSFiles(tlsFiles))))
}
