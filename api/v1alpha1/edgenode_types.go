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

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SSHSpec describes how the operator reaches the VPS over SSH. Credentials are
// always provided through a referenced Secret (keys: password | privateKey,
// plus an optional passphrase); they are never inlined in the CR.
type SSHSpec struct {
	// Port is the TCP port where the VPS SSH daemon listens.
	// +kubebuilder:default=22
	// +optional
	Port int32 `json:"port,omitempty"`

	// User is the SSH login used to enroll and manage the VPS.
	// +kubebuilder:default=root
	// +optional
	User string `json:"user,omitempty"`

	// SecretRef points to the Secret holding the SSH credentials. The Secret is
	// expected to carry a "password" or a "privateKey" entry (and optionally a
	// "passphrase" for an encrypted private key). It may also carry a
	// "knownHosts" entry (OpenSSH known_hosts format, e.g. the output of
	// "ssh-keyscan") used to verify the VPS host key.
	// +required
	SecretRef SecretReference `json:"secretRef"`

	// ConnectTimeout bounds how long the operator waits to establish the SSH
	// connection to the VPS (e.g. "30s"). It prevents a reconcile worker from
	// blocking indefinitely on an unreachable host.
	// +kubebuilder:default="30s"
	// +optional
	ConnectTimeout string `json:"connectTimeout,omitempty"`

	// InsecureSkipHostKeyVerification disables SSH host key verification. When
	// false (the default) the operator requires a "knownHosts" entry in the
	// referenced Secret and refuses to connect to a host whose key does not
	// match, protecting the enrollment channel from man-in-the-middle attacks.
	// +kubebuilder:default=false
	// +optional
	InsecureSkipHostKeyVerification bool `json:"insecureSkipHostKeyVerification,omitempty"`
}

// TunnelNetworkSpec configures the WireGuard relay transport that lives on the
// VPS. The relay owns the .1 address of the network; uplink replicas take
// .2 + ordinal (see internal/ipam).
type TunnelNetworkSpec struct {
	// ListenPort is the UDP port where the VPS WireGuard relay listens for the
	// tunnels initiated by the cluster.
	// +kubebuilder:default=51821
	// +optional
	ListenPort int32 `json:"listenPort,omitempty"`

	// Network is the CIDR of the tunnel overlay. ".1" is the VPS relay and
	// ".2 + ordinal" is each uplink replica.
	// +kubebuilder:default="10.200.0.0/24"
	// +optional
	Network string `json:"network,omitempty"`

	// MTU is the Maximum Transmission Unit for the WireGuard interfaces on both
	// the VPS and the cluster. Defaults to 1420 (standard for internet transport).
	// +kubebuilder:default=1420
	// +optional
	MTU int32 `json:"mtu,omitempty"`

	// PersistentKeepalive specifies the interval in seconds between WireGuard
	// keepalive packets sent by the uplink to keep stateful firewalls/NATs open.
	// Defaults to 25.
	// +kubebuilder:default=25
	// +optional
	PersistentKeepalive int32 `json:"persistentKeepalive,omitempty"`
}

// UplinkSpec configures the in-cluster side of the tunnel: the StatefulSet of
// uplink replicas that terminate the WireGuard tunnels and apply the DNAT table.
type UplinkSpec struct {
	// Namespace is where the uplink StatefulSet, ConfigMap and Secrets are created.
	// Immutable: changing it after creation would make teardown look in the new
	// namespace and orphan the resources already created in the old one.
	// +kubebuilder:default="tunnel"
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="uplink.namespace is immutable"
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// Replicas is the number of active-active uplink peers. Each replica is an
	// independent WireGuard peer claiming its own /32.
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	// +optional
	Replicas int32 `json:"replicas,omitempty"`

	// Labels are added to the uplink Pods.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations are added to the uplink Pods.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Resources define the compute resource requirements for the uplink container.
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// NodeSelector defines which nodes the uplink pods can be scheduled on.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations allow the uplink pods to be scheduled on tainted nodes.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// Affinity allows defining advanced scheduling rules for the uplink pods.
	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`
}

// EdgeSpec configures the VPS-side edge proxy (Envoy): how it health checks the
// uplink replicas and fails over between them. The whole block is optional; when
// omitted the operator applies sane defaults.
type EdgeSpec struct {
	// HealthCheck tunes the active health checks Envoy runs against each uplink
	// replica's readiness endpoint.
	// +optional
	HealthCheck HealthCheckSpec `json:"healthCheck,omitempty"`
}

// HealthCheckSpec configures the active health checks the VPS Envoy performs
// against each uplink replica. Envoy probes the replica readiness endpoint and
// only load-balances traffic onto replicas that pass, so a replica whose tunnel
// is down stops receiving traffic instead of black-holing it.
type HealthCheckSpec struct {
	// Interval is the time between probes, in Envoy duration format (e.g. "5s").
	// +kubebuilder:default="5s"
	// +optional
	Interval string `json:"interval,omitempty"`

	// Timeout is how long each probe may take before it counts as a failure
	// (e.g. "2s").
	// +kubebuilder:default="2s"
	// +optional
	Timeout string `json:"timeout,omitempty"`

	// HealthyThreshold is the number of consecutive successful probes required
	// before a replica is put back into rotation.
	// +kubebuilder:default=2
	// +kubebuilder:validation:Minimum=1
	// +optional
	HealthyThreshold int32 `json:"healthyThreshold,omitempty"`

	// UnhealthyThreshold is the number of consecutive failed probes required
	// before a replica is taken out of rotation.
	// +kubebuilder:default=2
	// +kubebuilder:validation:Minimum=1
	// +optional
	UnhealthyThreshold int32 `json:"unhealthyThreshold,omitempty"`
}

// EdgeNodeSpec defines the desired state of a EdgeNode: a single VPS acting
// as a public relay plus the in-cluster uplink that terminates its tunnels.
type EdgeNodeSpec struct {
	// Address is the public IP (or hostname) of the VPS.
	// +required
	Address string `json:"address"`

	// SSH holds the connection details used to enroll and manage the VPS.
	// +required
	SSH SSHSpec `json:"ssh"`

	// Edge configures the VPS-side edge proxy: how it health checks the uplink
	// replicas and fails over between them. Optional; sane defaults apply.
	// +optional
	Edge EdgeSpec `json:"edge,omitempty"`

	// Tunnel configures the WireGuard relay transport.
	// +optional
	Tunnel TunnelNetworkSpec `json:"tunnel,omitempty"`

	// Uplink configures the in-cluster uplink StatefulSet.
	// +optional
	Uplink UplinkSpec `json:"uplink,omitempty"`
}

// UplinkStatus reports the observed state of a single uplink replica, keyed by
// its StatefulSet ordinal. It mirrors what "wg show" reports on the VPS relay.
type UplinkStatus struct {
	// Ordinal is the StatefulSet ordinal of the replica (0-based).
	Ordinal int32 `json:"ordinal"`

	// TunnelIP is the overlay address assigned to this replica.
	TunnelIP string `json:"tunnelIP"`

	// PublicKey is the WireGuard public key of this replica's keypair.
	PublicKey string `json:"publicKey"`

	// LastHandshake is the timestamp of the most recent successful handshake
	// as observed on the VPS relay. Empty means no handshake yet.
	// +optional
	LastHandshake *metav1.Time `json:"lastHandshake,omitempty"`
}

// EdgeNodeStatus defines the observed state of a EdgeNode.
type EdgeNodeStatus struct {
	// ObservedGeneration is the .metadata.generation of the EdgeNode spec that
	// was last processed by the reconciler. Consumers (GitOps tooling, dependent
	// controllers) use this field to detect whether the current status reflects
	// the latest desired state or still corresponds to a previous generation.
	// The reconciler must set this to node.Generation before calling
	// Status().Update().
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions represent the current state of the EdgeNode. Standard types
	// are: Enrolled, TunnelEstablished, ConfigSynced and Ready.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// PublicKey is the WireGuard public key of the VPS relay. The matching
	// private key is generated on the VPS and never leaves it.
	// +optional
	PublicKey string `json:"publicKey,omitempty"`

	// Uplink is the per-replica observed state.
	// +listType=map
	// +listMapKey=ordinal
	// +optional
	Uplink []UplinkStatus `json:"uplink,omitempty"`

	// AppliedConfigHash is the SHA-256 of the last successfully applied plan
	// (relay + proxy + nft). It is the anchor used for drift detection.
	// +optional
	AppliedConfigHash string `json:"appliedConfigHash,omitempty"`

	// AppliedBindings lists the PortBindings (as namespace/name) whose
	// definitions are materialized in the last successfully applied plan.
	// The PortBindingReconciler watches this field to set each binding's
	// Ready condition honestly: present here means the port is actually
	// programmed on the edge, not merely requested.
	// +listType=set
	// +optional
	AppliedBindings []string `json:"appliedBindings,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=en
// +kubebuilder:printcolumn:name="Address",type=string,JSONPath=`.spec.address`
// +kubebuilder:printcolumn:name="Replicas",type=integer,JSONPath=`.spec.uplink.replicas`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="ObservedGen",type=integer,JSONPath=`.status.observedGeneration`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// EdgeNode is the Schema for the edgenodes API. It models one VPS relay and
// its in-cluster uplink. The EdgeNodeReconciler is the single writer over the
// machine and over the uplink workload.
type EdgeNode struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec defines the desired state of EdgeNode.
	// +required
	Spec EdgeNodeSpec `json:"spec"`

	// status defines the observed state of EdgeNode.
	// +optional
	Status EdgeNodeStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// EdgeNodeList contains a list of EdgeNode.
type EdgeNodeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EdgeNode `json:"items"`
}

// init registers EdgeNode and EdgeNodeList with the SchemeBuilder.
func init() {
	SchemeBuilder.Register(&EdgeNode{}, &EdgeNodeList{})
}
