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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TargetServiceRef points to a Kubernetes Service that will receive the
// forwarded traffic. All three fields are required: an empty name or namespace
// produces an unresolvable reference, and a port outside 1-65535 is invalid at
// the OS level.
// Ref: https://book.kubebuilder.io/reference/markers/crd-validation
type TargetServiceRef struct {
	// Name is the name of the target Service.
	// +kubebuilder:validation:MinLength=1
	// +required
	Name string `json:"name"`

	// Namespace is the namespace of the target Service.
	// +kubebuilder:validation:MinLength=1
	// +required
	Namespace string `json:"namespace"`

	// Port is the port number on the target Service to forward traffic to.
	// Must be a valid TCP/UDP port number (1-65535).
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +required
	Port int32 `json:"port"`
}

// BindingTarget is the destination of a PortBinding. Exactly one of Service or
// Address must be set; the CEL validation rule on PortBinding enforces mutual
// exclusivity at admission time.
type BindingTarget struct {
	// Service points to an in-cluster Service. The operator resolves it to its
	// current ClusterIP.
	// +optional
	Service *TargetServiceRef `json:"service,omitempty"`

	// Address is a raw IP address (e.g. 10.244.3.17) to forward traffic to.
	// +optional
	Address string `json:"address,omitempty"`

	// Port is required when Address is used. Must be a valid TCP/UDP port
	// number (1-65535).
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +optional
	Port int32 `json:"port,omitempty"`
}

// TCPParams holds TCP-specific configuration for the proxy.
type TCPParams struct {
	// ProxyProtocol enables proxy_protocol v1 towards the target.
	// +kubebuilder:default=false
	// +optional
	ProxyProtocol bool `json:"proxyProtocol,omitempty"`

	// ConnectTimeout is the proxy connect timeout (e.g. "5s").
	// +kubebuilder:default="5s"
	// +optional
	ConnectTimeout string `json:"connectTimeout,omitempty"`

	// IdleTimeout is the proxy idle timeout for TCP sessions (e.g. "1h").
	// +kubebuilder:default="1h"
	// +optional
	IdleTimeout string `json:"idleTimeout,omitempty"`
}

// UDPParams holds UDP-specific configuration for the proxy.
type UDPParams struct {
	// SessionTimeout is the proxy idle timeout for UDP sessions. Must be
	// greater than the keepalive of the transported protocol (e.g. "60s").
	// +kubebuilder:default="60s"
	// +optional
	SessionTimeout string `json:"sessionTimeout,omitempty"`
}

// TLSConfig holds TLS termination settings for a TCP binding. Three modes are
// supported:
//
//   - passthrough: Envoy routes traffic by SNI without decrypting it. The
//     private key never leaves the cluster. No Secret is needed on the VPS.
//
//   - offload: Envoy terminates TLS on the VPS. The operator reads tls.crt
//     and tls.key from the referenced Secret (type kubernetes.io/tls).
//
//   - mutual: Same as offload plus mTLS client-certificate verification.
//     The operator additionally reads ca.crt from the referenced Secret to
//     validate the client chain.
//
// Ref: https://book.kubebuilder.io/reference/markers/crd-validation
type TLSConfig struct {
	// Mode selects how TLS is handled for this binding.
	// passthrough routes by SNI without decrypting; offload terminates TLS on
	// the VPS using tls.crt and tls.key from the Secret; mutual adds
	// client-certificate verification using ca.crt from the Secret.
	// +kubebuilder:validation:Enum=passthrough;offload;mutual
	// +required
	Mode string `json:"mode"`

	// SecretRef points to a kubernetes.io/tls Secret from which the operator
	// reads credentials according to the selected mode:
	//   - offload: reads tls.crt and tls.key
	//   - mutual:  reads tls.crt, tls.key, and ca.crt
	//   - passthrough: field is ignored; the private key stays in the cluster
	// The CEL rule on PortBinding enforces that secretRef is present when mode
	// is offload or mutual.
	// +optional
	SecretRef *SecretReference `json:"secretRef,omitempty"`
}

// PortBindingDefinition defines one exposed port and its routing.
type PortBindingDefinition struct {
	// Name is a unique identifier for this binding within the PortBinding CR.
	// It keys the Envoy listener and the per-binding SDS document path on the
	// VPS, so it is constrained to a DNS-1123 label: lowercase alphanumerics
	// and dashes, no slashes or dots, which would otherwise break the on-disk
	// SDS path and the rendered config.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	// +kubebuilder:validation:MaxLength=63
	// +required
	Name string `json:"name"`

	// Protocol is TCP or UDP.
	// +kubebuilder:validation:Enum=TCP;UDP
	// +required
	Protocol string `json:"protocol"`

	// ListenPort is the public port exposed on the VPS. Must be unique across
	// all bindings of the same host.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +required
	ListenPort int32 `json:"listenPort"`

	// TCP holds parameters specific to TCP bindings. Only valid if Protocol is TCP.
	// +optional
	TCP *TCPParams `json:"tcp,omitempty"`

	// UDP holds parameters specific to UDP bindings. Only valid if Protocol is UDP.
	// +optional
	UDP *UDPParams `json:"udp,omitempty"`

	// TLS holds optional TLS configuration for this binding. Only valid when
	// Protocol is TCP. The CEL rules on PortBinding reject TLS on UDP bindings
	// and require secretRef when mode is offload or mutual.
	// +optional
	TLS *TLSConfig `json:"tls,omitempty"`

	// Target is where the traffic is forwarded after exiting the tunnel.
	// +required
	Target BindingTarget `json:"target"`
}

// ObjectReference points to the EdgeNode that owns this PortBinding. The Name
// field is mandatory; without a valid non-empty name the PortBindingReconciler
// cannot resolve the target EdgeNode.
type ObjectReference struct {
	// Name is the name of the referenced EdgeNode. Must be a non-empty string.
	// +kubebuilder:validation:MinLength=1
	// +required
	Name string `json:"name"`

	// Namespace is the namespace of the referenced EdgeNode. Defaults to the
	// PortBinding namespace when omitted.
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// PortBindingSpec defines the desired state of PortBinding.
type PortBindingSpec struct {
	// EdgeNodeRef points to the EdgeNode where these ports will be exposed.
	// +required
	EdgeNodeRef ObjectReference `json:"edgeNodeRef"`

	// Bindings is the list of ports to expose and their targets.
	// +listType=map
	// +listMapKey=name
	// +required
	Bindings []PortBindingDefinition `json:"bindings"`
}

// PortBindingStatus defines the observed state of PortBinding.
type PortBindingStatus struct {
	// ObservedGeneration is the .metadata.generation of the PortBinding spec
	// that was last processed by the reconciler. Consumers (GitOps tooling,
	// dependent controllers) use this field to detect whether the current
	// status reflects the latest desired state or still corresponds to a
	// previous generation. The reconciler must set this to
	// portBinding.Generation before calling Status().Update().
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions represent the current state of the PortBinding. The Ready
	// condition is set to True once the corresponding EdgeNode has accepted
	// and applied all bindings declared in this CR.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=pb
// +kubebuilder:printcolumn:name="Node",type=string,JSONPath=`.spec.edgeNodeRef.name`
// +kubebuilder:printcolumn:name="ObservedGen",type=integer,JSONPath=`.status.observedGeneration`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:validation:XValidation:rule="self.spec.bindings.all(b, (b.protocol == 'TCP' ? !has(b.udp) : !has(b.tcp)))",message="Protocol TCP cannot have UDP params and vice-versa"
// +kubebuilder:validation:XValidation:rule="self.spec.bindings.all(b, (has(b.target.service) ? !has(b.target.address) : has(b.target.address)))",message="Target must have either Service or Address, not both"
// +kubebuilder:validation:XValidation:rule="self.spec.bindings.all(b, !has(b.tls) || b.protocol == 'TCP')",message="TLS configuration is only valid for TCP protocol"
// +kubebuilder:validation:XValidation:rule="self.spec.bindings.all(b, !has(b.tls) || b.tls.mode == 'passthrough' || has(b.tls.secretRef))",message="tls.secretRef is required when mode is offload or mutual"

// PortBinding is the Schema for the portbindings API. It declares which ports to
// expose on an EdgeNode and where to route them in the cluster.
type PortBinding struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec defines the desired state of PortBinding
	// +required
	Spec PortBindingSpec `json:"spec"`

	// status defines the observed state of PortBinding
	// +optional
	Status PortBindingStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PortBindingList contains a list of PortBinding.
type PortBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PortBinding `json:"items"`
}

// init registers PortBinding and PortBindingList with the SchemeBuilder.
func init() {
	SchemeBuilder.Register(&PortBinding{}, &PortBindingList{})
}
