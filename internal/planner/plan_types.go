// Package planner computes the complete desired state (Plan) for a VPS relay
// and its uplink replicas from a v1alpha1.EdgeNode and a set of PortBindings.
// It is a pure computation package: no IO, no Kubernetes client calls.
package planner

import (
	"crypto/sha256"
	"fmt"
)

// TargetResolver abstracts the resolution of Kubernetes Services to ClusterIPs.
// The planner calls it for every PortBindingDefinition whose target is a Service
// reference, keeping the package free of direct Kubernetes client dependencies.
type TargetResolver interface {
	// ResolveService returns the ClusterIP of the named service, or an error
	// if the service does not exist or has no usable ClusterIP.
	ResolveService(namespace, name string) (string, error)
}

// TLSMaterial describes one binding's TLS credential requirements that the
// controller must satisfy before enrollment. The planner populates this list
// only for offload and mutual modes; passthrough never pushes key material to
// the VPS so it does not appear here.
//
// The controller reads the referenced Secret and renders a single SDS document
// per binding at SDSPath, embedding the cert/key (and CA for mutual) inline. The
// listener references those secrets by CertSecretName/CASecretName via file-based
// SDS, so a rotation is an atomic swap of one file that Envoy hot-reloads.
//
// Path/name convention (per-binding, not shared):
//
//	/etc/envoy/tls/<bindingName>.sds.yaml - SDS document (cert/key inline, +CA for mutual)
//	secret name <bindingName>             - server certificate/key
//	secret name <bindingName>-ca          - client-CA validation context (mutual only)
//
// Using per-binding files avoids collisions when multiple bindings rotate
// certificates independently.
type TLSMaterial struct {
	// BindingName is the name of the PortBindingDefinition this entry belongs to.
	BindingName string
	// SecretName is the name of the kubernetes.io/tls Secret to read.
	SecretName string
	// SecretNamespace is the namespace of the Secret. It follows the same
	// defaulting convention as the rest of the operator: empty means the
	// controller should use the PortBinding or EdgeNode namespace.
	SecretNamespace string
	// Mode is the TLS mode: offload or mutual.
	Mode string
	// SDSPath is the destination path on the VPS for the binding's SDS document.
	SDSPath string
	// CertSecretName is the SDS resource name for the server certificate/key.
	CertSecretName string
	// CASecretName is the SDS resource name for the CA validation context.
	// Only set when Mode is mutual; empty otherwise.
	CASecretName string
}

// Plan is the complete desired state for the VPS and its uplink replicas.
// Each field is a ready-to-deploy artifact produced deterministically from
// the same EdgeNode + PortBinding inputs.
type Plan struct {
	// EnvoyLDS is the rendered Envoy Listener Discovery Service YAML.
	EnvoyLDS []byte
	// EnvoyCDS is the rendered Envoy Cluster Discovery Service YAML.
	EnvoyCDS []byte

	// EnvoyLDSHash is the hex-encoded SHA-256 of EnvoyLDS.
	EnvoyLDSHash string
	// EnvoyCDSHash is the hex-encoded SHA-256 of EnvoyCDS.
	EnvoyCDSHash string

	// RelayDocument is the tunnelctl desired-state JSON for the VPS relay,
	// applied natively by tunnelctl over SSH (WireGuard via netlink).
	RelayDocument []byte
	// RelayDocumentHash is the hex-encoded SHA-256 of RelayDocument.
	RelayDocumentHash string

	// UplinkDocument is the tunnelctl desired-state JSON shared by every uplink
	// replica (WireGuard + nftables). Interface.PrivateKey and Interface.Address
	// are intentionally empty: the uplink agent injects them at runtime from its
	// mounted key Secret and ordinal, then validates and applies.
	UplinkDocument []byte
	// UplinkDocumentHash is the hex-encoded SHA-256 of UplinkDocument.
	UplinkDocumentHash string

	// PlanHash is the hex-encoded SHA-256 over the artifacts actually applied to
	// a node (relay document, uplink document, Envoy LDS and CDS). It uniquely
	// identifies the full desired state and backs EdgeNode.status.appliedConfigHash.
	PlanHash string

	// TLSMaterials lists the TLS credential requirements for every binding that
	// needs key material pushed to the VPS (offload and mutual modes). It is
	// sorted by BindingName for deterministic output. Passthrough bindings are
	// absent because they never push a private key to the edge.
	TLSMaterials []TLSMaterial

	// EnvoyVersion is the Envoy release to install on the VPS. It is an
	// install-time input set by the controller from the manager's --envoy-version
	// flag (not derived from the EdgeNode/PortBindings), so it does not feed any
	// of the hashes above.
	EnvoyVersion string

	// TunnelctlDir is the local directory the controller reads the static
	// tunnelctl binaries from (tunnelctl-linux-<arch>) to push to the VPS over
	// SSH. Like EnvoyVersion it is an install-time input set by the controller
	// from the manager's --tunnelctl-dir flag, so it does not feed any of the hashes.
	TunnelctlDir string
}

// hashBytes returns the hex-encoded SHA-256 digest of b.
func hashBytes(b []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(b))
}
