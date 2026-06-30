// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

// This file holds API types shared by more than one Kind in this group. Types
// that belong to a single Kind live next to it (edgenode_types.go,
// portbinding_types.go); anything referenced by two or more Kinds is collected
// here so its shared nature is explicit.
package v1alpha1

// SecretReference is a minimal, namespace-aware reference to a Secret. It is
// shared by several Kinds: EdgeNode uses it for the SSH credentials Secret and
// PortBinding uses it for the TLS material Secret. When the namespace is omitted
// the operator resolves it against the owning resource's namespace.
type SecretReference struct {
	// Name is the Secret name.
	// +kubebuilder:validation:MinLength=1
	// +required
	Name string `json:"name"`

	// Namespace is the Secret namespace. Defaults to the owner's namespace when empty.
	// +optional
	Namespace string `json:"namespace,omitempty"`
}
