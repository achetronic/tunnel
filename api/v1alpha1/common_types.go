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
