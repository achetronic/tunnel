// SPDX-FileCopyrightText: 2026 Alby Hernández (Achetronic)
// SPDX-License-Identifier: Apache-2.0

package controller

// portBindingFinalizer may be present on PortBindings in the cluster. Nothing
// adds it: deletion visibility is guaranteed by the EdgeNodeReconciler's
// direct watch on PortBindings, which enqueues the referenced EdgeNode on
// delete events and re-renders the plan without the removed listeners. The
// reconciler removes the finalizer from any object that carries it so such
// PortBindings are never stuck in Terminating.
const portBindingFinalizer = "tunnel.achetronic.com/portbinding-finalizer"
