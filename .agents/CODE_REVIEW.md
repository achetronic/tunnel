# Code Review (hardening pass)

Full read-through of the Go codebase following call chains across packages to
separate real defects from things that only look suspicious. Scope: every
production file under `internal/`, `cmd/` and `api/v1alpha1/`. Branch:
`code-review-hardening`.

Severity legend:
- **CRITICAL** — real defect affecting correctness, reliability or security.
- **ROBUSTNESS** — genuine but lower-impact fragility.
- **NOTE** — worth knowing; left untouched on purpose (cosmetic or design call).
- **DISMISSED** — looked wrong at first, verified fine in context.

Verdict: the codebase is in good shape. Error handling is disciplined (no
`_ = err` in production code), SSH host-key verification is correct, IPAM bounds
and the agentconfig validators are solid, renders are deterministic (slices
sorted before hashing), and timeouts/contexts bound every remote command. Two
real defects were found and fixed; the rest are notes or dismissals.

---

## Fixed

### F1 — TLS certificate rotation was never picked up by Envoy (CRITICAL)
**Files:** `internal/provision/enroll.go` (`Enroll`, `applyEnvoyConfig`,
`ensureEnvoyRunning`), `internal/render/envoy.go:73-100`.

**What.** Edge TLS (`offload`/`mutual`) renders the listener with the cert/key
referenced by **filename** in the `DownstreamTlsContext`
(`certificate_chain.filename`, `private_key.filename`). Envoy reads those files
**only when the listener is (re)loaded**, not when the file content changes
underneath it (verified against the Envoy docs: file-based `tls_certificate`
needs SDS + `watched_directory` or a hot restart to refresh; a plain `filename`
is read once at load).

**Call-chain evidence.** On a cert-manager rotation: the Secret changes →
`mapSecretToEdgeNodes` enqueues the EdgeNode → `handleReconciliation` →
`planner.BuildPlan`. The rendered LDS/CDS depend only on the cert **paths**,
which do not change on rotation, so `EnvoyLDSHash`/`EnvoyCDSHash` are identical.
In `Enroll`, `applyTLSFiles` writes the new cert (and reports `tlsApplied=true`),
but `applyEnvoyConfig` sees unchanged hashes and skips the `mv` that would
retrigger Envoy's inotify reload, and `ensureEnvoyRunning` sees the service
already `active` and does **not** restart it. Net result: the new certificate
sits on disk while Envoy keeps serving the old one until it expires — a silent
outage of the TLS listener. The architecture doc claims rotation hot-reloads
automatically; it did not.

**Fix.** `applyEnvoyConfig` now returns whether it moved a discovery file and
`ensureEnvoyRunning` returns whether it (re)started the service. `Enroll`
restarts Envoy **only** when TLS material was (re)written this round AND neither
a config change nor a fresh start already reloaded it
(`tlsApplied && !envoyConfigChanged && !envoyStarted`). This keeps steady-state
reconciles from bouncing connections (the original goal) while guaranteeing a
rotated cert is actually served. Regression test:
`TestEnroll_TLSRotationRestartsEnvoy`.

**Trade-off / follow-up.** A cert-only rotation now causes one brief Envoy
restart, which drops the affected L4 connections momentarily. That is strictly
better than serving an expired cert, but it is not zero-downtime. The fully
graceful, Envoy-native alternative is to deliver the certs via **file-based SDS
with a `watched_directory`** (Envoy reloads the secret gracefully when the
directory is atomically swapped) instead of inline `filename` references. That
is a larger change to the render templates + bootstrap + enroll and is left as a
recommended future improvement rather than done here.

### F2 — `collectBindings` ignored the namespace (CRITICAL/correctness)
**File:** `internal/controller/edgenode_utils.go` (`collectBindings`), caller
`internal/controller/edgenode_sync.go:295`.

**What.** During EdgeNode reconciliation the aggregate plan is built from every
PortBinding whose `spec.edgeNodeRef.Name` matched — **by name only**, ignoring
the namespace entirely.

**Call-chain evidence.** The rest of the controller is namespace-aware and
treats `EdgeNodeRef.Namespace` (defaulting to the PortBinding's own namespace)
as part of the identity: `triggerEdgeNode` (portbinding_sync.go:48-51) and
`mapSecretToEdgeNodes` (edgenode_utils.go:444-451) both resolve and enqueue the
EdgeNode using that namespace. But `collectBindings` did not, so two EdgeNodes
that merely share a name in different namespaces would aggregate each other's
bindings: PortBindings (and their exposed ports + targets) from namespace A
would be rendered onto the VPS of the same-named EdgeNode in namespace B. In a
single-namespace deployment this never bites, but it is a real multi-tenant
correctness/isolation bug and an internal inconsistency.

**Fix.** `collectBindings` now takes the `*EdgeNode` and matches on both the
referenced name AND the resolved reference namespace
(`EdgeNodeRef.Namespace` or, when empty, the PortBinding's namespace) against
the node's namespace, mirroring the rest of the controller. Regression test:
`collectBindings namespace isolation`.

### F3 — Spanish leftover comments violated the English-only rule (cleanup)
**File:** `internal/planner/plan.go` (several `// Hallazgo #N: ...` comments).

These were stale Spanish review annotations referencing a defunct numbering.
They violate DESIGN_AND_RULES §5 ("English Only"). Rewritten to equivalent
English comments. No logic change. (Done because it is an explicit project rule
and trivial; purely cosmetic English/Spanish drift elsewhere was left alone.)

---

## Notes (intentionally not changed)

### N1 — Orphaned TLS key material after a binding is removed (ROBUSTNESS/hygiene)
`applyTLSFiles` writes/refreshes cert/key files under `/etc/envoy/tls/` but never
prunes files for bindings that were deleted; only full `Teardown` wipes
`/etc/envoy`. After removing a TLS binding the LDS no longer references the old
cert (so Envoy won't use it), but the private key lingers on the edge until the
node is torn down. Given the design treats key-on-edge as sensitive, pruning the
`tls/` dir to exactly the current materials would be tidier. Low severity (no
functional impact, key is unreferenced); left as a deliberate follow-up rather
than risk changing the apply path in this pass.

### N2 — `agentrun.Run` does not observe its `ctx` for shutdown (NOTE)
`Run(ctx, ...)` starts `watchConfig` and `srv.ListenAndServe()` but never uses
`ctx` to stop the HTTP server or the watcher; it returns only on a server error.
For the uplink daemon this is harmless (the container is killed on SIGTERM and
the process exits), so it is a graceful-shutdown nicety, not a leak that matters
in practice. Left as-is.

### N3 — Direct-address target requires a port only at runtime (NOTE)
CEL on PortBinding enforces "exactly one of service/address" but does not require
`target.port` when `address` is used (the field is an optional non-pointer int,
so an omitted value serializes as absent and dodges the `Minimum=1` marker).
`planner.resolveTarget` catches `port <= 0` at reconcile time
(`PlanBuildFailed`), so it is defense-in-depth rather than a hole. Acceptable;
could be tightened with a CEL rule if desired.

### N4 — `installEnvoyBinary` downloads without checksum verification (NOTE)
The Envoy binary is fetched over HTTPS from the official GitHub releases with no
post-download SHA verification. The transport is TLS and the design explicitly
chose direct download, so this is consistent with the stated approach; adding a
pinned checksum per version would be a hardening improvement but is out of scope.

---

## Dismissed (looked suspicious, verified fine)

- **D1 — `buildUplinkDocument` marshals without `Validate()`** while the relay
  document validates. Intentional and documented: the uplink template
  deliberately leaves `Interface.PrivateKey`/`Address` empty for the runtime to
  inject per-replica (via `agentconfig.Decode` + transforms) and validate before
  applying. `agentconfig.Validate` would reject the empty fields, so validating
  here would be wrong. Fine.
- **D2 — IPAM only varies the last octet** (`ReplicaIP`/`RelayIP`). For the
  default `/24` it is exact; for other prefixes it is bounded by
  `prefix.Contains` and the `>254` guard, returning a clear error rather than a
  wrong address. Networks whose base `.1` falls outside the prefix are rejected
  up front. Correct, if conservative.
- **D3 — `knownHostsCallback` accepts any pinned key regardless of host pattern.**
  It compares the presented key against all parsed entries. Because the
  known_hosts blob is per-EdgeNode (one host), this is equivalent to
  host-scoped matching and not a downgrade. Host-key verification is on by
  default and only skippable via the explicit `insecureSkipHostKeyVerification`.
  Fine.
- **D4 — `Run` discards stdout on a non-zero exit** (returns `""` + error).
  Callers that need the output on failure (`readState`, health probes) classify
  via `isExitError` and read what they need; the relay/health JSON is produced
  on the success path or tolerated as not-ready. Fine.
- **D5 — restart-envoy annotation consumed before the restart runs.** If enroll
  fails after the annotation is deleted, the one-shot request is "lost". This is
  the documented trade-off (consume-with-finalizer before any status write to
  avoid clobbering status); acceptable by design.
- **D6 — `ensureEnvoyRunning` re-Puts the static bootstrap every reconcile.**
  Content is constant and Envoy does not watch the bootstrap; no restart unless
  inactive. Harmless.
- **D7 — determinism.** All renders/plans sort slices before hashing
  (`sortEnvoyConfig`, `sortNftRules`, `collectBindingDefs`, `buildTLSMaterials`,
  `hashTLSFiles`); no map iteration leaks into output. Confirmed deterministic.
- **D8 — CEL markers vs documented invariants.** The four `XValidation` rules on
  PortBinding correctly enforce: TCP/UDP param coherence, exactly one of
  service/address, TLS only on TCP, and `secretRef` required for
  offload/mutual. They match ARCHITECTURE §3.2.

---

## Validation
- `go build ./...` — clean.
- `go vet ./...` — clean.
- `gofmt -l internal/` — clean.
- `golangci-lint run` on changed packages — 0 issues.
- Full unit + envtest suite (`go test $(go list ./... | grep -v /e2e)`) — green,
  including the two new regression tests.
