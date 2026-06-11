# Code Review (hardening pass) — outstanding items

Full read-through of the Go codebase (every production file under `internal/`,
`cmd/` and `api/v1alpha1/`), following call chains across packages to separate
real defects from things that only look suspicious.

The defects found were fixed and committed on branch `code-review-hardening`
(see `git log` for the details and rationale of each): edge TLS now rotates via
file-based SDS with zero downtime, PortBinding aggregation is namespace-scoped,
orphaned TLS material is pruned from the edge, and the stray non-English
comments were cleaned up. This document now tracks only what is **not** done:
low-priority notes left untouched on purpose, and findings that were dismissed
after verification (kept for context so they are not re-investigated).

General verdict stands: the codebase is in good shape. Error handling is
disciplined (no `_ = err` in production code), SSH host-key verification is
correct, IPAM bounds and the agentconfig validators are solid, renders are
deterministic (slices sorted before hashing), and timeouts/contexts bound every
remote command.

---

## Outstanding notes (intentionally not changed)

### N1 — `agentrun.Run` does not observe its `ctx` for shutdown
`Run(ctx, ...)` starts `watchConfig` and `srv.ListenAndServe()` but never uses
`ctx` to stop the HTTP server or the watcher; it returns only on a server error.
For the uplink daemon this is harmless (the container is killed on SIGTERM and
the process exits), so it is a graceful-shutdown nicety, not a leak that matters
in practice. Left as-is.

### N2 — Direct-address target requires a port only at runtime
CEL on PortBinding enforces "exactly one of service/address" but does not require
`target.port` when `address` is used (the field is an optional non-pointer int,
so an omitted value serializes as absent and dodges the `Minimum=1` marker).
`planner.resolveTarget` catches `port <= 0` at reconcile time
(`PlanBuildFailed`), so it is defense-in-depth rather than a hole. Acceptable;
could be tightened with a CEL rule if desired.

### N3 — `installEnvoyBinary` downloads without checksum verification
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
