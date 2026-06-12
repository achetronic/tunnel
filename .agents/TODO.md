# Future Work & Pending Tasks (TODO)

This document tracks pending architectural improvements and technical debt.

## 1. Migrate off the deprecated controller-runtime events API
- **Context:** `internal/controller/edgenode_controller.go` uses `mgr.GetEventRecorderFor` with a `record.EventRecorder` field.
- **Task:** Migrate to the new events API (`mgr.GetEventRecorder` returning `events.EventRecorder`) and rewrite every `.Event()` call to `Eventf` with the regarding/related/action signature.
- **When:** Only once controller-runtime announces actual removal of the classic API; today it is still supported and the migration touches every event call site for no functional gain.

## 2. Optional passive outlier detection on the Envoy upstreams
- **Context:** Envoy already active-health-checks each uplink's `/ready` (`spec.edge.healthCheck`), so a downed replica is ejected after roughly `interval * unhealthyThreshold` (~10s with the defaults). During that detection window new connections round-robined onto the just-failed replica still fail (connect timeout or RST).
- **Task:** Add optional passive ejection (`outlier_detection` in the CDS cluster) so a replica is dropped on the first real connection failures, without waiting for the active-check threshold. Tuneable from a new `spec.edge.outlierDetection` block (`enabled`, `consecutiveFailures`, `ejectionDuration`), off by default, defaults applied in the planner like `healthCheck`.
- **When:** Only if the ~10s window during a single-uplink failure proves too painful in practice. Active health checks already cover the steady state and the all-down case (`healthy_panic_threshold` is hard-coded to 0 for fast failure); this only tightens the transient. Keep it out of scope until there is a real need, to avoid the flapping and tuning surface it adds.

## 3. Let `tunnelctl` also apply the Envoy config
- **Context:** On the edge, Envoy LDS/CDS are pushed as files that Envoy hot-reloads on its own. Today the operator writes them over SSH, separately from the WireGuard document that `tunnelctl` applies.
- **Task:** Add an optional `envoy` section to the `tunnelctl` desired-state document (the rendered LDS/CDS) so `apply` writes those files atomically and `status` reports Envoy health (active + loaded config hash) alongside WireGuard. One `apply`/`status` per node, with the symmetry `wireguard` + routing (`envoy` on the edge, `nftables` on the uplink).
- **Boundary:** `tunnelctl` applies config only. Installing the Envoy binary, the immutable bootstrap and the systemd unit stay in the operator enroll (one-time host setup tied to `--envoy-version`).
- **When:** The WireGuard + nftables document already ships and is applied natively by `tunnelctl`; this extends the same document with the Envoy section.

## 4. Userspace WireGuard fallback (wireguard-go / boringtun) for hosts without the kernel module
- **Context:** `tunnelctl` programs WireGuard through the kernel module. Hosts without it (OpenVZ/LXC "VPS", very old or minimal kernels) cannot bring the interface up.
- **Task:** When the kernel module is absent, fall back to a userspace data plane (`wireguard-go`, or `boringtun` if it benchmarks better) shipped as a static binary like `tunnelctl`. The `wgctrl` configuration path is unchanged (same UAPI), so only interface creation/teardown differs behind the existing backend seam in `internal/wg`. Note this fallback IS a genuine resident daemon on the host (the userspace data plane), unlike the kernel path.
- **Does NOT change privileges:** userspace WireGuard still needs `CAP_NET_ADMIN` (creating the TUN via `/dev/net/tun` + `TUNSETIFF`, and the address/MTU/up/route netlink calls that are shared with the kernel backend). It only removes the kernel-module dependency, not the root/cap requirement (see item 5).
- **When:** Choose wireguard-go vs boringtun by performance.

## 5. Run the uplink without root (CAP_NET_ADMIN via file capabilities)
- **Context:** The uplink container runs as root (`gcr.io/distroless/static:latest`) because creating the WireGuard link and programming nftables go through netlink, which needs an effective `CAP_NET_ADMIN`. A non-root uid does not get caps in its effective set even in a privileged pod (we hit `operation not permitted` with the `:nonroot` image), so root is the simple path today.
- **Task:** Drop root (and ideally `privileged`) by giving the binary file capabilities: `setcap cap_net_admin+ep /usr/local/bin/uplink` in `Dockerfile.uplink`, run as a non-root uid, and add `securityContext.capabilities.add: [NET_ADMIN]` (the bounding set the file cap is raised into). This is independent of the WireGuard backend (works for the kernel path and item 4's userspace path; the latter also needs `/dev/net/tun` mounted). Kubernetes ambient capabilities would be the cleaner mechanism but are still alpha/poorly exposed, so file caps are the pragmatic route.
- **When:** Only if running the data-plane pod as root/privileged becomes a real concern (hardened clusters, PSA `restricted`). Not urgent.

## 6. Verify the downloaded Envoy binary against a known checksum
- **Context:** `provision.installEnvoyBinary` downloads the Envoy release over HTTPS from the official GitHub releases and runs it with no integrity check beyond TLS. A compromised mirror/redirect, a truncated download or a corrupted artifact would be installed and started as the sole public-facing process on the VPS.
- **Task:** Pin the expected SHA-256 per `--envoy-version` (a small embedded map, or a sidecar `.sha256` fetched from the same release and verified) and have the install command compute and compare the digest before the atomic `mv` into `/usr/local/bin/envoy`; fail the enroll loudly on mismatch. Keep it arch-aware (amd64/arm64 differ).
- **When:** Worth doing as supply-chain hardening; the edge binary is security-sensitive. Low effort once the per-version digests are tracked alongside `DefaultEnvoyVersion`.

## 7. Reject a direct-address PortBinding target without a port at admission
- **Context:** The CRD CEL rules enforce "exactly one of `target.service` / `target.address`" but cannot require `target.port` when `address` is used: `port` is an optional non-pointer int, so an omitted value serialises as absent and slips past the `Minimum=1` marker. `planner.resolveTarget` then rejects `port <= 0` at reconcile time, surfacing as `PlanBuildFailed` on the EdgeNode rather than as a clear admission error on the offending PortBinding.
- **Task:** Add an XValidation rule on PortBinding requiring `target.port` to be set (and in range) whenever `target.address` is set, so the bad spec is rejected at apply time with a precise message instead of failing a downstream EdgeNode reconcile. Keep the planner check as defense-in-depth.
- **When:** Small, purely additive validation; do it next time the API CRDs are regenerated (it is a three-part CRD edit per DESIGN_AND_RULES §5).

## 8. Honour the context in `agentrun.Run` for graceful shutdown
- **Context:** `agentrun.Run(ctx, ...)` takes a context but never observes it: it starts `watchConfig` and `srv.ListenAndServe()` and only returns on a server error. The `ctx` parameter is silently ignored, so the daemon relies on the container being SIGKILL'd. Harmless in the uplink pod today, but a function that accepts a `ctx` and drops it is a smell and blocks any clean in-process shutdown/testing.
- **Task:** Wire `ctx` through: stop the fsnotify watcher and call `srv.Shutdown(ctx)` when `ctx` is done (run `ListenAndServe` in a goroutine, select on `ctx.Done()`), and treat `http.ErrServerClosed` as a clean exit. Have `tunnelctl run` pass a signal-bound context instead of `context.Background()`.
- **When:** Low priority (no production impact), but cheap and removes the dropped-parameter smell.

---

*Items 9–18 come from the June 2026 robustness audit (3 workers + manual confirmation against the code; `make verify` green incl. race). Severity noted per item. These are the agreed working set.*

## 9. [HIGH] ~~EdgeNode reconcile hot loop: status update re-queues itself~~ ✅ DONE (jun 2026)
- **Fixed:** `For()` now carries `predicate.Or(GenerationChangedPredicate, AnnotationChangedPredicate, LabelChangedPredicate)` (`edgeNodeEventPredicate`), and `updateStatusAndReturn` skips the `Status().Update()` when the status is semantically DeepEqual to the snapshot taken after the Get. Regression tests: a status-write-counting client wrapper proves the second reconcile performs zero status writes (mutation-tested: fails with the skip disabled), plus direct predicate assertions (status-only → no enqueue; generation/annotation/label change → enqueue).

## 10. [HIGH] ~~Envoy admin address hardcoded to `10.200.0.1` in the bootstrap~~ ✅ DONE (jun 2026)
- **Fixed:** the planner now exposes `Plan.RelayIP` (already embedded in RelayDocument, so its hash covers changes; PlanHash untouched) and `ensureEnvoyRunning` templates the admin address from it, failing loudly when empty. The bootstrap delivery is change-aware without touching State: the remote `/etc/envoy/envoy.yaml` is compared with the desired content — identical means no Put and no restart, different/missing means Put + restart (Envoy only reads the bootstrap at startup, so a relay-network change now actually takes effect). Default-network nodes get byte-identical content, so upgrading the operator causes zero restarts. Tests mutation-verified (hardcoded-IP, never-diff and always-diff mutants all killed).

## 11. [HIGH] known_hosts verification ignores the hostname
- **Context:** `ssh_utils.go:31-56` — the `hosts[]` returned by `ParseKnownHosts` are discarded, so the host-key callback accepts any key present in the file for any host. With a single VPS it is barely exploitable, but the anti-MitM semantics are broken as soon as the Secret holds more than one entry.
- **Task:** Replace the manual parsing/callback with `golang.org/x/crypto/ssh/knownhosts.New`, which does hostname-aware matching correctly.
- **When:** Now. Security semantics, small diff.

## 12. [MEDIUM] Enroll early-exit misses `TunnelctlHash` and `EnvoyVersion` (silently ineffective upgrades)
- **Context:** `enroll.go:67` — the early-exit comparison only covers the plan hash. Upgrading the `tunnelctl` binary or `--envoy-version` without a plan change leaves the VPS running the old artifacts indefinitely, with no observable signal. Two faces of the same bug.
- **Task:** Include `TunnelctlHash` and `EnvoyVersion` in the early-exit decision (compare against what `state.json` recorded on the VPS).
- **When:** With the HIGH batch; it is the same file as item 10.

## 13. [MEDIUM] Orphaned kernel routes on uplink scale-down
- **Context:** `wg.go` — `RouteReplace` installs routes for current peers but nothing ever calls `RouteDel` for removed peers. Traffic to a dead replica is silently dropped and `ip route` lies about the topology.
- **Task:** Diff desired vs. installed routes during apply and delete the stale ones (same pattern as the peer reconciliation).
- **When:** Soon; bites on any replica scale-down.

## 14. [MEDIUM] `spec.uplink.namespace` is mutable and orphans resources on teardown
- **Context:** If the namespace changes after resources were created, teardown looks in the new namespace, sees NotFound, removes the finalizer and leaves the STS + ConfigMap + Secrets orphaned in the old one.
- **Task:** Add a CEL immutability rule (`self == oldSelf`) on `spec.uplink.namespace`.
- **When:** Soon; one-line CRD validation (three-part CRD edit per DESIGN_AND_RULES §5).

## 15. [MEDIUM] Initial `Apply` in `agentrun` has no retry
- **Context:** If the first `Apply` fails (e.g. a race with the kernel module at startup), nothing retries until the ConfigMap changes. The pod stays `Running` but NotReady forever, with no CrashLoop to rescue it.
- **Task:** Retry the initial apply with backoff (or exit non-zero on persistent failure so the kubelet restarts the container).
- **When:** Soon; turns a transient race into a permanent outage today.

## 16. [MEDIUM] `EnvoyVersion` interpolated into VPS shell without sanitisation
- **Context:** The value ends up inside shell commands run as root on the VPS. The vector is operator-controlled (a flag), but a typo should not be a root RCE.
- **Task:** Validate it against a strict version regex (e.g. `^v?[0-9]+\.[0-9]+\.[0-9]+$`) before any interpolation, or shell-quote it.
- **When:** Soon; trivial guard.

## 17. [MEDIUM] PortBinding `Ready=True` means "triggered", not "applied"
- **Context:** The condition is set when the label is written, not when the port is actually applied on the edge. GitOps tooling (Argo/Flux) will read it as "operational".
- **Task:** Only set `Ready=True` once the EdgeNode reconcile confirms the port is in the applied plan (or introduce a separate `Programmed`/`Ready` pair with honest semantics).
- **When:** Soon; observability correctness.

## 18. [MEDIUM] Grouped minor findings from the audit
- **Context/Task:** Small, independent fixes confirmed in the audit:
  - `mapSecretToEdgeNodes` swallows List errors without logging (a TLS/SSH secret rotation can be silently missed) — log the error.
  - RBAC grants `create`/`delete` on the operator's own CRDs — trim to what the controller actually needs.
  - The Secrets watch is cluster-wide and unfiltered — add a field/label selector or namespace scoping (manager memory on large clusters).
  - ipam is anchored to the 4th octet — breaks with CIDRs that are not `.0`-aligned `/24`s; compute offsets properly over the CIDR.
  - The planner does not reserve 8080/9901 as forbidden ports — a PortBinding can collide with the readiness endpoint / Envoy admin.
  - The STS `ServiceName` points to a headless Service nobody creates — create it (or drop the reference).
  - `--leader-elect` defaults to false — flip the default to true.
- **When:** Batch them in one cleanup pass after items 9–17.

