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

## 9. Live end-to-end validation of the robustness-audit fixes
- **Context:** The test suite covers everything fakeable (envtest + FakeExecutor for SSH, a root-gated netlink test for routes); what remains genuinely needs a real VPS + Kind session with real WireGuard handshakes.
- **Task:** Verify on a real enroll: the PortBinding `Ready` transition driven by the watch chain (PortBinding create/delete enqueues the EdgeNode, listeners appear/drop on the VPS without any label choreography), stale-route deletion visible in `ip route` after an uplink scale-down, the uplink headless Service resolving per-pod DNS, the headless Service disappearing on EdgeNode deletion, the `.tunnel.*` orphan sweep on a cancelled transfer, the forced SSH teardown path against a silently dead peer, and that leader election does not get in the way under `make run` (disable with `--leader-elect=false` if it does).
- **When:** Blocked on regenerating access to the dev VPS (recreated; the `vps-ssh-secret` is stale).
