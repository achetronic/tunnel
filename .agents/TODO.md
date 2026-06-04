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
