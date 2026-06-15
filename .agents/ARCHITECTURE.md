# Architecture and Implementation Details

Reference for the data path, API, controller behavior, code structure, required tests, and the closed design decisions.

## 1. Context and Objective

Expose arbitrary ports (TCP and UDP) on the public IP of one or more VPS and route that traffic to services of a private Kubernetes cluster (Services or direct IPs), with these non-negotiable properties:

1. The private network does not expose anything: all tunnels are initiated by the cluster (outbound-only).
2. The VPS is a relay with no access to the content: it never possesses keys of the transported protocols.
3. Maximum performance data path: kernel WireGuard as transport, Envoy as the sole userspace process, kernel NAT for final translation. The operator is only control plane and never participates in the data path.
4. Trivial operation: enrolling a new machine = a Secret with SSH credentials + a CR. Exposing a port = a CR.
5. Everything running on the VPS is readable and killable: one systemd unit (Envoy) plus the `tunnelctl` binary applying WireGuard natively, and config files. Zero custom daemons on the VPS.

## 2. Data path architecture

```
internet ──:51820/udp──┐
internet ──:80,:443────┤  Envoy proxy (VPS)
internet ──:NNNN───────┘     │ upstream: load balances between tunnel IPs
                             ▼
                       wg-relay (VPS, kernel, N peers /32)
                             ║ N WG tunnels, initiated from the cluster
                             ║ keepalive 25s, zero inbound in private net
                             ▼
                 uplink replicas (StatefulSet, NET_ADMIN)
                             │ DNAT per binding + masquerade (identical on all)
                             ▼
                 ClusterIP svc / direct IP
```

### 2.1 Transport: N WireGuard Tunnels

Each uplink replica is an independent WG peer with its own keypair and stable tunnel IP by ordinal (10.200.0.2 for uplink-0, .3 for uplink-1, ...). The private side does not have a ListenPort and maintains the flow with PersistentKeepalive.

### 2.2 VPS: Envoy proxy with upstreams

Sole process with open public ports. The machine is assumed to be dedicated to this role. Envoy is bootstrapped once with an immutable `/etc/envoy/envoy.yaml` that defines the `admin` block and `dynamic_resources` pointing at file-based LDS/CDS (`path_config_source` -> `/etc/envoy/lds.yaml` and `/etc/envoy/cds.yaml`). The operator owns those three files and updates listeners/clusters via atomic `mv` of `.tmp` files, so Envoy hot-reloads without restarting (see DESIGN_AND_RULES §3). Sessions are sticky by client addr:port. Each cluster carries active health checks: Envoy probes every uplink replica's `/ready` endpoint (HTTP on the replica's `:40500`, selected per endpoint via `health_check_config.port_value` while traffic still targets the listen port) using the interval/timeout/thresholds from `spec.edge.healthCheck` (optional, defaults 5s/2s/2/2). The signal is protocol-agnostic (it probes the uplink readiness, not the data port), so it covers TCP, TLS and UDP listeners alike; a replica whose tunnel is down or whose nft/handshake readiness fails is taken out of rotation instead of black-holing traffic. When a TCP binding enables `proxyProtocol`, the cluster declares `transport_socket_matches`: data-path endpoints select the PROXY-protocol wrapper through endpoint metadata, while the active health check sets an empty `transport_socket_match_criteria` that selects the plain `raw_buffer` match, so the probe to `/ready` is not prefixed with a PROXY header the readiness server would reject. The cluster is a `STATIC` type over the replicas' literal tunnel IPs (no DNS resolution on the VPS). `healthy_panic_threshold` is hard-coded to 0 so that when most or all replicas are unhealthy Envoy fails fast (`no healthy upstream`) rather than re-flooding dead tunnels. Envoy originates connections with `10.200.0.1`, so return traffic is symmetric without SNAT on the VPS. The admin interface binds to `10.200.0.1:40600` (reachable only over the tunnel).

### 2.3 Cluster: Uplink replicas

Pod with `NET_ADMIN`. On boot it reads the shared desired-state document from the mounted ConfigMap, injects this replica's identity (tunnel address by ordinal, WireGuard private key from the mounted keys Secret), and applies it natively: WireGuard via netlink/wgctrl and the nftables DNAT ruleset via `google/nftables`. No `wg-quick`, no `nft` CLI, no `iproute2`. Replicas are identical except for keypair and tunnel IP: the DNAT ruleset is the SAME on all.

The masquerade does not destroy the client's real IP at the application level because it travels in Proxy Protocol.

### 2.4 Strict Data Path Rules

- The VPS never receives the WireGuard private keys of the cluster, nor the keys of the transported protocols: it is a blind relay. Its own WG private key is generated locally in-cluster with `wgctrl` and stored in a Secret; the relay's private key is delivered to the VPS only inside the `tunnelctl` desired-state document (0600) and never leaves via keygen on the host.
- The single, explicit exception is **TLS edge termination** (`offload`/`mutual` modes on a PortBinding, see §3.2 and §4.4). There the user deliberately opts in to terminating TLS on the VPS, which requires the server certificate's private key to live on the edge. The operator surfaces this with a `PrivateKeyOnEdge` warning Event the first time the key is pushed. `passthrough` mode keeps this rule intact: it only inspects SNI and forwards the still-encrypted stream, so no key ever leaves the cluster.

## 3. API Details

### 3.1 Kind: EdgeNode
Credentials ALWAYS by `secretRef`, never inline in the CR.

### 3.2 Kind: PortBinding
A PortBinding carries a list of `bindings`, each discriminated by `protocol` (`TCP`|`UDP`) with typed sub-structs `tcp` / `udp`, both optional (the operator/planner applies defaults if omitted: TCP `connectTimeout=5s`, `idleTimeout=3600s`; UDP `sessionTimeout=60s`).
Validations:
- Protocol/params coherence and "Target is exactly one of Service or Address" are enforced declaratively by CEL `XValidation` markers on the CRD (admission time).
- Unique `(protocol, listenPort)` pair across ALL PortBindings referencing the same EdgeNode (so the same port on TCP and UDP can coexist, since they are separate sockets), `listenPort` != `tunnel.listenPort` of the referenced host, and `listenPort` not on a reserved infrastructure port (40500 uplink readiness, 40600 Envoy admin/metrics, both protocol-agnostic) are enforced at runtime inside `internal/planner.BuildPlan` during EdgeNode reconciliation (a conflict fails that EdgeNode's reconcile, not the PortBinding admission).

#### 3.2.1 TLS at the edge (optional, TCP only)
A TCP binding may carry an optional `tls` block: `{ mode, secretRef }`. A single `secretRef` points at a standard `kubernetes.io/tls` Secret; the `mode` decides which keys are read from inside it:
- `passthrough`: Envoy forwards the still-encrypted stream to the upstream through a catch-all filter chain (the `tls_inspector` still extracts the SNI for stats/logs, but routing does not depend on it, so any SNI and no-SNI connections are accepted). No decryption, no key leaves the cluster, `secretRef` is ignored.
- `offload`: Envoy terminates TLS on the VPS. The operator reads `tls.crt` + `tls.key` from the Secret and pushes them to the edge.
- `mutual`: same as `offload` plus downstream mTLS verification of the client certificate; additionally reads `ca.crt` and renders `require_client_certificate` + a validation context. Verification happens at the VPS edge; traffic toward the uplink stays in clear (the operator does not do mTLS to the upstream).

Validation is split: CEL on the CRD enforces the spec shape (`tls` only on TCP bindings; `secretRef` required when mode is `offload`/`mutual`). The presence of the right keys *inside* the Secret cannot be checked at admission, so it is validated at runtime during EdgeNode reconciliation (reason `TLSSecretIncomplete` on the Ready condition when a Secret or a required key is missing).

## 4. Controller Behavior

### 4.1 EdgeNodeReconciler (sole writer to the machine and uplink)
1. **IPAM and keys**: Assigns tunnel IP by ordinal. Generates one WireGuard keypair per replica (stored in the `<node>-uplink-keys` Secret). The VPS keypair is generated locally in-cluster with `wgctrl`/`wgtypes` and cached in the `<node>-vps-key` Secret, so no command runs on the VPS to create it.
2. **SSH Enrollment**: Idempotent. Pushes the matching static `tunnelctl` binary to the VPS (read from the local `--tunnelctl-dir`: baked into the operator image, or a local build dir under `make run`; the right arch chosen from `uname -m`), plus the static Envoy binary; writes the relay `tunnelctl` desired-state document and applies it with `tunnelctl apply` (WireGuard via netlink, no `wireguard-tools`, no `wg-quick`, no download on the VPS). The only systemd units installed are the Envoy service and a `wg-relay` boot oneshot (`Type=oneshot`, `RemainAfterExit=yes`) that reapplies the relay document on boot so WireGuard survives a VPS reboot; the Envoy unit `Requires`/`After` it. Neither is a resident WireGuard daemon. It also writes the immutable Envoy bootstrap plus LDS/CDS files, any TLS material for edge-terminating bindings, and `state.json` with artifact hashes (relay document, tunnelctl binary hash, LDS, CDS, TLS).
3. **Uplink**: Creates/updates a StatefulSet with the uplink image, a ConfigMap holding the shared uplink `tunnelctl` desired-state document (WireGuard + nftables; each replica injects its own identity at runtime), and the headless Service the StatefulSet's `spec.serviceName` references (ClusterIP None, selector-only).
4. **Aggregate Render**: Lists all PortBindings that reference this EdgeNode, resolves Service targets to ClusterIPs, validates cross-binding port conflicts (and conflicts with the tunnel ListenPort), and renders the relay and uplink `tunnelctl` desired-state documents plus the Envoy LDS/CDS via `internal/planner.BuildPlan`. For bindings with `tls` in `offload`/`mutual`, the plan also declares the TLS material to install (the per-binding SDS document path on the VPS); the reconciler reads the referenced `kubernetes.io/tls` Secret, validates the required keys, renders a per-binding SDS document (server cert/key inline, plus `ca.crt` for `mutual`) and pushes it to the edge.
5. **Drift**: Re-render is event-driven plus a periodic safety net. The happy path requeues after `RequeueInterval` (default 3 min) for drift detection and status refresh, and also reacts to watches (the EdgeNode itself, the PortBindings that reference it, and the TLS Secrets referenced by its bindings). It compares `status.appliedConfigHash` (the plan hash folded with the TLS material hash, so cert rotations are visible) and the per-artifact hashes against the desired plan and the remote `state.json`; only re-pushes/restarts services when hashes differ, and reports health back into status. Envoy health is read via `systemctl is-active`; relay WireGuard health and the peer handshakes are read via `tunnelctl status` (JSON + exit code). Optimistic-concurrency conflicts on writes/status updates are turned into clean requeues, never swallowed.
6. **Binary delivery**: which Envoy release is installed is an operator-wide setting, the manager flag `--envoy-version` (default `controller.DefaultEnvoyVersion`); `provision.installEnvoyBinary` builds the download URL from version + architecture and reinstalls when Envoy is absent or a different version. `tunnelctl` is NOT downloaded on the VPS: the operator reads the static binary from `--tunnelctl-dir` (default `controller.DefaultTunnelctlDir`, baked into the operator image; overridden to a local build dir under `make run`) and pushes the arch-matching one over SSH, re-pushing only when its SHA-256 changes (tracked in `state.json`). The controller injects the Envoy version and the tunnelctl dir into the plan after `BuildPlan` (the planner stays pure). The operator stamps its own version into the binary via `internal/version.Version` (`-ldflags -X`), logged at startup. A running Envoy does not pick up a new binary until it is restarted (see the restart-envoy annotation).
7. **Teardown** (on deletion, guarded by a finalizer): runs `provision.Teardown` over SSH (deletes the `wg-relay` interface with `ip link del`, removes the `tunnelctl` binary, stops/disables both the Envoy service and the `wg-relay` boot oneshot and removes both systemd units, removes the Envoy config, the sysctl drop-in and `/etc/tunnel`) and then explicitly deletes the in-cluster uplink StatefulSet, ConfigMap, keys Secret and the cached `<node>-vps-key` Secret. They are deleted explicitly (not via owner references) because they live in `spec.uplink.namespace`, which can differ from the EdgeNode namespace, and cross-namespace owner-reference GC is not allowed. Set the `tunnel.achetronic.com/skip-deprovision: "true"` annotation to skip the SSH teardown.

#### 4.1.0 Operational annotations
- `tunnel.achetronic.com/skip-deprovision: "true"` skips the SSH teardown on deletion (the in-cluster uplink resources are still removed).
- `tunnel.achetronic.com/restart-envoy: "true"` makes the next reconcile restart Envoy on the VPS (via `provision.RestartEnvoy`, a systemctl restart that waits for the unit to become active) after enrollment, the way to apply a new `--envoy-version`. It is a one-shot: the reconciler consumes and removes the annotation in the same metadata update as the finalizer, before any status mutation, so it never clobbers the status write and never loops. A failed restart surfaces as `Ready=False`/`EnvoyRestartFailed`.

#### 4.1.1 TLS certificate rotation
The EdgeNodeReconciler `Watches` Secrets. When a Secret referenced by some binding's `tls.secretRef` changes (e.g. cert-manager renews it), a map function (`mapSecretToEdgeNodes`) resolves which EdgeNodes consume it and enqueues them, so the renewed certificate is re-pushed to the VPS. Delivery is via file-based **SDS**: the operator writes `/etc/envoy/tls/<binding>.sds.yaml` (cert/key inline, plus the CA for `mutual`) with a single atomic `mv` into the `watched_directory` (`/etc/envoy/tls`) that Envoy monitors; Envoy hot-reloads just that secret gracefully, with no listener rebuild, no dropped connections and no restart. Only Secrets actually referenced by a TLS binding produce a requeue. The `PrivateKeyOnEdge` warning Event is emitted only when key material is genuinely (re)written this reconcile, not on every loop.

### 4.2 PortBindingReconciler (independent of the EdgeNodeReconciler)
PortBindings have their own reconciler with its own lifecycle; the two controllers share no code or memory and communicate exclusively through the API server (`status.appliedBindings` + an EdgeNode watch upstream, see the NOTE below). This reconciler does not speak SSH, does not touch the uplink, does not resolve targets or validate conflicts, and never writes to the EdgeNode; its sole job is publishing the PortBinding's conditions. Plan rebuilding is driven by the EdgeNodeReconciler itself: it `Watches` PortBindings with a map function (`mapPortBindingToEdgeNode`) that enqueues the referenced EdgeNode on every create, spec change and deletion (a generation predicate filters PortBinding status writes, which carry no plan input), so the aggregate plan always reflects the live set of bindings, including dropped listeners after a deletion. PortBindings carry no finalizer; if an object still has `tunnel.achetronic.com/portbinding-finalizer`, the reconciler removes it on deletion so the object is never stuck. Target resolution and cross-binding conflict validation (including binding-name uniqueness across all PortBindings of a node, since the name keys the Envoy listener and the SDS document path) happen inside `BuildPlan` during EdgeNode reconciliation.

> NOTE: The PortBindingReconciler sets `PortBindingStatus.ObservedGeneration` and two conditions: `Programmed` (reason `Synced`, the spec was observed) and `Ready` (True with reason `Applied` only once the EdgeNode's `status.appliedBindings` lists the binding, i.e. the port is materialized in the plan applied on the edge). The two reconcilers communicate exclusively through the API server: the EdgeNodeReconciler publishes `appliedBindings` in its status after each successful enroll, and the PortBindingReconciler watches EdgeNodes to re-enqueue its bindings when that status changes. A transient failure reading the EdgeNode sets `Ready=Unknown` (reason `EdgeNodeUnreadable`) and returns the error, so controller-runtime retries with backoff instead of parking the condition. It does NOT populate `PortBindingStatus.ResolvedTargets`: target resolution lives in the planner and is reflected only in the rendered config and the EdgeNode plan, not mirrored into PortBinding status.

### 4.3 Uplink
The uplink image is the generic `tunnelctl` agent (same binary the edge uses), distroless and run as **root** (`gcr.io/distroless/static:latest`, not `:nonroot`): creating the WireGuard link and programming nftables via netlink needs an effective `CAP_NET_ADMIN`, which a non-root uid does not get even in a privileged pod. There is no uplink-specific binary.
- The StatefulSet runs `tunnelctl run --config /etc/tunnel/uplink.json --transforms /etc/tunnelctl/uplink.transforms.yaml`. The config is the shared desired-state template from the mounted ConfigMap (same for every replica); the transforms are a baked-in CEL document that fills each replica's identity at runtime (`internal/configtransform`): it parses the ordinal from `POD_NAME`, derives the tunnel address with `cidrHost(network, 2 + ordinal)`, and reads the private key from the per-ordinal file under `KEYS_DIR` (the mounted keys Secret).
- `tunnelctl run` applies WireGuard + nftables natively, watches the ConfigMap and re-applies (re-running the transforms, so identity stays consistent) on change, and serves the readiness endpoint on `:40500`. Readiness reports 200 only once a full apply (WireGuard AND nftables) has succeeded, the config watcher is active, and the WireGuard handshake is fresh, so a replica with WireGuard up but no DNAT rules is never put in rotation. If the config watcher cannot be maintained (inotify limits exhausted), the agent exits so the kubelet restarts the pod instead of running blind with stale config.

## 5. Code Structure and Decoupling

The reconcile loop DOES NOT contain business logic.
- `internal/planner`, `internal/render`, `internal/ipam`, `internal/agentconfig`, and `internal/provision`: zero dependencies on controller-runtime/client-go.
- `internal/agentconfig` is the shared JSON desired-state contract (WireGuard + optional nftables) the planner produces and `tunnelctl` consumes. `internal/wg` (netlink + wgctrl) and `internal/nftables` (`google/nftables`) apply it natively; `internal/agentrun` is the shared apply/status/run core behind `tunnelctl` (used by both the edge oneshot and the uplink daemon).
- `internal/configtransform` is a generic CEL postprocessor: it applies a `{path, expr}` rules document on top of a config before it is parsed, with helper functions (`getenv`, `readFile`, `fromJSON`, `fromYAML`, `cidrHost`). The uplink uses it to resolve per-replica identity declaratively, so there is no bespoke uplink binary.
- All renders deterministic: `internal/render` covers the Envoy LDS/CDS (including the three TLS listener shapes). WireGuard and nftables are not text-rendered; they are applied natively from the structured `agentconfig` documents.
- `internal/version` holds the operator version stamped via `-ldflags`, logged at startup.
- `sshexec.Executor` is the only boundary with the machine.
- A single point writes to the VPS (`EdgeNodeReconciler`).
- Inside `internal/controller`, files are split by ownership so it stays obvious what is kubebuilder scaffolding versus our logic: `*_controller.go` holds the kubebuilder-generated surface (the Reconciler struct, `Reconcile`, `SetupWithManager`, RBAC markers); `*_sync.go` holds our reconcile logic (enrollment flow, status, resolver, constants); `*_utils.go` holds auxiliary helpers (ensure/createOrUpdate/TLS/Secret-mapping).

## 6. Required Tests

### 6.1 Unit (pure, no network, no cluster)
- **internal/render**: deterministic output for the Envoy LDS/CDS.
- **internal/agentconfig**: parse/marshal/validate of the desired-state document.
- **internal/wg / internal/nftables**: pure config building (device config, rule building) behind the IO seam.
- **internal/ipam**: ordinal calculation, bounds check.
- **internal/planner**: stable hash, stable plan generation (relay + uplink documents, Envoy LDS/CDS), conflict detection.
- **internal/configtransform**: CEL transform engine (path/expr replacements, helper functions) and the shipped uplink identity transforms asset.
- **internal/provision (fake sshexec)**: enrollment sequence (tunnelctl + Envoy install, relay document apply), idempotency, partial failure handling.

### 6.2 Integration (envtest)
- Reconcilers manage standard StatefulSet, ConfigMap, and Secrets generation.

### 6.3 E2E
- Full end-to-end traffic tests with actual containers.

## 7. Closed Decisions (Do not reopen)

- **Envoy** as public proxy.
- **Active-active HA with N tunnels**: one /32 peer per replica.
- **DNAT (netfilter/nftables) in the pods** as final translation.
- **Operator out of the data path.**
- **Native config via `tunnelctl`**: WireGuard and nftables are applied natively (netlink/wgctrl/`google/nftables`) from a JSON desired-state document, not via `wireguard-tools`/`wg-quick`/`nft` CLI. The operator carries the static binary (baked into its image, or a local build dir under `make run`) and pushes the arch-matching one to the VPS over SSH; the VPS downloads nothing.
