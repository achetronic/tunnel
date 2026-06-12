# Tunnel - AI Agent Guide

Tunnel is a Kubernetes operator that exposes arbitrary TCP/UDP ports on the public IP
of one or more Linux VPS instances and routes that traffic back into a private cluster.
The data path is: `internet → Envoy (VPS) → N WireGuard tunnels → uplink pods (DNAT) →
ClusterIP/IP`. The operator is **control plane only** and never sits in the data path.
Envoy active-health-checks each uplink's `/ready` (`:8080`) and only balances onto replicas
whose tunnel is up; tune it via the optional `spec.edge.healthCheck` on the EdgeNode.

> Read the companion docs in this folder before touching the data path:
> `ARCHITECTURE.md` (full data path + controller behavior), `DESIGN_AND_RULES.md`
> (closed design decisions + hard code rules). They are authoritative; this file is the
> quick map.

## Build / Test / Lint Commands

```bash
make test          # manifests+generate+fmt+vet, then unit+integration tests (envtest). Excludes ./test/e2e
make test-e2e      # spins up a Kind cluster (tunnel-test-e2e), runs -tags=e2e ./test/e2e, tears down
make lint          # golangci-lint run   (config in .golangci.yml, custom plugins in .custom-gcl.yml)
make lint-fix      # golangci-lint run --fix
make run           # runs the manager (cmd/main.go) against current kubeconfig
make manifests     # regenerate CRDs + RBAC from kubebuilder markers
make generate      # regenerate zz_generated.deepcopy.go
make build         # builds bin/manager (also runs manifests+generate+fmt+vet first)
```

Run a single test package, e.g. the planner:
```bash
go test ./internal/planner/...
go test ./internal/render/... -run TestEnvoy
```
`make test`/`make build` always run `manifests generate fmt vet` first, so generated
files are refreshed implicitly. If you only changed pure Go logic, plain `go test ./...`
is faster.

## Two Binaries

- `cmd/main.go`: the **operator/manager** (image `Dockerfile`). Registers two
  independent reconcilers: `EdgeNodeReconciler` and `PortBindingReconciler`.
- `cmd/tunnelctl/main.go`: the **tunnelctl** agent (`apply`/`status`/`run` on a desired-state
  JSON document, with an optional `--transforms` CEL document applied first). It runs on BOTH
  sides: the operator pushes it to the VPS over SSH and drives `apply`/`status` oneshot there;
  the **uplink** image (`Dockerfile.uplink`, distroless, root) IS this binary and runs
  `tunnelctl run --config <ConfigMap> --transforms <baked-in identity transforms>`. There is
  no separate uplink binary.

## Package Map (where logic actually lives)

The reconcile loop contains **no business logic**. Everything below `internal/` (except
`controller/` and `uplink/`) imports **nothing** from controller-runtime/client-go and is
pure + deterministic:

| Package | Responsibility |
|---|---|
| `internal/planner` | `BuildPlan()`: aggregates an EdgeNode + all its PortBindings into the full desired state (relay and uplink `tunnelctl` documents, Envoy LDS/CDS) + per-artifact SHA-256 hashes + combined `PlanHash`. Also does **cross-binding port-conflict validation** and target resolution via the `TargetResolver` interface. |
| `internal/agentconfig` | The shared JSON desired-state contract (`wireguard` + optional `nftables`): types, `Parse`/`Decode`/`Marshal`/`Validate`. Produced by the planner, consumed by `tunnelctl`. |
| `internal/configtransform` | Generic CEL postprocessor: applies `{path, expr}` rules on top of a config before parsing, with helpers (`getenv`, `readFile`, `fromJSON`, `fromYAML`, `cidrHost`). The uplink uses it (asset `assets/uplink.transforms.yaml`) to resolve per-replica identity declaratively, so no bespoke uplink binary is needed. |
| `internal/render` | Deterministic text rendering of the Envoy LDS/CDS (`envoy.go`). Sort slices before rendering: output hash MUST be stable for identical input. |
| `internal/wg` / `internal/nftables` | Native apply/status of WireGuard (netlink + wgctrl) and nftables (`google/nftables`) from an `agentconfig` document. |
| `internal/agentrun` | Shared apply/status/run core behind `tunnelctl` (apply, watch + re-apply, readiness), used by both the edge oneshot and the uplink daemon. A failed initial apply retries in the background with backoff (1s..60s) until any apply succeeds. |
| `internal/version` | Operator version stamped via `-ldflags`, logged at startup. |
| `internal/ipam` | Tunnel IP math over the whole CIDR prefix: relay = base+1, uplink replica = base+2+ordinal. Works for non-aligned bases and networks wider than /24; rejects the broadcast address. |
| `internal/provision` | SSH enrollment (`enroll.go`), `health.go`, `teardown.go`. Idempotent: only writes/restarts when local hashes differ from the remote `state.json`. Also pushes TLS material (cert/key/ca) to the edge for offload/mutual bindings. |
| `internal/sshexec` | The **only** boundary to the VPS. `Executor` interface (every call takes a `context.Context`); `ssh.go` real impl, `fake.go` for tests. |
| `internal/controller` | The two reconcilers (thin; delegate to the packages above). Files split by ownership: `*_controller.go` = kubebuilder surface (struct, `Reconcile`, `SetupWithManager`, RBAC markers); `*_sync.go` = our reconcile logic; `*_utils.go` = helpers. |
| `internal/uplink` | Helpers for building the uplink StatefulSet/ConfigMap from the operator side. |
| `internal/logging` | Shared `log/slog` setup (`LOG_FORMAT`/`LOG_LEVEL`); both binaries use it, the manager bridges controller-runtime's logr onto its handler. |
| `api/v1alpha1` | CRD types: `EdgeNode` (VPS + uplink) and `PortBinding` (ports + targets). |

## Control Flow (critical, non-obvious)

- **`EdgeNodeReconciler` is the SOLE writer** to the VPS (over SSH) and to the uplink
  StatefulSet/ConfigMap/Secrets. It runs IPAM, generates one WG keypair per replica
  (stored in `<node>-uplink-keys` Secret), generates the VPS keypair over SSH once and
  caches it in the `<node>-vps-key` Secret, enrolls the VPS, lists all PortBindings
  referencing the node, resolves Service targets to ClusterIPs, calls `planner.BuildPlan`,
  and pushes config. The happy path requeues after `RequeueInterval` (default 3 min) as a
  drift-detection safety net; re-render between requeues is driven by watches (the EdgeNode,
  the trigger label, and the TLS Secrets it references). Drift detection compares
  `status.appliedConfigHash` + per-artifact hashes
  against the remote `state.json` and only re-pushes/restarts when they differ. Optimistic
  conflicts become clean requeues.
- **TLS at the edge:** a TCP binding may set `tls: { mode, secretRef }`. `passthrough`
  routes by SNI without decrypting (key stays in the cluster); `offload` terminates TLS on
  the VPS; `mutual` adds downstream client-cert verification. For offload/mutual the
  reconciler reads the `kubernetes.io/tls` Secret, validates the keys it needs at runtime
  (`TLSSecretIncomplete` Ready reason otherwise), pushes cert/key/ca to the VPS, and emits a
  `PrivateKeyOnEdge` warning Event the first time the key is written. `SetupWithManager`
  `Watches` Secrets and `mapSecretToEdgeNodes` re-enqueues affected EdgeNodes on rotation.
- **PortBindings have their own independent reconciler.** The two controllers share no
  code or memory; they communicate exclusively through the API server.
  `PortBindingReconciler` never touches SSH/uplink/targets: on create/update it adds a
  finalizer and bumps the `tunnel.achetronic.com/last-portbinding-trigger` label on the
  referenced EdgeNode; on delete the finalizer lets it bump that label one last time (so
  the EdgeNode re-renders and drops the listeners) before removing the finalizer. A
  missing EdgeNode makes the trigger a no-op. In the other direction, the
  EdgeNodeReconciler publishes `status.appliedBindings` after each successful enroll and
  the PortBindingReconciler `Watches` EdgeNodes to re-enqueue its bindings when that
  status changes (this watch deliberately reacts to status updates; the EdgeNode's own
  `For()` predicate filters them out — predicates are per-watch, they don't clash).
- **Deletion is finalizer-guarded** (`tunnel.achetronic.com/finalizer`). Teardown runs
  `provision.Teardown` over SSH and then `deleteUplinkResources` deletes the uplink
  StatefulSet/ConfigMap/Secret explicitly; owner-reference GC does NOT apply because
  they live in `spec.uplink.namespace`, which may differ from the EdgeNode namespace
  (cross-namespace owner refs are disallowed). The annotation
  `tunnel.achetronic.com/skip-deprovision: "true"` skips the SSH teardown.
- **Periodic reconcile.** A healthy EdgeNode requeues after `RequeueInterval` (default
  3 min, `defaultRequeueInterval`) for drift detection and status refresh, instead of
  hammering or relying only on watches. The Envoy binary version is the manager flag
  `--envoy-version` (default `controller.DefaultEnvoyVersion`), injected into the plan by the
  controller after `BuildPlan` (the planner stays pure); `provision.installEnvoyBinary`
  builds the download URL from version+arch and reinstalls when absent or version-mismatched.
- **Operator-managed images.** The uplink StatefulSet image is not hardcoded: the manager
  composes it from `--image-repo` (default `ghcr.io/achetronic/tunnel`) and `--image-tag`
  (default `latest`) as `<repo>/uplink:<tag>`, mirroring its own `<repo>/controller:<tag>`,
  and passes it to `uplink.BuildStatefulSet` with `imagePullPolicy: IfNotPresent` (works both
  for a preloaded kind image and a real registry). Set `--image-tag` to the operator version
  so the uplink tag matches. `controller.DefaultImageRepo`/`DefaultImageTag`/`DefaultUplinkImage`
  are the single source of the defaults.
- **One-shot restart annotation.** `tunnel.achetronic.com/restart-envoy: "true"` makes the
  next reconcile run `provision.RestartEnvoy` (systemctl restart + wait active) after enroll,
  to apply a new Envoy binary. The reconciler consumes (removes) the annotation in the same
  metadata update as the finalizer, before any status mutation, so it is a deliberate
  one-shot and never clobbers the status write.
- **Logging.** Both binaries use `log/slog` via `internal/logging` (`LOG_FORMAT=text|json`
  default json, `LOG_LEVEL=debug|info|warn|error` default info). The manager bridges
  controller-runtime's logr onto the same slog handler (`logr.FromSlogHandler`), so reconciler
  logs and the lower-level `provision` slog logs share one stream. `debug` shows per-step
  enrollment detail.
- `PortBindingReconciler` populates `PortBindingStatus` with `ObservedGeneration` and two
  conditions: `Programmed` (reason `Synced`, the trigger reached the EdgeNode) and `Ready`
  (True/reason `Applied` only once the EdgeNode's `status.appliedBindings` lists the
  binding — i.e. the port is in the plan actually applied on the edge; `NotYetApplied` /
  `EdgeNodeNotFound` otherwise). GitOps tooling should gate on `Ready`. What it does NOT
  populate is `PortBindingStatus.ResolvedTargets`: target resolution lives in the planner
  during EdgeNode reconciliation and is reflected only in the rendered config and the
  EdgeNode plan, never mirrored back into PortBinding status.

## Validation Split (no admission webhooks)

There is **no `internal/webhook/` directory** and the `PROJECT` file declares no webhook
resources. Do NOT scaffold a webhook unless explicitly asked.
- **Admission-time** checks are declarative CEL `// +kubebuilder:validation:XValidation`
  markers on the CRD types (see top of `api/v1alpha1/portbinding_types.go`): TCP/UDP param
  coherence, "Target is exactly one of Service or Address", `tls` only on TCP bindings, and
  `tls.secretRef` required when mode is offload/mutual.
- **Runtime** checks live in `planner.BuildPlan` during EdgeNode reconciliation (unique
  `listenPort` across all PortBindings of the same EdgeNode, and `listenPort != tunnel.listenPort`)
  and in the reconciler for TLS Secret contents (the required keys must exist inside the
  referenced Secret; `TLSSecretIncomplete` otherwise). A conflict fails the **EdgeNode**
  reconcile, not the PortBinding admission.

## Testing Conventions

- Ginkgo + Gomega (BDD) for controller integration tests under `internal/controller`
  (`suite_test.go` sets up envtest = real kube-apiserver + etcd, no kubelet).
- Pure packages (`planner`, `render`, `ipam`, `provision`) use standard `go test` table
  tests. Provision tests inject `sshexec.NewFakeExecutor()` (set `fake.RunFunc`).
- **envtest executor injection:** the `EdgeNodeReconciler` has an `ExecutorFactory` field.
  When nil (production) `getSSHExecutor` dials the real host via `sshexec.NewSSHExecutor`;
  integration tests set it to a factory returning a `sshexec.FakeExecutor`, so production
  code never references the fake and no magic address is involved.
- e2e tests are build-tagged `e2e` and require an **isolated Kind cluster**, never your
  real dev/prod cluster. `make test-e2e` manages cluster lifecycle.
- The suite must stay green for an anonymous contributor with nothing but Go installed:
  no VPS, no Docker, no VM. Tests needing real privileges (e.g. `TestSyncRoutes_Kernel`
  creates a dummy interface, needs root) self-skip with an explicit "SKIPPED, NOT TESTED"
  log and document the sudo command that provides the coverage.

## Code Rules (from DESIGN_AND_RULES.md, enforced)

- **Determinism:** every render must produce an identical hash for identical input. Sort
  before rendering.
- **Functional purity:** `internal/planner` and `internal/render` import nothing from
  Kubernetes/client-go.
- **Idempotency:** `internal/provision` writes/restarts only when hashes differ vs the
  remote `state.json`. Service-stop commands use trailing `|| true`.
- **Strict error handling:** no `_ = err`, no shadowing. Wrap and return
  (`fmt.Errorf("...: %w", err)`). Blank-assign of errors tolerated only in `_test.go` for
  repeated deterministic-render calls already asserted once.
- **English only** for all code, comments, logs, docs.
- **Product naming:** the product is **Tunnel**. Do not reintroduce `tunnel-operator` in
  user-facing names. The on-disk VPS path `/etc/tunnel-operator/` is an intentional,
  stable internal detail, leave it.
- **No leaking concrete use cases** in product docs.

## Generated / Do-Not-Edit Files

- `config/crd/bases/*.yaml`, `config/rbac/role.yaml` → from `make manifests`
- `api/**/zz_generated.deepcopy.go` → from `make generate`
- `PROJECT` → kubebuilder metadata (single-group `tunnel.achetronic.com/v1alpha1`,
  kinds `EdgeNode` + `PortBinding`)
- Do not delete `// +kubebuilder:scaffold:*` markers.

After editing `api/**/*_types.go` or markers: run `make manifests generate`.

## Deploy & Debug

```bash
make install && make deploy IMG=<registry>/tunnel:tag   # CRDs + manager
kubectl apply -k config/samples/
```
The official debug path is the **admin bridge**: an nftables DNAT in the uplink pods
forwards port `9901` through the tunnel to Envoy's admin (`10.200.0.1:9901`, never public):
```bash
kubectl -n tunnel exec -it <node>-uplink-0 -c uplink -- curl -s http://127.0.0.1:9901/config_dump
kubectl -n tunnel exec -it <node>-uplink-0 -c uplink -- curl -s http://127.0.0.1:9901/stats/prometheus
```
We deliberately keep CR status minimal and rely on raw Envoy admin access instead of
building rich status summaries.

## VPS Provisioning Notes (OS-agnostic)

- Envoy is installed by downloading the static binary matching `uname -m`
  (`amd64`/`arm64`) + an injected systemd unit, same version on every distro.
- WireGuard and nftables are applied natively by `tunnelctl` (no `wireguard-tools`, no
  `wg-quick`, no `nft` CLI). The operator carries the static `tunnelctl` binary in its image
  (or a local build dir under `make run`, via `--tunnelctl-dir`) and pushes the arch-matching
  one to the VPS over SSH; the relay downloads nothing and needs only the WireGuard kernel module.
- The VPS never receives the cluster's WireGuard keys or the keys of the transported
  protocols; its own WG private key is generated locally in-cluster with `wgctrl` and
  delivered only inside the `tunnelctl` document. The one opt-in exception is TLS
  `offload`/`mutual`, where the user chooses to terminate TLS on the edge and the server
  cert's private key is pushed to the VPS (with a `PrivateKeyOnEdge` warning). `passthrough`
  keeps the key in the cluster.
