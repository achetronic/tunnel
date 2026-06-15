package planner

import (
	"fmt"
	"sort"
	"time"

	"github.com/achetronic/tunnel/api/v1alpha1"
	"github.com/achetronic/tunnel/internal/agentconfig"
	"github.com/achetronic/tunnel/internal/ipam"
	"github.com/achetronic/tunnel/internal/render"
)

// BuildPlan derives the complete desired state from the EdgeNode spec and the
// currently active PortBindings.  It is a pure function: no IO, no side
// effects, deterministic output for the same inputs.
//
// Preconditions:
//   - node must not be nil.
//   - vpsPrivKey must not be empty (it becomes the WireGuard [Interface] PrivateKey
//     on the VPS; an empty key produces a syntactically valid but non-functional config).
//   - vpsPubKey must not be empty (it becomes the relay peer's PublicKey in the
//     uplink document; an empty key produces a non-functional tunnel).
//   - uplinkKeys must not be nil and must contain a non-empty public key for every
//     ordinal in the range [0, node.Spec.Uplink.Replicas).
//   - resolver must not be nil.
//
// Returns error if:
//   - any precondition above is violated.
//   - the tunnel network CIDR is invalid or does not contain the relay/replica addresses.
//   - two PortBindingDefinitions claim the same ListenPort (including the tunnel port).
//   - a Service-targeted binding cannot be resolved via resolver.
//   - a direct-address binding has an empty Address or a port <= 0.
func BuildPlan(
	node *v1alpha1.EdgeNode,
	bindings []v1alpha1.PortBinding,
	resolver TargetResolver,
	vpsPrivKey string,
	vpsPubKey string,
	uplinkKeys map[int32]string, // ordinal -> publicKey
) (*Plan, error) {
	if err := validateBuildPlanInputs(node, resolver, vpsPrivKey, vpsPubKey, uplinkKeys); err != nil {
		return nil, err
	}

	network := node.Spec.Tunnel.Network
	if network == "" {
		network = defaultTunnelNetwork
	}
	listenPort := node.Spec.Tunnel.ListenPort
	if listenPort == 0 {
		listenPort = 51821
	}
	replicas := node.Spec.Uplink.Replicas
	if replicas <= 0 {
		replicas = 1
	}

	ipCalc, err := ipam.New(network)
	if err != nil {
		return nil, fmt.Errorf("ipam error: %w", err)
	}

	relayIP, err := ipCalc.RelayIP()
	if err != nil {
		return nil, fmt.Errorf("relay ip error: %w", err)
	}

	// Use MaskBits() instead of re-splitting the CIDR string, reusing the parse
	// ipam.New already performed on the prefix.
	mask := ipCalc.MaskBits()

	mtu := node.Spec.Tunnel.MTU
	if mtu <= 0 {
		mtu = 1420
	}

	keepalive := node.Spec.Tunnel.PersistentKeepalive
	if keepalive <= 0 {
		keepalive = 25
	}

	wgPeers, err := buildRelayPeers(ipCalc, uplinkKeys, replicas)
	if err != nil {
		return nil, err
	}

	relayDocument, err := buildRelayDocument(vpsPrivKey, fmt.Sprintf("%s/%d", relayIP, mask), listenPort, mtu, wgPeers)
	if err != nil {
		return nil, fmt.Errorf("render relay document: %w", err)
	}

	allDefs, err := collectBindingDefs(bindings, listenPort)
	if err != nil {
		return nil, err
	}

	resolvedHC := resolveEnvoyHealthCheck(node.Spec.Edge.HealthCheck)
	envoyListeners, nftRules, err := buildEnvoyListeners(allDefs, resolver, ipCalc, replicas, resolvedHC)
	if err != nil {
		return nil, err
	}

	tlsMaterials, err := buildTLSMaterials(bindings)
	if err != nil {
		return nil, err
	}

	envoyLDS, err := render.RenderEnvoyLDS(render.EnvoyConfig{
		Listeners: envoyListeners,
	})
	if err != nil {
		return nil, fmt.Errorf("render envoy LDS: %w", err)
	}

	envoyCDS, err := render.RenderEnvoyCDS(render.EnvoyConfig{
		Listeners: envoyListeners,
	})
	if err != nil {
		return nil, fmt.Errorf("render envoy CDS: %w", err)
	}

	uplinkEndpoint := fmt.Sprintf("%s:%d", node.Spec.Address, listenPort)
	uplinkDocument, err := buildUplinkDocument(vpsPubKey, relayIP, network, uplinkEndpoint, mtu, keepalive, nftRules)
	if err != nil {
		return nil, fmt.Errorf("render uplink document: %w", err)
	}

	relayDocHash := hashBytes(relayDocument)
	uplinkDocHash := hashBytes(uplinkDocument)
	ldsHash := hashBytes(envoyLDS)
	cdsHash := hashBytes(envoyCDS)

	// PlanHash covers exactly what the operator applies to a node: the relay and
	// uplink desired-state documents plus the Envoy LDS/CDS. It backs
	// EdgeNode.status.appliedConfigHash for drift detection.
	planHash := hashBytes([]byte(relayDocHash + uplinkDocHash + ldsHash + cdsHash))

	return &Plan{
		EnvoyLDS:           envoyLDS,
		EnvoyCDS:           envoyCDS,
		EnvoyLDSHash:       ldsHash,
		EnvoyCDSHash:       cdsHash,
		RelayDocument:      relayDocument,
		RelayDocumentHash:  relayDocHash,
		UplinkDocument:     uplinkDocument,
		UplinkDocumentHash: uplinkDocHash,
		PlanHash:           planHash,
		RelayIP:            relayIP,
		TLSMaterials:       tlsMaterials,
	}, nil
}

// relayInterface is the WireGuard interface name on the VPS relay.
const relayInterface = "wg-relay"

// uplinkInterface is the WireGuard interface name on each uplink replica pod.
const uplinkInterface = "wg-uplink"

// metricsPort is the port the relay's Envoy admin interface listens on and the
// port the uplink forwards in-cluster scrape traffic to over the tunnel. It
// matches the metrics DNAT applied natively by internal/nftables.
const metricsPort = 40600

// buildRelayDocument renders the tunnelctl desired-state document for the VPS
// relay. tunnelctl applies it natively via netlink. The relay has no nftables
// section; its peers are the uplink replicas, reached only when they dial in, so
// they carry no endpoint or keepalive.
func buildRelayDocument(privateKey, interfaceIP string, listenPort, mtu int32, peers []agentconfig.WireGuardPeer) ([]byte, error) {
	doc := agentconfig.Document{
		Version: agentconfig.CurrentVersion,
		WireGuard: agentconfig.WireGuardConfig{
			Interface: agentconfig.WireGuardInterface{
				Name:       relayInterface,
				PrivateKey: privateKey,
				ListenPort: int(listenPort),
				Address:    interfaceIP,
				MTU:        int(mtu),
			},
			Peers: peers,
		},
	}
	if err := doc.Validate(); err != nil {
		return nil, fmt.Errorf("invalid relay document: %w", err)
	}
	return doc.Marshal()
}

// buildUplinkDocument renders the tunnelctl desired-state document shared by every
// uplink replica. It carries the full nftables ruleset and the single relay peer
// (reached at endpoint with persistent keepalive), but intentionally leaves
// Interface.PrivateKey and Interface.Address empty: those are per-replica identity
// that the uplink agent injects at runtime from its mounted key Secret and its
// ordinal (decoded via agentconfig.Decode), then validates before applying. Because
// the template is incomplete by design, it is marshalled WITHOUT validation here;
// the runtime is responsible for the final Validate after injection.
func buildUplinkDocument(vpsPubKey, relayIP, network, endpoint string, mtu, keepalive int32, nftRules []agentconfig.NftablesRule) ([]byte, error) {
	doc := agentconfig.Document{
		Version: agentconfig.CurrentVersion,
		WireGuard: agentconfig.WireGuardConfig{
			Interface: agentconfig.WireGuardInterface{
				Name: uplinkInterface,
				MTU:  int(mtu),
				// PrivateKey and Address are injected per replica at runtime.
			},
			Peers: []agentconfig.WireGuardPeer{
				{
					PublicKey:           vpsPubKey,
					AllowedIPs:          []string{fmt.Sprintf("%s/32", relayIP)},
					Endpoint:            endpoint,
					PersistentKeepalive: int(keepalive),
				},
			},
		},
		Nftables: &agentconfig.NftablesConfig{
			Interface:     uplinkInterface,
			TunnelNetwork: network,
			Metrics: &agentconfig.NftablesMetrics{
				Port:         metricsPort,
				RelayAddress: relayIP,
			},
			Rules: sortNftRules(nftRules),
		},
	}
	return doc.Marshal()
}

// sortNftRules returns a copy of rules sorted by listen port then protocol so the
// document is deterministic regardless of the input order.
func sortNftRules(rules []agentconfig.NftablesRule) []agentconfig.NftablesRule {
	out := make([]agentconfig.NftablesRule, len(rules))
	copy(out, rules)
	sort.Slice(out, func(i, j int) bool {
		if out[i].ListenPort == out[j].ListenPort {
			return out[i].Protocol < out[j].Protocol
		}
		return out[i].ListenPort < out[j].ListenPort
	})
	return out
}

// defaultTunnelNetwork is the relay network used when the EdgeNode spec leaves
// the tunnel network unset.
const defaultTunnelNetwork = "10.200.0.0/24"

// uplinkReadinessPort is the port each uplink replica serves its readiness
// endpoint on. Envoy health-checks /ready on this port. It must match the
// readiness probe port the uplink container exposes in internal/uplink.
const uplinkReadinessPort int32 = 40500

// resolveEnvoyHealthCheck turns the EdgeNode health-check spec into the render
// input, applying sane defaults for any field left unset. These defaults must
// match the kubebuilder defaults on v1alpha1.HealthCheckSpec.
func resolveEnvoyHealthCheck(hc v1alpha1.HealthCheckSpec) render.EnvoyHealthCheck {
	interval := hc.Interval
	if interval == "" {
		interval = "5s"
	}
	timeout := hc.Timeout
	if timeout == "" {
		timeout = "2s"
	}
	healthy := hc.HealthyThreshold
	if healthy <= 0 {
		healthy = 2
	}
	unhealthy := hc.UnhealthyThreshold
	if unhealthy <= 0 {
		unhealthy = 2
	}
	return render.EnvoyHealthCheck{
		Interval:           interval,
		Timeout:            timeout,
		HealthyThreshold:   healthy,
		UnhealthyThreshold: unhealthy,
		Port:               uplinkReadinessPort,
	}
}

// validateBuildPlanInputs enforces the BuildPlan preconditions, returning a
// descriptive error for the first violation found.
func validateBuildPlanInputs(node *v1alpha1.EdgeNode, resolver TargetResolver, vpsPrivKey, vpsPubKey string, uplinkKeys map[int32]string) error {
	// Guard against a nil node before any dereference.
	if node == nil {
		return fmt.Errorf("node is nil")
	}
	// An empty private key produces a syntactically valid but broken config.
	if vpsPrivKey == "" {
		return fmt.Errorf("vpsPrivKey is empty")
	}
	// The relay public key is the uplink's peer; empty breaks the tunnel.
	if vpsPubKey == "" {
		return fmt.Errorf("vpsPubKey is empty")
	}
	// A nil map is semantically distinct from an empty one; reject it explicitly
	// so the contract is unambiguous.
	if uplinkKeys == nil {
		return fmt.Errorf("uplinkKeys is nil")
	}
	if resolver == nil {
		return fmt.Errorf("resolver is nil")
	}
	return nil
}

// buildRelayPeers builds the WireGuard relay peer list, one entry per uplink
// replica, mapping each ordinal to its tunnel IP and public key.
func buildRelayPeers(ipCalc *ipam.IPAM, uplinkKeys map[int32]string, replicas int32) ([]agentconfig.WireGuardPeer, error) {
	wgPeers := make([]agentconfig.WireGuardPeer, 0, replicas)
	for i := range replicas {
		replicaIP, err := ipCalc.ReplicaIP(i)
		if err != nil {
			// Wrap with the phase and ordinal for context.
			return nil, fmt.Errorf("wg peers: replica %d ip: %w", i, err)
		}
		pubKey := uplinkKeys[i]
		if pubKey == "" {
			return nil, fmt.Errorf("uplink key for replica %d is empty", i)
		}
		wgPeers = append(wgPeers, agentconfig.WireGuardPeer{
			PublicKey:  pubKey,
			AllowedIPs: []string{fmt.Sprintf("%s/32", replicaIP)},
		})
	}
	return wgPeers, nil
}

// reservedPorts are listen ports the data path claims for itself on the VPS:
// the uplink readiness endpoint Envoy health-checks (40500) and the Envoy admin
// interface / metrics DNAT (40600). A PortBinding on either would silently
// shadow or break the infrastructure, so the planner rejects the collision
// with a precise message.
var reservedPorts = map[int32]string{
	uplinkReadinessPort: "uplink readiness endpoint",
	metricsPort:         "Envoy admin/metrics",
}

// portProtocolKey defines a composite key combining a transmission protocol
// and a target listen port to check for socket collisions.
type portProtocolKey struct {
	protocol string
	port     int32
}

// portOwner holds the owning Kubernetes PortBinding resource identifier
// and the individual binding definition name to assist in precise conflict reporting.
type portOwner struct {
	owner       string
	bindingName string
}

// collectBindingDefs flattens every PortBindingDefinition across the active
// PortBindings, rejecting collisions with the tunnel listenPort, the reserved
// infrastructure ports and duplicate listen ports, and returns them sorted by
// ListenPort for deterministic output.
func collectBindingDefs(bindings []v1alpha1.PortBinding, listenPort int32) ([]v1alpha1.PortBindingDefinition, error) {
	usedPorts := make(map[portProtocolKey]portOwner)
	usedNames := make(map[string]string)
	var allDefs []v1alpha1.PortBindingDefinition
	for _, pb := range bindings {
		for _, def := range pb.Spec.Bindings {
			if def.ListenPort == listenPort {
				return nil, fmt.Errorf("binding %s uses tunnel listenPort %d", def.Name, listenPort)
			}
			if owner, reserved := reservedPorts[def.ListenPort]; reserved {
				return nil, fmt.Errorf("binding %s uses port %d, reserved for the %s", def.Name, def.ListenPort, owner)
			}
			owner := pb.Namespace + "/" + pb.Name
			key := portProtocolKey{protocol: def.Protocol, port: def.ListenPort}
			if existing, ok := usedPorts[key]; ok {
				return nil, fmt.Errorf("port conflict on %s/%d between PortBinding %s (binding %s) and %s (binding %s)",
					def.Protocol, def.ListenPort, existing.owner, existing.bindingName, owner, def.Name)
			}
			// Binding names must be unique across every PortBinding aggregated
			// into this node's plan, not just within one CR: the name keys the
			// Envoy listener (duplicates break the LDS update) and the SDS
			// document path on the VPS (duplicates silently serve one binding's
			// certificate for the other). The CRD listMapKey only guards a
			// single CR, so the cross-CR check lives here.
			if existing, ok := usedNames[def.Name]; ok {
				return nil, fmt.Errorf("binding name %q used by both %s and %s", def.Name, existing, owner)
			}
			usedNames[def.Name] = owner
			usedPorts[key] = portOwner{
				owner:       owner,
				bindingName: def.Name,
			}
			allDefs = append(allDefs, def)
		}
	}

	sort.Slice(allDefs, func(i, j int) bool {
		if allDefs[i].ListenPort == allDefs[j].ListenPort {
			return allDefs[i].Protocol < allDefs[j].Protocol
		}
		return allDefs[i].ListenPort < allDefs[j].ListenPort
	})
	return allDefs, nil
}

// tlsDir is the directory on the VPS holding the per-binding SDS documents. It
// is the watched_directory Envoy monitors for atomic moves to hot-reload a
// rotated certificate without bouncing connections.
const tlsDir = "/etc/envoy/tls"

// tlsSDSPath returns the VPS path for the SDS document of a binding.
func tlsSDSPath(bindingName string) string {
	return tlsDir + "/" + bindingName + ".sds.yaml"
}

// tlsCertSecretName returns the SDS secret name for a binding's server cert/key.
func tlsCertSecretName(bindingName string) string {
	return bindingName
}

// tlsCASecretName returns the SDS secret name for a binding's client-CA context.
func tlsCASecretName(bindingName string) string {
	return bindingName + "-ca"
}

// buildTLSConfig converts a v1alpha1.TLSConfig into a render.EnvoyTLSConfig
// using deterministic VPS SDS paths and secret names derived from bindingName.
// It returns an error when mode is offload or mutual and SecretRef is nil
// (belt-and-suspenders check; CEL already rejects this at admission time).
func buildTLSConfig(bindingName string, cfg *v1alpha1.TLSConfig) (*render.EnvoyTLSConfig, error) {
	if cfg == nil {
		return nil, nil
	}
	switch cfg.Mode {
	case "passthrough":
		// SNI routing: Envoy forwards raw TLS bytes, no cert material needed.
		return &render.EnvoyTLSConfig{Mode: "passthrough"}, nil
	case "offload":
		if cfg.SecretRef == nil {
			return nil, fmt.Errorf("binding %s: mode offload requires a secretRef", bindingName)
		}
		return &render.EnvoyTLSConfig{
			Mode:           "offload",
			SDSPath:        tlsSDSPath(bindingName),
			WatchedDir:     tlsDir,
			CertSecretName: tlsCertSecretName(bindingName),
		}, nil
	case "mutual":
		if cfg.SecretRef == nil {
			return nil, fmt.Errorf("binding %s: mode mutual requires a secretRef", bindingName)
		}
		return &render.EnvoyTLSConfig{
			Mode:           "mutual",
			SDSPath:        tlsSDSPath(bindingName),
			WatchedDir:     tlsDir,
			CertSecretName: tlsCertSecretName(bindingName),
			CASecretName:   tlsCASecretName(bindingName),
		}, nil
	default:
		return nil, fmt.Errorf("binding %s: unknown TLS mode %q", bindingName, cfg.Mode)
	}
}

// buildEnvoyListeners turns the sorted binding definitions into Envoy listeners
// (with one upstream per replica) and their matching nftables DNAT rules.
func buildEnvoyListeners(allDefs []v1alpha1.PortBindingDefinition, resolver TargetResolver, ipCalc *ipam.IPAM, replicas int32, healthCheck render.EnvoyHealthCheck) ([]render.EnvoyListener, []agentconfig.NftablesRule, error) {
	var envoyListeners []render.EnvoyListener
	var nftRules []agentconfig.NftablesRule

	for _, def := range allDefs {
		targetIP, targetPort, err := resolveTarget(def, resolver)
		if err != nil {
			return nil, nil, err
		}

		tlsCfg, err := buildTLSConfig(def.Name, def.TLS)
		if err != nil {
			return nil, nil, err
		}

		listener := render.EnvoyListener{
			Name:       def.Name,
			Protocol:   def.Protocol,
			ListenPort: def.ListenPort,
			TLS:        tlsCfg,
		}

		for i := range replicas {
			replicaIP, err := ipCalc.ReplicaIP(i)
			if err != nil {
				// Wrap with the phase and ordinal for context.
				return nil, nil, fmt.Errorf("envoy upstreams: replica %d ip: %w", i, err)
			}
			listener.Upstreams = append(listener.Upstreams, render.EnvoyUpstreamServer{
				IP:   replicaIP,
				Port: def.ListenPort,
			})
		}

		listener.HealthCheck = healthCheck
		if err := applyProtocolDefaults(&listener, def); err != nil {
			return nil, nil, err
		}
		envoyListeners = append(envoyListeners, listener)

		nftRules = append(nftRules, agentconfig.NftablesRule{
			Protocol:   def.Protocol,
			ListenPort: int(def.ListenPort),
			TargetIP:   targetIP,
			TargetPort: int(targetPort),
		})
	}
	return envoyListeners, nftRules, nil
}

// resolveTarget returns the destination IP and port for a binding, resolving a
// Service reference via resolver or validating a direct address/port target.
func resolveTarget(def v1alpha1.PortBindingDefinition, resolver TargetResolver) (string, int32, error) {
	if def.Target.Service != nil {
		ip, err := resolver.ResolveService(def.Target.Service.Namespace, def.Target.Service.Name)
		if err != nil {
			return "", 0, fmt.Errorf("failed to resolve service for %s: %w", def.Name, err)
		}
		return ip, def.Target.Service.Port, nil
	}
	// Validate the address and port in the direct-target branch.
	if def.Target.Address == "" {
		return "", 0, fmt.Errorf("binding %s: target address is empty", def.Name)
	}
	if def.Target.Port <= 0 {
		return "", 0, fmt.Errorf("binding %s: target port must be > 0, got %d", def.Name, def.Target.Port)
	}
	return def.Target.Address, def.Target.Port, nil
}

// applyProtocolDefaults copies the protocol-specific tuning from the binding
// definition into the listener and fills in the default timeouts when unset.
func applyProtocolDefaults(listener *render.EnvoyListener, def v1alpha1.PortBindingDefinition) error {
	if def.Protocol == "TCP" {
		if def.TCP != nil {
			listener.TCP.ProxyProtocol = def.TCP.ProxyProtocol
			listener.TCP.ConnectTimeout = def.TCP.ConnectTimeout
			listener.TCP.IdleTimeout = def.TCP.IdleTimeout
		}
		if listener.TCP.ConnectTimeout == "" {
			listener.TCP.ConnectTimeout = "5s"
		}
		if listener.TCP.IdleTimeout == "" {
			listener.TCP.IdleTimeout = "3600s"
		}

		var err error
		listener.TCP.ConnectTimeout, err = normalizeEnvoyDuration(listener.TCP.ConnectTimeout)
		if err != nil {
			return fmt.Errorf("binding %s: invalid TCP ConnectTimeout: %w", def.Name, err)
		}
		listener.TCP.IdleTimeout, err = normalizeEnvoyDuration(listener.TCP.IdleTimeout)
		if err != nil {
			return fmt.Errorf("binding %s: invalid TCP IdleTimeout: %w", def.Name, err)
		}
		return nil
	}
	if def.UDP != nil {
		listener.UDP.SessionTimeout = def.UDP.SessionTimeout
	}
	if listener.UDP.SessionTimeout == "" {
		listener.UDP.SessionTimeout = "60s"
	}

	var err error
	listener.UDP.SessionTimeout, err = normalizeEnvoyDuration(listener.UDP.SessionTimeout)
	if err != nil {
		return fmt.Errorf("binding %s: invalid UDP SessionTimeout: %w", def.Name, err)
	}
	return nil
}

// normalizeEnvoyDuration parses a Go duration string and converts it to the
// Envoy-compatible integer seconds format with a trailing "s". It ensures
// any user-supplied duration is properly structured as an integer seconds
// value to prevent protobuf duration parsing failures inside Envoy.
func normalizeEnvoyDuration(s string) (string, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%ds", int64(d.Seconds())), nil
}

// buildTLSMaterials produces one TLSMaterial entry for each binding that needs
// cert/key material pushed to the VPS (offload and mutual modes). Passthrough
// bindings are excluded because they never push a private key to the edge. It
// takes the PortBindings, not the flattened defs, so an omitted secretRef
// namespace resolves to the owning PortBinding's namespace per the
// SecretReference API contract; flattening first would lose it and the
// controller would look in the EdgeNode's namespace instead. The result is
// sorted by BindingName for deterministic output.
func buildTLSMaterials(bindings []v1alpha1.PortBinding) ([]TLSMaterial, error) {
	var materials []TLSMaterial
	for _, pb := range bindings {
		for _, def := range pb.Spec.Bindings {
			if def.TLS == nil {
				continue
			}
			switch def.TLS.Mode {
			case "passthrough":
				// No material to push; TLS bytes are forwarded as-is.
				continue
			case "offload":
				if def.TLS.SecretRef == nil {
					return nil, fmt.Errorf("binding %s: mode offload requires a secretRef", def.Name)
				}
				materials = append(materials, TLSMaterial{
					BindingName:     def.Name,
					SecretName:      def.TLS.SecretRef.Name,
					SecretNamespace: tlsSecretNamespace(def.TLS.SecretRef.Namespace, pb.Namespace),
					Mode:            "offload",
					SDSPath:         tlsSDSPath(def.Name),
					CertSecretName:  tlsCertSecretName(def.Name),
				})
			case "mutual":
				if def.TLS.SecretRef == nil {
					return nil, fmt.Errorf("binding %s: mode mutual requires a secretRef", def.Name)
				}
				materials = append(materials, TLSMaterial{
					BindingName:     def.Name,
					SecretName:      def.TLS.SecretRef.Name,
					SecretNamespace: tlsSecretNamespace(def.TLS.SecretRef.Namespace, pb.Namespace),
					Mode:            "mutual",
					SDSPath:         tlsSDSPath(def.Name),
					CertSecretName:  tlsCertSecretName(def.Name),
					CASecretName:    tlsCASecretName(def.Name),
				})
			default:
				return nil, fmt.Errorf("binding %s: unknown TLS mode %q", def.Name, def.TLS.Mode)
			}
		}
	}
	sort.Slice(materials, func(i, j int) bool {
		return materials[i].BindingName < materials[j].BindingName
	})
	return materials, nil
}

// tlsSecretNamespace resolves the namespace a TLS Secret lives in: the explicit
// secretRef namespace when set, otherwise the owning PortBinding's namespace,
// matching the SecretReference contract that an omitted namespace defaults to
// the owner's. It is never empty for a binding that carries a secretRef.
func tlsSecretNamespace(refNamespace, ownerNamespace string) string {
	if refNamespace != "" {
		return refNamespace
	}
	return ownerNamespace
}
