// SPDX-FileCopyrightText: 2026 Alby Hernández (Achetronic)
// SPDX-License-Identifier: Apache-2.0

package planner

import (
	"fmt"
	"strings"
	"testing"

	"github.com/achetronic/tunnel/api/v1alpha1"
	"github.com/achetronic/tunnel/internal/agentconfig"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// testVPSAddress is a documentation-range IP (RFC 5737) used as the EdgeNode
// public address in document tests.
const testVPSAddress = "203.0.113.10"

// mockResolver implements TargetResolver using an in-memory lookup table.
type mockResolver struct {
	ip map[string]string
	// errOnKey causes ResolveService to return an error for the given "ns/name" key.
	errOnKey string
}

// ResolveService returns the ClusterIP for the given namespace/name pair.
// If errOnKey is set and matches, it returns an error to simulate a failing resolver.
func (m mockResolver) ResolveService(ns, name string) (string, error) {
	if m.errOnKey == ns+"/"+name {
		return "", fmt.Errorf("resolver: service %s/%s not found", ns, name)
	}
	key := ns + "/" + name
	if val, ok := m.ip[key]; ok {
		return val, nil
	}
	return "", fmt.Errorf("not found")
}

// makeNode returns a minimal but fully valid EdgeNode for tests.
func makeNode() *v1alpha1.EdgeNode {
	node := &v1alpha1.EdgeNode{}
	node.Spec.Tunnel.Network = defaultTunnelNetwork
	node.Spec.Tunnel.ListenPort = 51821
	node.Spec.Uplink.Replicas = 2
	return node
}

func TestBuildPlan(t *testing.T) {
	node := makeNode()

	resolver := mockResolver{
		ip: map[string]string{
			"default/svc1": "10.96.1.1",
		},
	}

	keys := map[int32]string{
		0: "pub0",
		1: "pub1",
	}

	bindings := []v1alpha1.PortBinding{
		{
			Spec: v1alpha1.PortBindingSpec{
				Bindings: []v1alpha1.PortBindingDefinition{
					{
						Name:       "test1",
						Protocol:   "TCP",
						ListenPort: 80,
						Target: v1alpha1.BindingTarget{
							Service: &v1alpha1.TargetServiceRef{
								Namespace: "default",
								Name:      "svc1",
								Port:      8080,
							},
						},
					},
					{
						Name:       "test2",
						Protocol:   "UDP",
						ListenPort: 53,
						Target: v1alpha1.BindingTarget{
							Address: "8.8.8.8",
							Port:    53,
						},
					},
				},
			},
		},
	}

	plan1, err := BuildPlan(node, bindings, resolver, "priv", "pub", keys)
	if err != nil {
		t.Fatal(err)
	}

	plan2, err := BuildPlan(node, bindings, resolver, "priv", "pub", keys)
	if err != nil {
		t.Fatal(err)
	}

	if plan1.PlanHash != plan2.PlanHash {
		t.Fatal("hashes are not stable")
	}

	if plan1.EnvoyLDSHash != plan2.EnvoyLDSHash {
		t.Fatal("LDS hashes are not stable")
	}

	if plan1.EnvoyCDSHash != plan2.EnvoyCDSHash {
		t.Fatal("CDS hashes are not stable")
	}

	if len(plan1.EnvoyLDS) == 0 {
		t.Fatal("EnvoyLDS is empty")
	}

	if len(plan1.EnvoyCDS) == 0 {
		t.Fatal("EnvoyCDS is empty")
	}

	// The applied artifacts and their hashes must be populated.
	if plan1.RelayDocumentHash == "" {
		t.Fatal("RelayDocumentHash is empty")
	}
	if plan1.UplinkDocumentHash == "" {
		t.Fatal("UplinkDocumentHash is empty")
	}

	// Conflict test
	bindingsConflict := []v1alpha1.PortBinding{
		{
			Spec: v1alpha1.PortBindingSpec{
				Bindings: []v1alpha1.PortBindingDefinition{
					{ListenPort: 80, Name: "a"},
					{ListenPort: 80, Name: "b"},
				},
			},
		},
	}
	_, err = BuildPlan(node, bindingsConflict, resolver, "priv", "pub", keys)
	if err == nil {
		t.Fatal("expected conflict error")
	}

	// Tunnel port conflict test
	bindingsTunnelPort := []v1alpha1.PortBinding{
		{
			Spec: v1alpha1.PortBindingSpec{
				Bindings: []v1alpha1.PortBindingDefinition{
					{ListenPort: 51821, Name: "a"},
				},
			},
		},
	}
	_, err = BuildPlan(node, bindingsTunnelPort, resolver, "priv", "pub", keys)
	if err == nil {
		t.Fatal("expected tunnel port conflict error")
	}

	// Binding names key the Envoy listener and the SDS document path, so a
	// duplicate across two PortBindings must be rejected even when the ports
	// differ. Within one CR the CRD listMapKey already forbids it; this guards
	// the cross-CR aggregate.
	bindingsDupName := []v1alpha1.PortBinding{
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "pb-a"},
			Spec: v1alpha1.PortBindingSpec{
				Bindings: []v1alpha1.PortBindingDefinition{
					{ListenPort: 80, Name: "web", Target: v1alpha1.BindingTarget{Address: "10.0.0.1", Port: 80}},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "team-b", Name: "pb-b"},
			Spec: v1alpha1.PortBindingSpec{
				Bindings: []v1alpha1.PortBindingDefinition{
					{ListenPort: 443, Name: "web", Target: v1alpha1.BindingTarget{Address: "10.0.0.2", Port: 443}},
				},
			},
		},
	}
	_, err = BuildPlan(node, bindingsDupName, resolver, "priv", "pub", keys)
	if err == nil {
		t.Fatal("expected duplicate binding name error")
	}
	if !strings.Contains(err.Error(), "team-a/pb-a") || !strings.Contains(err.Error(), "team-b/pb-b") {
		t.Fatalf("duplicate name error must identify both PortBindings, got: %v", err)
	}

	// Reserved infrastructure ports (TODO #18): the uplink readiness
	// endpoint and the Envoy admin/metrics port must be rejected.
	for _, port := range []int32{40500, 40600} {
		bindingsReserved := []v1alpha1.PortBinding{
			{
				Spec: v1alpha1.PortBindingSpec{
					Bindings: []v1alpha1.PortBindingDefinition{
						{ListenPort: port, Name: "a"},
					},
				},
			},
		}
		if _, err := BuildPlan(node, bindingsReserved, resolver, "priv", "pub", keys); err == nil {
			t.Fatalf("expected reserved port error for %d", port)
		}
	}
}

// TestBuildPlanErrorCases covers all critical error paths that were missing
// in the original test suite (hallazgo #16).
func TestBuildPlanErrorCases(t *testing.T) {
	goodResolver := mockResolver{
		ip: map[string]string{"default/svc1": "10.96.1.1"},
	}
	goodKeys := map[int32]string{0: "pub0"}
	goodNode := makeNode()
	goodNode.Spec.Uplink.Replicas = 1

	t.Run("node nil", func(t *testing.T) {
		_, err := BuildPlan(nil, nil, goodResolver, "priv", "pub", goodKeys)
		if err == nil {
			t.Fatal("expected error for nil node")
		}
	})

	t.Run("vpsPrivKey empty", func(t *testing.T) {
		_, err := BuildPlan(goodNode, nil, goodResolver, "", "pub", goodKeys)
		if err == nil {
			t.Fatal("expected error for empty vpsPrivKey")
		}
	})

	t.Run("uplinkKeys nil", func(t *testing.T) {
		_, err := BuildPlan(goodNode, nil, goodResolver, "priv", "pub", nil)
		if err == nil {
			t.Fatal("expected error for nil uplinkKeys")
		}
	})

	t.Run("resolver nil", func(t *testing.T) {
		_, err := BuildPlan(goodNode, nil, nil, "priv", "pub", goodKeys)
		if err == nil {
			t.Fatal("expected error for nil resolver")
		}
	})

	t.Run("binding target address empty", func(t *testing.T) {
		bindings := []v1alpha1.PortBinding{
			{
				Spec: v1alpha1.PortBindingSpec{
					Bindings: []v1alpha1.PortBindingDefinition{
						{
							Name:       "bad",
							Protocol:   "TCP",
							ListenPort: 80,
							Target:     v1alpha1.BindingTarget{Address: "", Port: 80},
						},
					},
				},
			},
		}
		_, err := BuildPlan(goodNode, bindings, goodResolver, "priv", "pub", goodKeys)
		if err == nil {
			t.Fatal("expected error for empty target address")
		}
	})

	t.Run("binding target port zero", func(t *testing.T) {
		bindings := []v1alpha1.PortBinding{
			{
				Spec: v1alpha1.PortBindingSpec{
					Bindings: []v1alpha1.PortBindingDefinition{
						{
							Name:       "bad",
							Protocol:   "TCP",
							ListenPort: 80,
							Target:     v1alpha1.BindingTarget{Address: "1.2.3.4", Port: 0},
						},
					},
				},
			},
		}
		_, err := BuildPlan(goodNode, bindings, goodResolver, "priv", "pub", goodKeys)
		if err == nil {
			t.Fatal("expected error for zero target port")
		}
	})

	t.Run("replicas 1 default when zero", func(t *testing.T) {
		node := &v1alpha1.EdgeNode{}
		node.Spec.Tunnel.Network = defaultTunnelNetwork
		node.Spec.Tunnel.ListenPort = 51821
		node.Spec.Uplink.Replicas = 0 // should default to 1
		plan, err := BuildPlan(node, nil, goodResolver, "priv", "pub", goodKeys)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if plan == nil {
			t.Fatal("expected non-nil plan")
		}
	})

	t.Run("resolver returns error", func(t *testing.T) {
		errResolver := mockResolver{
			errOnKey: "default/svc1",
		}
		bindings := []v1alpha1.PortBinding{
			{
				Spec: v1alpha1.PortBindingSpec{
					Bindings: []v1alpha1.PortBindingDefinition{
						{
							Name:       "svc-binding",
							Protocol:   "TCP",
							ListenPort: 80,
							Target: v1alpha1.BindingTarget{
								Service: &v1alpha1.TargetServiceRef{
									Namespace: "default",
									Name:      "svc1",
									Port:      8080,
								},
							},
						},
					},
				},
			},
		}
		_, err := BuildPlan(goodNode, bindings, errResolver, "priv", "pub", goodKeys)
		if err == nil {
			t.Fatal("expected error from failing resolver")
		}
		// Verify error carries a non-empty message with context.
		if err.Error() == "" {
			t.Fatal("error message is empty")
		}
	})

	t.Run("invalid ConnectTimeout", func(t *testing.T) {
		bindings := []v1alpha1.PortBinding{
			{
				Spec: v1alpha1.PortBindingSpec{
					Bindings: []v1alpha1.PortBindingDefinition{
						{
							Name:       "bad",
							Protocol:   "TCP",
							ListenPort: 80,
							Target:     v1alpha1.BindingTarget{Address: "1.2.3.4", Port: 80},
							TCP: &v1alpha1.TCPParams{
								ConnectTimeout: "invalid-duration",
							},
						},
					},
				},
			},
		}
		_, err := BuildPlan(goodNode, bindings, goodResolver, "priv", "pub", goodKeys)
		if err == nil {
			t.Fatal("expected error for invalid TCP ConnectTimeout")
		}
	})

	t.Run("invalid IdleTimeout", func(t *testing.T) {
		bindings := []v1alpha1.PortBinding{
			{
				Spec: v1alpha1.PortBindingSpec{
					Bindings: []v1alpha1.PortBindingDefinition{
						{
							Name:       "bad",
							Protocol:   "TCP",
							ListenPort: 80,
							Target:     v1alpha1.BindingTarget{Address: "1.2.3.4", Port: 80},
							TCP: &v1alpha1.TCPParams{
								IdleTimeout: "invalid-duration",
							},
						},
					},
				},
			},
		}
		_, err := BuildPlan(goodNode, bindings, goodResolver, "priv", "pub", goodKeys)
		if err == nil {
			t.Fatal("expected error for invalid TCP IdleTimeout")
		}
	})

	t.Run("invalid UDP SessionTimeout", func(t *testing.T) {
		bindings := []v1alpha1.PortBinding{
			{
				Spec: v1alpha1.PortBindingSpec{
					Bindings: []v1alpha1.PortBindingDefinition{
						{
							Name:       "bad",
							Protocol:   "UDP",
							ListenPort: 80,
							Target:     v1alpha1.BindingTarget{Address: "1.2.3.4", Port: 80},
							UDP: &v1alpha1.UDPParams{
								SessionTimeout: "invalid-duration",
							},
						},
					},
				},
			},
		}
		_, err := BuildPlan(goodNode, bindings, goodResolver, "priv", "pub", goodKeys)
		if err == nil {
			t.Fatal("expected error for invalid UDP SessionTimeout")
		}
	})
}

// TestResolveEnvoyHealthCheck_Defaults verifies that a zero-value HealthCheckSpec
// yields the sane defaults: interval 5s, timeout 2s, healthy 2, unhealthy 2,
// port uplinkReadinessPort (40500).
func TestResolveEnvoyHealthCheck_Defaults(t *testing.T) {
	hc := resolveEnvoyHealthCheck(v1alpha1.HealthCheckSpec{})
	if hc.Interval != "5s" {
		t.Errorf("Interval: want %q, got %q", "5s", hc.Interval)
	}
	if hc.Timeout != "2s" {
		t.Errorf("Timeout: want %q, got %q", "2s", hc.Timeout)
	}
	if hc.HealthyThreshold != 2 {
		t.Errorf("HealthyThreshold: want 2, got %d", hc.HealthyThreshold)
	}
	if hc.UnhealthyThreshold != 2 {
		t.Errorf("UnhealthyThreshold: want 2, got %d", hc.UnhealthyThreshold)
	}
	if hc.Port != uplinkReadinessPort {
		t.Errorf("Port: want %d, got %d", uplinkReadinessPort, hc.Port)
	}
}

// TestResolveEnvoyHealthCheck_NonDefault verifies that explicitly provided fields
// are preserved while unset fields still fall back to defaults.
func TestResolveEnvoyHealthCheck_NonDefault(t *testing.T) {
	hc := resolveEnvoyHealthCheck(v1alpha1.HealthCheckSpec{
		Interval:           "10s",
		UnhealthyThreshold: 3,
	})
	if hc.Interval != "10s" {
		t.Errorf("Interval: want %q, got %q", "10s", hc.Interval)
	}
	if hc.Timeout != "2s" {
		t.Errorf("Timeout: want default %q, got %q", "2s", hc.Timeout)
	}
	if hc.HealthyThreshold != 2 {
		t.Errorf("HealthyThreshold: want default 2, got %d", hc.HealthyThreshold)
	}
	if hc.UnhealthyThreshold != 3 {
		t.Errorf("UnhealthyThreshold: want 3, got %d", hc.UnhealthyThreshold)
	}
	if hc.Port != uplinkReadinessPort {
		t.Errorf("Port: want %d, got %d", uplinkReadinessPort, hc.Port)
	}
}

// TestBuildPlan_HealthCheckDefaults verifies that a default EdgeNode (zero
// HealthCheckSpec) produces a CDS output that contains the sane defaults
// (interval 5s, timeout 2s, unhealthy 2, healthy 2, port 40500).
func TestBuildPlan_HealthCheckDefaults(t *testing.T) {
	node := makeNode()
	// node.Spec.Edge.HealthCheck is zero-valued; defaults must apply.
	bindings := []v1alpha1.PortBinding{
		{
			Spec: v1alpha1.PortBindingSpec{
				Bindings: []v1alpha1.PortBindingDefinition{
					{
						Name:       "http",
						Protocol:   "TCP",
						ListenPort: 80,
						Target: v1alpha1.BindingTarget{
							Address: "10.0.0.1",
							Port:    8080,
						},
					},
				},
			},
		},
	}

	plan, err := BuildPlan(node, bindings, mockResolver{}, "priv", "pub", map[int32]string{0: "pub0", 1: "pub1"})
	if err != nil {
		t.Fatal(err)
	}
	cds := string(plan.EnvoyCDS)
	for _, want := range []string{
		"timeout: 2s",
		"interval: 5s",
		"unhealthy_threshold: 2",
		"healthy_threshold: 2",
		"port_value: 40500",
	} {
		if !strings.Contains(cds, want) {
			t.Errorf("CDS must contain %q;\nCDS:\n%s", want, cds)
		}
	}
}

// TestBuildPlan_HealthCheckNonDefault verifies that a non-default HealthCheckSpec
// on the EdgeNode flows through to the rendered CDS output.
func TestBuildPlan_HealthCheckNonDefault(t *testing.T) {
	node := makeNode()
	node.Spec.Edge.HealthCheck = v1alpha1.HealthCheckSpec{
		Interval:           "10s",
		UnhealthyThreshold: 3,
	}
	bindings := []v1alpha1.PortBinding{
		{
			Spec: v1alpha1.PortBindingSpec{
				Bindings: []v1alpha1.PortBindingDefinition{
					{
						Name:       "http",
						Protocol:   "TCP",
						ListenPort: 80,
						Target: v1alpha1.BindingTarget{
							Address: "10.0.0.1",
							Port:    8080,
						},
					},
				},
			},
		},
	}

	plan, err := BuildPlan(node, bindings, mockResolver{}, "priv", "pub", map[int32]string{0: "pub0", 1: "pub1"})
	if err != nil {
		t.Fatal(err)
	}
	cds := string(plan.EnvoyCDS)
	if !strings.Contains(cds, "interval: 10s") {
		t.Errorf("CDS must contain %q;\nCDS:\n%s", "interval: 10s", cds)
	}
	if !strings.Contains(cds, "unhealthy_threshold: 3") {
		t.Errorf("CDS must contain %q;\nCDS:\n%s", "unhealthy_threshold: 3", cds)
	}
	// Timeout and HealthyThreshold must still use defaults.
	if !strings.Contains(cds, "timeout: 2s") {
		t.Errorf("CDS must contain default %q;\nCDS:\n%s", "timeout: 2s", cds)
	}
	if !strings.Contains(cds, "healthy_threshold: 2") {
		t.Errorf("CDS must contain default %q;\nCDS:\n%s", "healthy_threshold: 2", cds)
	}
}

// TestBuildPlan_RelayDocument verifies that the relay tunnelctl document is a
// complete, valid agentconfig with the relay interface and one peer per replica
// and no nftables section.
func TestBuildPlan_RelayDocument(t *testing.T) {
	node := makeNode()
	node.Spec.Address = testVPSAddress
	keys := map[int32]string{0: "pub0", 1: "pub1"}

	plan, err := BuildPlan(node, nil, mockResolver{}, "relaypriv", "relaypub", keys)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.RelayDocument) == 0 || plan.RelayDocumentHash == "" {
		t.Fatal("RelayDocument or its hash is empty")
	}

	// The relay document is complete: Parse (decode + validate) must succeed.
	doc, err := agentconfig.Parse(plan.RelayDocument)
	if err != nil {
		t.Fatalf("relay document does not validate: %v", err)
	}
	if doc.WireGuard.Interface.Name != "wg-relay" {
		t.Errorf("relay interface name = %q, want wg-relay", doc.WireGuard.Interface.Name)
	}
	if doc.WireGuard.Interface.PrivateKey != "relaypriv" {
		t.Errorf("relay private key = %q, want relaypriv", doc.WireGuard.Interface.PrivateKey)
	}
	if doc.WireGuard.Interface.ListenPort != 51821 {
		t.Errorf("relay listenPort = %d, want 51821", doc.WireGuard.Interface.ListenPort)
	}
	if doc.WireGuard.Interface.Address != "10.200.0.1/24" {
		t.Errorf("relay address = %q, want 10.200.0.1/24", doc.WireGuard.Interface.Address)
	}
	if len(doc.WireGuard.Peers) != 2 {
		t.Fatalf("relay peers = %d, want 2", len(doc.WireGuard.Peers))
	}
	if doc.Nftables != nil {
		t.Error("relay document must not carry an nftables section")
	}
	// Relay peers have no endpoint or keepalive: the uplinks dial in.
	for i, p := range doc.WireGuard.Peers {
		if p.Endpoint != "" {
			t.Errorf("relay peer[%d] endpoint = %q, want empty", i, p.Endpoint)
		}
		if p.PersistentKeepalive != 0 {
			t.Errorf("relay peer[%d] keepalive = %d, want 0", i, p.PersistentKeepalive)
		}
	}
}

// TestBuildPlan_UplinkDocument verifies the shared uplink tunnelctl document:
// it carries the relay peer and the full nftables ruleset, leaves the per-replica
// identity (private key + address) empty so it does not validate as-is, and
// becomes valid once that identity is injected at runtime.
func TestBuildPlan_UplinkDocument(t *testing.T) {
	node := makeNode()
	node.Spec.Address = testVPSAddress
	keys := map[int32]string{0: "pub0", 1: "pub1"}

	bindings := []v1alpha1.PortBinding{
		{
			Spec: v1alpha1.PortBindingSpec{
				Bindings: []v1alpha1.PortBindingDefinition{
					{
						Name:       "http",
						Protocol:   "TCP",
						ListenPort: 80,
						Target: v1alpha1.BindingTarget{
							Address: "10.96.1.1",
							Port:    8080,
						},
					},
					{
						Name:       "dns",
						Protocol:   "UDP",
						ListenPort: 53,
						Target: v1alpha1.BindingTarget{
							Address: "10.96.1.2",
							Port:    53,
						},
					},
				},
			},
		},
	}

	plan, err := BuildPlan(node, bindings, mockResolver{}, "relaypriv", "relaypub", keys)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.UplinkDocument) == 0 || plan.UplinkDocumentHash == "" {
		t.Fatal("UplinkDocument or its hash is empty")
	}

	// The template is intentionally incomplete: it must decode but NOT validate,
	// because the private key and address are injected per replica at runtime.
	doc, err := agentconfig.Decode(plan.UplinkDocument)
	if err != nil {
		t.Fatalf("uplink document does not decode: %v", err)
	}
	if err := doc.Validate(); err == nil {
		t.Fatal("uplink template must not validate before identity injection")
	}

	if doc.WireGuard.Interface.Name != "wg-uplink" {
		t.Errorf("uplink interface name = %q, want wg-uplink", doc.WireGuard.Interface.Name)
	}
	if doc.WireGuard.Interface.PrivateKey != "" {
		t.Errorf("uplink private key = %q, want empty (runtime-injected)", doc.WireGuard.Interface.PrivateKey)
	}
	if doc.WireGuard.Interface.Address != "" {
		t.Errorf("uplink address = %q, want empty (runtime-injected)", doc.WireGuard.Interface.Address)
	}
	if doc.WireGuard.Interface.ListenPort != 0 {
		t.Errorf("uplink listenPort = %d, want 0 (dials out only)", doc.WireGuard.Interface.ListenPort)
	}
	if doc.WireGuard.Interface.MTU != 1420 {
		t.Errorf("uplink mtu = %d, want 1420", doc.WireGuard.Interface.MTU)
	}

	// Exactly one peer: the relay.
	if len(doc.WireGuard.Peers) != 1 {
		t.Fatalf("uplink peers = %d, want 1", len(doc.WireGuard.Peers))
	}
	peer := doc.WireGuard.Peers[0]
	if peer.PublicKey != "relaypub" {
		t.Errorf("uplink peer public key = %q, want relaypub", peer.PublicKey)
	}
	if peer.Endpoint != testVPSAddress+":51821" {
		t.Errorf("uplink peer endpoint = %q, want 203.0.113.10:51821", peer.Endpoint)
	}
	if peer.PersistentKeepalive != 25 {
		t.Errorf("uplink peer keepalive = %d, want 25", peer.PersistentKeepalive)
	}
	if len(peer.AllowedIPs) != 1 || peer.AllowedIPs[0] != "10.200.0.1/32" {
		t.Errorf("uplink peer allowedIPs = %v, want [10.200.0.1/32]", peer.AllowedIPs)
	}

	// Nftables section: self-contained, with metrics and one rule per binding.
	if doc.Nftables == nil {
		t.Fatal("uplink document must carry an nftables section")
	}
	if doc.Nftables.Interface != "wg-uplink" {
		t.Errorf("nftables interface = %q, want wg-uplink", doc.Nftables.Interface)
	}
	if doc.Nftables.TunnelNetwork != "10.200.0.0/24" {
		t.Errorf("nftables tunnelNetwork = %q, want 10.200.0.0/24", doc.Nftables.TunnelNetwork)
	}
	if doc.Nftables.Metrics == nil {
		t.Fatal("nftables metrics must be set")
	}
	if doc.Nftables.Metrics.Port != 40600 || doc.Nftables.Metrics.RelayAddress != "10.200.0.1" {
		t.Errorf("nftables metrics = %+v, want {Port:40600 RelayAddress:10.200.0.1}", doc.Nftables.Metrics)
	}
	if len(doc.Nftables.Rules) != 2 {
		t.Fatalf("nftables rules = %d, want 2", len(doc.Nftables.Rules))
	}
	// Rules are sorted by listen port: dns (53) before http (80).
	if doc.Nftables.Rules[0].ListenPort != 53 || doc.Nftables.Rules[0].Protocol != "UDP" {
		t.Errorf("nftables rule[0] = %+v, want UDP/53", doc.Nftables.Rules[0])
	}
	if doc.Nftables.Rules[1].ListenPort != 80 || doc.Nftables.Rules[1].Protocol != "TCP" {
		t.Errorf("nftables rule[1] = %+v, want TCP/80", doc.Nftables.Rules[1])
	}

	// Once the runtime injects the per-replica identity, the document validates.
	doc.WireGuard.Interface.PrivateKey = "replicapriv"
	doc.WireGuard.Interface.Address = "10.200.0.2/32"
	if err := doc.Validate(); err != nil {
		t.Fatalf("uplink document must validate after identity injection: %v", err)
	}
}

// TestBuildPlan_UplinkDocumentDeterministic verifies that two builds from the
// same inputs produce byte-identical uplink documents and hashes.
func TestBuildPlan_UplinkDocumentDeterministic(t *testing.T) {
	node := makeNode()
	node.Spec.Address = testVPSAddress
	keys := map[int32]string{0: "pub0", 1: "pub1"}
	bindings := []v1alpha1.PortBinding{
		{
			Spec: v1alpha1.PortBindingSpec{
				Bindings: []v1alpha1.PortBindingDefinition{
					{Name: "http", Protocol: "TCP", ListenPort: 80, Target: v1alpha1.BindingTarget{Address: "10.96.1.1", Port: 8080}},
				},
			},
		},
	}

	p1, err := BuildPlan(node, bindings, mockResolver{}, "relaypriv", "relaypub", keys)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := BuildPlan(node, bindings, mockResolver{}, "relaypriv", "relaypub", keys)
	if err != nil {
		t.Fatal(err)
	}
	if string(p1.UplinkDocument) != string(p2.UplinkDocument) {
		t.Error("UplinkDocument is not deterministic")
	}
	if p1.UplinkDocumentHash != p2.UplinkDocumentHash {
		t.Error("UplinkDocumentHash is not deterministic")
	}
	if p1.RelayDocumentHash != p2.RelayDocumentHash {
		t.Error("RelayDocumentHash is not deterministic")
	}
}

// TestBuildPlan_EmptyVPSPubKey verifies BuildPlan rejects an empty relay public
// key, since it would produce a non-functional uplink tunnel.
func TestBuildPlan_EmptyVPSPubKey(t *testing.T) {
	node := makeNode()
	_, err := BuildPlan(node, nil, mockResolver{}, "priv", "", map[int32]string{0: "pub0", 1: "pub1"})
	if err == nil {
		t.Fatal("expected error for empty vpsPubKey")
	}
	if !strings.Contains(err.Error(), "vpsPubKey") {
		t.Errorf("error = %q, want it to mention vpsPubKey", err.Error())
	}
}

// TestBuildPlan_ProtocolAwarePortConflict checks that distinct protocol bindings
// on the same port do not collide, while identical protocol bindings on the same
// port are still rejected. It also checks that reserved ports are rejected regardless of protocol.
func TestBuildPlan_ProtocolAwarePortConflict(t *testing.T) {
	node := makeNode()
	node.Spec.Address = testVPSAddress
	keys := map[int32]string{0: "pub0", 1: "pub1"}

	// Positive test: PortBinding with TCP/53 and UDP/53 on the same port should succeed.
	bindingsPositive := []v1alpha1.PortBinding{
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "pb-tcp"},
			Spec: v1alpha1.PortBindingSpec{
				Bindings: []v1alpha1.PortBindingDefinition{
					{
						Name:       "dns-tcp",
						Protocol:   "TCP",
						ListenPort: 53,
						Target: v1alpha1.BindingTarget{
							Address: "1.1.1.1",
							Port:    53,
						},
					},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "pb-udp"},
			Spec: v1alpha1.PortBindingSpec{
				Bindings: []v1alpha1.PortBindingDefinition{
					{
						Name:       "dns-udp",
						Protocol:   "UDP",
						ListenPort: 53,
						Target: v1alpha1.BindingTarget{
							Address: "8.8.8.8",
							Port:    53,
						},
					},
				},
			},
		},
	}

	plan, err := BuildPlan(node, bindingsPositive, mockResolver{}, "priv", "pub", keys)
	if err != nil {
		t.Fatalf("expected BuildPlan to succeed for TCP/53 and UDP/53, got: %v", err)
	}

	// Verify we got no TLS materials.
	if len(plan.TLSMaterials) != 0 {
		t.Errorf("expected no TLS materials, got %d", len(plan.TLSMaterials))
	}

	// Verify the Envoy LDS and CDS contain both the TCP and UDP configurations.
	// Since RenderEnvoyLDS renders to bytes, we search the YAML representation.
	ldsYAML := string(plan.EnvoyLDS)
	if !strings.Contains(ldsYAML, "listener_dns-tcp") || !strings.Contains(ldsYAML, "listener_dns-udp") {
		t.Errorf("LDS is missing listeners, got:\n%s", ldsYAML)
	}

	cdsYAML := string(plan.EnvoyCDS)
	if !strings.Contains(cdsYAML, "cluster_dns-tcp") || !strings.Contains(cdsYAML, "cluster_dns-udp") {
		t.Errorf("CDS is missing clusters, got:\n%s", cdsYAML)
	}

	// Verify the uplink document has two nftables rules.
	uplinkYAML := string(plan.UplinkDocument)
	if !strings.Contains(uplinkYAML, "1.1.1.1") || !strings.Contains(uplinkYAML, "8.8.8.8") {
		t.Errorf("Uplink document is missing rules, got:\n%s", uplinkYAML)
	}

	// Negative tests:
	// 1. Two TCP/53 bindings are rejected.
	bindingsDupTCP := []v1alpha1.PortBinding{
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "pb-tcp1"},
			Spec: v1alpha1.PortBindingSpec{
				Bindings: []v1alpha1.PortBindingDefinition{
					{
						Name:       "dns-tcp1",
						Protocol:   "TCP",
						ListenPort: 53,
						Target: v1alpha1.BindingTarget{
							Address: "1.1.1.1",
							Port:    53,
						},
					},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "pb-tcp2"},
			Spec: v1alpha1.PortBindingSpec{
				Bindings: []v1alpha1.PortBindingDefinition{
					{
						Name:       "dns-tcp2",
						Protocol:   "TCP",
						ListenPort: 53,
						Target: v1alpha1.BindingTarget{
							Address: "8.8.8.8",
							Port:    53,
						},
					},
				},
			},
		},
	}
	_, err = BuildPlan(node, bindingsDupTCP, mockResolver{}, "priv", "pub", keys)
	if err == nil {
		t.Error("expected BuildPlan to fail for duplicate TCP/53 bindings, but it succeeded")
	} else if !strings.Contains(err.Error(), "port conflict on TCP/53") {
		t.Errorf("expected TCP port conflict error, got: %v", err)
	}

	// 2. Two UDP/53 bindings are rejected.
	bindingsDupUDP := []v1alpha1.PortBinding{
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "pb-udp1"},
			Spec: v1alpha1.PortBindingSpec{
				Bindings: []v1alpha1.PortBindingDefinition{
					{
						Name:       "dns-udp1",
						Protocol:   "UDP",
						ListenPort: 53,
						Target: v1alpha1.BindingTarget{
							Address: "1.1.1.1",
							Port:    53,
						},
					},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "pb-udp2"},
			Spec: v1alpha1.PortBindingSpec{
				Bindings: []v1alpha1.PortBindingDefinition{
					{
						Name:       "dns-udp2",
						Protocol:   "UDP",
						ListenPort: 53,
						Target: v1alpha1.BindingTarget{
							Address: "8.8.8.8",
							Port:    53,
						},
					},
				},
			},
		},
	}
	_, err = BuildPlan(node, bindingsDupUDP, mockResolver{}, "priv", "pub", keys)
	if err == nil {
		t.Error("expected BuildPlan to fail for duplicate UDP/53 bindings, but it succeeded")
	} else if !strings.Contains(err.Error(), "port conflict on UDP/53") {
		t.Errorf("expected UDP port conflict error, got: %v", err)
	}

	// 3. Reserved port 40500 is rejected for any protocol (TCP or UDP).
	for _, proto := range []string{"TCP", "UDP"} {
		bindingsReserved := []v1alpha1.PortBinding{
			{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "pb-reserved"},
				Spec: v1alpha1.PortBindingSpec{
					Bindings: []v1alpha1.PortBindingDefinition{
						{
							Name:       "test-reserved",
							Protocol:   proto,
							ListenPort: 40500,
							Target: v1alpha1.BindingTarget{
								Address: "10.0.0.1",
								Port:    8080,
							},
						},
					},
				},
			},
		}
		_, err = BuildPlan(node, bindingsReserved, mockResolver{}, "priv", "pub", keys)
		if err == nil {
			t.Errorf("expected BuildPlan to fail for reserved port 40500 with protocol %s", proto)
		} else if !strings.Contains(err.Error(), "reserved for the uplink readiness endpoint") {
			t.Errorf("expected reserved port error mentioning uplink readiness endpoint, got: %v", err)
		}
	}
}

// TestBuildPlan_TLSSecretNamespaceResolution verifies that an offload binding
// whose secretRef omits the namespace resolves to the owning PortBinding's
// namespace (not left empty, which the controller would wrongly fall back to
// the EdgeNode's namespace for), and that an explicit namespace is preserved.
func TestBuildPlan_TLSSecretNamespaceResolution(t *testing.T) {
	node := makeNode()
	resolver := mockResolver{}
	keys := map[int32]string{0: "pub0", 1: "pub1"}

	bindings := []v1alpha1.PortBinding{
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "pb-omitted"},
			Spec: v1alpha1.PortBindingSpec{
				Bindings: []v1alpha1.PortBindingDefinition{
					{
						Name:       "web-omitted",
						Protocol:   "TCP",
						ListenPort: 443,
						Target:     v1alpha1.BindingTarget{Address: "10.0.0.1", Port: 8443},
						TLS: &v1alpha1.TLSConfig{
							Mode:      "offload",
							SecretRef: &v1alpha1.SecretReference{Name: "web-cert"},
						},
					},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-b", Name: "pb-explicit"},
			Spec: v1alpha1.PortBindingSpec{
				Bindings: []v1alpha1.PortBindingDefinition{
					{
						Name:       "web-explicit",
						Protocol:   "TCP",
						ListenPort: 8444,
						Target:     v1alpha1.BindingTarget{Address: "10.0.0.2", Port: 8443},
						TLS: &v1alpha1.TLSConfig{
							Mode:      "offload",
							SecretRef: &v1alpha1.SecretReference{Name: "shared-cert", Namespace: "shared-certs"},
						},
					},
				},
			},
		},
	}

	plan, err := BuildPlan(node, bindings, resolver, "priv", "pub", keys)
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]string{}
	for _, m := range plan.TLSMaterials {
		got[m.BindingName] = m.SecretNamespace
	}

	// The omitted namespace must resolve to the PortBinding namespace, never empty.
	if got["web-omitted"] != "tenant-a" {
		t.Fatalf("omitted secretRef namespace must resolve to the PortBinding namespace tenant-a, got %q", got["web-omitted"])
	}
	// An explicit namespace must be preserved verbatim.
	if got["web-explicit"] != "shared-certs" {
		t.Fatalf("explicit secretRef namespace must be preserved, got %q", got["web-explicit"])
	}
}

// TestBuildPlan_DurationNormalization asserts that standard durations (like "1h", "30m", "90s") are normalized
// to Envoy-compliant seconds format (e.g., "3600s", "1800s", "90s") on BuildPlan.
func TestBuildPlan_DurationNormalization(t *testing.T) {
	node := makeNode()
	node.Spec.Uplink.Replicas = 1
	resolver := mockResolver{
		ip: map[string]string{"default/svc1": "10.96.1.1"},
	}
	keys := map[int32]string{0: "pub0"}
	bindings := []v1alpha1.PortBinding{
		{
			Spec: v1alpha1.PortBindingSpec{
				Bindings: []v1alpha1.PortBindingDefinition{
					{
						Name:       "tcp-norm",
						Protocol:   "TCP",
						ListenPort: 80,
						Target:     v1alpha1.BindingTarget{Address: "1.2.3.4", Port: 80},
						TCP: &v1alpha1.TCPParams{
							ConnectTimeout: "30s",
							IdleTimeout:    "1h",
						},
					},
					{
						Name:       "udp-norm",
						Protocol:   "UDP",
						ListenPort: 53,
						Target:     v1alpha1.BindingTarget{Address: "1.2.3.4", Port: 53},
						UDP: &v1alpha1.UDPParams{
							SessionTimeout: "15m",
						},
					},
				},
			},
		},
	}

	plan, err := BuildPlan(node, bindings, resolver, "priv", "pub", keys)
	if err != nil {
		t.Fatal(err)
	}

	// Verify that the LDS/CDS rendered output contains the normalized durations and NOT the original ones.
	ldsStr := string(plan.EnvoyLDS)
	cdsStr := string(plan.EnvoyCDS)

	if strings.Contains(ldsStr, "idle_timeout: 1h") {
		t.Fatal("LDS must not contain raw non-normalized 'idle_timeout: 1h'")
	}
	if !strings.Contains(ldsStr, "idle_timeout: 3600s") {
		t.Fatal("LDS must contain normalized 'idle_timeout: 3600s'")
	}

	if strings.Contains(ldsStr, "idle_timeout: 15m") {
		t.Fatal("LDS must not contain raw non-normalized 'idle_timeout: 15m'")
	}
	if !strings.Contains(ldsStr, "idle_timeout: 900s") {
		t.Fatal("LDS must contain normalized 'idle_timeout: 900s'")
	}

	if strings.Contains(cdsStr, "connect_timeout: 30s") == false {
		t.Fatal("CDS must contain normalized 'connect_timeout: 30s'")
	}
}
