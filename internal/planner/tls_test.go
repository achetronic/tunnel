package planner

import (
	"strings"
	"testing"

	"github.com/achetronic/tunnel/api/v1alpha1"
)

// modeOffload is the TLS offload mode value reused across the planner TLS tests.
const modeOffload = "offload"

// tlsBinding builds a single-binding PortBinding for a TCP listener carrying the
// given TLS config, targeting a fixed resolvable Service.
func tlsBinding(name string, listenPort int32, tls *v1alpha1.TLSConfig) v1alpha1.PortBinding {
	return v1alpha1.PortBinding{
		Spec: v1alpha1.PortBindingSpec{
			Bindings: []v1alpha1.PortBindingDefinition{
				{
					Name:       name,
					Protocol:   "TCP",
					ListenPort: listenPort,
					TLS:        tls,
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
	}
}

// tlsResolver and tlsKeys are the shared resolver and uplink keys used by the
// TLS planner tests.
func tlsResolver() mockResolver {
	return mockResolver{ip: map[string]string{"default/svc1": "10.96.1.1"}}
}

func tlsKeys() map[int32]string {
	return map[int32]string{0: "pub0", 1: "pub1"}
}

// TestBuildPlan_TLSPassthrough verifies a passthrough binding builds a plan with
// no TLS material (the private key never leaves the cluster) but still renders.
func TestBuildPlan_TLSPassthrough(t *testing.T) {
	node := makeNode()
	bindings := []v1alpha1.PortBinding{
		tlsBinding("https", 443, &v1alpha1.TLSConfig{Mode: "passthrough"}),
	}

	plan, err := BuildPlan(node, bindings, tlsResolver(), "priv", "pub", tlsKeys())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.TLSMaterials) != 0 {
		t.Fatalf("passthrough must not produce TLS material, got %d entries", len(plan.TLSMaterials))
	}
}

// TestBuildPlan_TLSOffload verifies an offload binding produces exactly one TLS
// material entry with the deterministic VPS cert/key paths and no CA path.
func TestBuildPlan_TLSOffload(t *testing.T) {
	node := makeNode()
	bindings := []v1alpha1.PortBinding{
		tlsBinding("https", 443, &v1alpha1.TLSConfig{
			Mode:      modeOffload,
			SecretRef: &v1alpha1.SecretReference{Name: "web-tls", Namespace: "default"},
		}),
	}

	plan, err := BuildPlan(node, bindings, tlsResolver(), "priv", "pub", tlsKeys())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.TLSMaterials) != 1 {
		t.Fatalf("offload must produce 1 TLS material, got %d", len(plan.TLSMaterials))
	}
	m := plan.TLSMaterials[0]
	if m.BindingName != "https" || m.SecretName != "web-tls" || m.SecretNamespace != "default" || m.Mode != modeOffload {
		t.Fatalf("unexpected TLS material metadata: %+v", m)
	}
	if m.CertPath != "/etc/envoy/tls/https.crt" || m.KeyPath != "/etc/envoy/tls/https.key" {
		t.Fatalf("unexpected cert/key paths: %+v", m)
	}
	if m.CAPath != "" {
		t.Fatalf("offload must not set a CA path, got %q", m.CAPath)
	}
	// Verify default health-check settings appear in the rendered CDS.
	cds := string(plan.EnvoyCDS)
	for _, want := range []string{"timeout: 2s", "interval: 5s", "unhealthy_threshold: 2", "healthy_threshold: 2"} {
		if !strings.Contains(cds, want) {
			t.Errorf("CDS must contain %q for default health check;\nCDS:\n%s", want, cds)
		}
	}
}

// TestBuildPlan_TLSMutual verifies a mutual binding additionally sets the CA path.
func TestBuildPlan_TLSMutual(t *testing.T) {
	node := makeNode()
	bindings := []v1alpha1.PortBinding{
		tlsBinding("grpc", 8443, &v1alpha1.TLSConfig{
			Mode:      "mutual",
			SecretRef: &v1alpha1.SecretReference{Name: "grpc-mtls", Namespace: "default"},
		}),
	}

	plan, err := BuildPlan(node, bindings, tlsResolver(), "priv", "pub", tlsKeys())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.TLSMaterials) != 1 {
		t.Fatalf("mutual must produce 1 TLS material, got %d", len(plan.TLSMaterials))
	}
	if got := plan.TLSMaterials[0].CAPath; got != "/etc/envoy/tls/grpc.ca.crt" {
		t.Fatalf("mutual must set CA path, got %q", got)
	}
}

// TestBuildPlan_TLSMaterialsSortedAndFiltered verifies that only offload/mutual
// bindings yield material and that the list is ordered by binding name.
func TestBuildPlan_TLSMaterialsSortedAndFiltered(t *testing.T) {
	node := makeNode()
	bindings := []v1alpha1.PortBinding{
		tlsBinding("zeta", 8443, &v1alpha1.TLSConfig{
			Mode:      "mutual",
			SecretRef: &v1alpha1.SecretReference{Name: "zeta-tls", Namespace: "default"},
		}),
		tlsBinding("alpha", 9443, &v1alpha1.TLSConfig{
			Mode:      modeOffload,
			SecretRef: &v1alpha1.SecretReference{Name: "alpha-tls", Namespace: "default"},
		}),
		tlsBinding("plain", 10443, &v1alpha1.TLSConfig{Mode: "passthrough"}),
	}

	plan, err := BuildPlan(node, bindings, tlsResolver(), "priv", "pub", tlsKeys())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.TLSMaterials) != 2 {
		t.Fatalf("expected 2 materials (offload+mutual, not passthrough), got %d", len(plan.TLSMaterials))
	}
	if plan.TLSMaterials[0].BindingName != "alpha" || plan.TLSMaterials[1].BindingName != "zeta" {
		t.Fatalf("TLS materials must be sorted by binding name, got %q then %q",
			plan.TLSMaterials[0].BindingName, plan.TLSMaterials[1].BindingName)
	}
}

// TestBuildPlan_TLSOffloadMissingSecretRef verifies BuildPlan rejects an
// offload/mutual binding without a secretRef (the safety net behind the CEL rule).
func TestBuildPlan_TLSOffloadMissingSecretRef(t *testing.T) {
	node := makeNode()
	bindings := []v1alpha1.PortBinding{
		tlsBinding("https", 443, &v1alpha1.TLSConfig{Mode: modeOffload}),
	}

	_, err := BuildPlan(node, bindings, tlsResolver(), "priv", "pub", tlsKeys())
	if err == nil {
		t.Fatal("expected error for offload binding without secretRef")
	}
}
