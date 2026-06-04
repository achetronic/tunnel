package render

import (
	"bytes"
	"testing"
)

func TestRenderEnvoyLDSAndCDS(t *testing.T) {
	cfg := EnvoyConfig{
		Listeners: []EnvoyListener{
			{
				Name:       "tcp_bind",
				Protocol:   "TCP",
				ListenPort: 443,
				Upstreams: []EnvoyUpstreamServer{
					{"10.200.0.3", 443},
					{"10.200.0.2", 443},
				},
				TCP: EnvoyTCPParams{
					ProxyProtocol:  true,
					ConnectTimeout: "5s",
					IdleTimeout:    "3600s",
				},
				HealthCheck: EnvoyHealthCheck{
					Interval:           "5s",
					Timeout:            "2s",
					HealthyThreshold:   2,
					UnhealthyThreshold: 2,
					Port:               8080,
				},
			},
			{
				Name:       "udp_bind",
				Protocol:   "UDP",
				ListenPort: 51820,
				Upstreams: []EnvoyUpstreamServer{
					{"10.200.0.2", 51820},
				},
				UDP: EnvoyUDPParams{
					SessionTimeout: "120s",
				},
				HealthCheck: EnvoyHealthCheck{
					Interval:           "5s",
					Timeout:            "2s",
					HealthyThreshold:   2,
					UnhealthyThreshold: 2,
					Port:               8080,
				},
			},
		},
	}

	ldsOut, err := RenderEnvoyLDS(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ldsOut2, err := RenderEnvoyLDS(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(ldsOut, ldsOut2) {
		t.Fatal("RenderEnvoyLDS is not deterministic")
	}

	if !bytes.Contains(ldsOut, []byte("listener_tcp_bind")) {
		t.Fatal("missing listener_tcp_bind in ldsOut")
	}

	ldsWant := goldenRead(t, "envoy_lds.golden", ldsOut)
	if !bytes.Equal(ldsOut, ldsWant) {
		t.Fatalf("LDS output mismatch:\ngot:\n%s\nwant:\n%s", ldsOut, ldsWant)
	}

	cdsOut, err := RenderEnvoyCDS(cfg)
	if err != nil {
		t.Fatal(err)
	}

	cdsOut2, err := RenderEnvoyCDS(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(cdsOut, cdsOut2) {
		t.Fatal("RenderEnvoyCDS is not deterministic")
	}

	if !bytes.Contains(cdsOut, []byte("ProxyProtocolUpstreamTransport")) {
		t.Fatal("missing proxy protocol upstream config in cdsOut")
	}

	cdsWant := goldenRead(t, "envoy_cds.golden", cdsOut)
	if !bytes.Equal(cdsOut, cdsWant) {
		t.Fatalf("CDS output mismatch:\ngot:\n%s\nwant:\n%s", cdsOut, cdsWant)
	}
}

// TestRenderEnvoyLDS_TLSPassthrough verifies that a TCP listener with
// TLS mode "passthrough" emits a tls_inspector listener_filter and a
// filter_chain_match on server_names without a downstream transport_socket.
func TestRenderEnvoyLDS_TLSPassthrough(t *testing.T) {
	cfg := EnvoyConfig{
		Listeners: []EnvoyListener{
			{
				Name:       "https_pt",
				Protocol:   "TCP",
				ListenPort: 443,
				Upstreams: []EnvoyUpstreamServer{
					{IP: "10.200.0.2", Port: 443},
				},
				TCP: EnvoyTCPParams{
					ConnectTimeout: "5s",
				},
				TLS: &EnvoyTLSConfig{
					Mode: "passthrough",
				},
			},
		},
	}

	out, err := RenderEnvoyLDS(cfg)
	if err != nil {
		t.Fatal(err)
	}

	out2, err := RenderEnvoyLDS(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, out2) {
		t.Fatal("RenderEnvoyLDS passthrough is not deterministic")
	}

	if !bytes.Contains(out, []byte("tls_inspector")) {
		t.Fatal("missing tls_inspector listener_filter in passthrough output")
	}
	if !bytes.Contains(out, []byte("filter_chain_match")) {
		t.Fatal("missing filter_chain_match in passthrough output")
	}
	if bytes.Contains(out, []byte("DownstreamTlsContext")) {
		t.Fatal("passthrough must NOT contain DownstreamTlsContext")
	}

	want := goldenRead(t, "envoy_lds_tls_passthrough.golden", out)
	if !bytes.Equal(out, want) {
		t.Fatalf("LDS passthrough output mismatch:\ngot:\n%s\nwant:\n%s", out, want)
	}
}

// TestRenderEnvoyLDS_TLSOffload verifies that a TCP listener with
// TLS mode "offload" emits a DownstreamTlsContext transport_socket with
// the server certificate and key, but no require_client_certificate.
func TestRenderEnvoyLDS_TLSOffload(t *testing.T) {
	cfg := EnvoyConfig{
		Listeners: []EnvoyListener{
			{
				Name:       "https_offload",
				Protocol:   "TCP",
				ListenPort: 8443,
				Upstreams: []EnvoyUpstreamServer{
					{IP: "10.200.0.2", Port: 8080},
				},
				TCP: EnvoyTCPParams{
					ConnectTimeout: "5s",
					IdleTimeout:    "300s",
				},
				TLS: &EnvoyTLSConfig{
					Mode:     "offload",
					CertPath: "/etc/envoy/tls/https_offload.crt",
					KeyPath:  "/etc/envoy/tls/https_offload.key",
				},
			},
		},
	}

	out, err := RenderEnvoyLDS(cfg)
	if err != nil {
		t.Fatal(err)
	}

	out2, err := RenderEnvoyLDS(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, out2) {
		t.Fatal("RenderEnvoyLDS offload is not deterministic")
	}

	if !bytes.Contains(out, []byte("DownstreamTlsContext")) {
		t.Fatal("missing DownstreamTlsContext in offload output")
	}
	if !bytes.Contains(out, []byte("https_offload.crt")) {
		t.Fatal("missing certificate_chain path in offload output")
	}
	if !bytes.Contains(out, []byte("https_offload.key")) {
		t.Fatal("missing private_key path in offload output")
	}
	if bytes.Contains(out, []byte("require_client_certificate")) {
		t.Fatal("offload must NOT contain require_client_certificate")
	}
	if bytes.Contains(out, []byte("tls_inspector")) {
		t.Fatal("offload must NOT contain tls_inspector")
	}

	want := goldenRead(t, "envoy_lds_tls_offload.golden", out)
	if !bytes.Equal(out, want) {
		t.Fatalf("LDS offload output mismatch:\ngot:\n%s\nwant:\n%s", out, want)
	}
}

// TestRenderEnvoyLDS_TLSMutual verifies that a TCP listener with TLS mode
// "mutual" emits a DownstreamTlsContext with require_client_certificate: true
// and a validation_context referencing CAPath.
func TestRenderEnvoyLDS_TLSMutual(t *testing.T) {
	cfg := EnvoyConfig{
		Listeners: []EnvoyListener{
			{
				Name:       "grpc_mtls",
				Protocol:   "TCP",
				ListenPort: 9443,
				Upstreams: []EnvoyUpstreamServer{
					{IP: "10.200.0.3", Port: 9090},
					{IP: "10.200.0.2", Port: 9090},
				},
				TCP: EnvoyTCPParams{
					ConnectTimeout: "10s",
				},
				TLS: &EnvoyTLSConfig{
					Mode:     "mutual",
					CertPath: "/etc/envoy/tls/grpc_mtls.crt",
					KeyPath:  "/etc/envoy/tls/grpc_mtls.key",
					CAPath:   "/etc/envoy/tls/ca.crt",
				},
			},
		},
	}

	out, err := RenderEnvoyLDS(cfg)
	if err != nil {
		t.Fatal(err)
	}

	out2, err := RenderEnvoyLDS(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, out2) {
		t.Fatal("RenderEnvoyLDS mutual is not deterministic")
	}

	if !bytes.Contains(out, []byte("DownstreamTlsContext")) {
		t.Fatal("missing DownstreamTlsContext in mutual output")
	}
	if !bytes.Contains(out, []byte("require_client_certificate: true")) {
		t.Fatal("missing require_client_certificate in mutual output")
	}
	if !bytes.Contains(out, []byte("ca.crt")) {
		t.Fatal("missing trusted_ca path in mutual output")
	}
	if !bytes.Contains(out, []byte("grpc_mtls.crt")) {
		t.Fatal("missing certificate_chain path in mutual output")
	}
	if !bytes.Contains(out, []byte("grpc_mtls.key")) {
		t.Fatal("missing private_key path in mutual output")
	}
	if bytes.Contains(out, []byte("tls_inspector")) {
		t.Fatal("mutual must NOT contain tls_inspector")
	}

	want := goldenRead(t, "envoy_lds_tls_mutual.golden", out)
	if !bytes.Equal(out, want) {
		t.Fatalf("LDS mutual output mismatch:\ngot:\n%s\nwant:\n%s", out, want)
	}
}
