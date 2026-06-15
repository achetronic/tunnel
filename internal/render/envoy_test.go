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

	// Assert cluster type is STATIC not STRICT_DNS (FIX 3)
	if bytes.Contains(cdsOut, []byte("type: STRICT_DNS")) {
		t.Fatal("expected cluster type to not be STRICT_DNS (FIX 3)")
	}
	if !bytes.Contains(cdsOut, []byte("type: STATIC")) {
		t.Fatal("expected cluster type to be STATIC (FIX 3)")
	}

	// Assert that for a proxyProtocol cluster, the health check overrides the transport socket (FIX 2)
	// Whereas a non-proxy cluster has no such override under health checks.
	// cluster_tcp_bind is proxyProtocol, cluster_udp_bind is not proxyProtocol.
	if !bytes.Contains(cdsOut, []byte("name: cluster_tcp_bind")) {
		t.Fatal("missing cluster_tcp_bind in cdsOut")
	}
	if !bytes.Contains(cdsOut, []byte("name: cluster_udp_bind")) {
		t.Fatal("missing cluster_udp_bind in cdsOut")
	}

	tcpIndex := bytes.Index(cdsOut, []byte("name: cluster_tcp_bind"))
	udpIndex := bytes.Index(cdsOut, []byte("name: cluster_udp_bind"))
	if tcpIndex == -1 || udpIndex == -1 {
		t.Fatal("could not find both clusters in cdsOut")
	}

	tcpClusterBlock := cdsOut[tcpIndex:udpIndex]
	udpClusterBlock := cdsOut[udpIndex:]

	// Inside the proxyProtocol TCP cluster block, health check must specify raw_buffer transport_socket
	if !bytes.Contains(tcpClusterBlock, []byte("envoy.transport_sockets.raw_buffer")) {
		t.Fatal("expected raw_buffer transport socket under health check for proxy cluster (FIX 2)")
	}

	// Inside the non-proxy UDP cluster block, health check must NOT specify raw_buffer transport_socket
	if bytes.Contains(udpClusterBlock, []byte("envoy.transport_sockets.raw_buffer")) {
		t.Fatal("expected no raw_buffer transport socket under health check for non-proxy cluster (FIX 2)")
	}

	// Health checks must not reuse the upstream connection: the uplink readiness
	// server closes idle keep-alive connections between probes, so reusing one
	// records a spurious network failure that ejects a healthy uplink.
	if bytes.Count(cdsOut, []byte("reuse_connection: false")) != 2 {
		t.Fatalf("expected reuse_connection: false under the health check of both clusters, got:\n%s", cdsOut)
	}

	cdsWant := goldenRead(t, "envoy_cds.golden", cdsOut)
	if !bytes.Equal(cdsOut, cdsWant) {
		t.Fatalf("CDS output mismatch:\ngot:\n%s\nwant:\n%s", cdsOut, cdsWant)
	}
}

// TestRenderEnvoySDS verifies the SDS document embeds the cert/key inline for
// offload, adds a CA validation resource for mutual, is deterministic, and
// rejects incomplete input.
func TestRenderEnvoySDS(t *testing.T) {
	offload, err := RenderEnvoySDS(EnvoySDSConfig{
		Mode:           "offload",
		CertSecretName: "web",
		CertPEM:        []byte("CERTPEM"),
		KeyPEM:         []byte("KEYPEM"),
	})
	if err != nil {
		t.Fatal(err)
	}
	offload2, err := RenderEnvoySDS(EnvoySDSConfig{
		Mode:           "offload",
		CertSecretName: "web",
		CertPEM:        []byte("CERTPEM"),
		KeyPEM:         []byte("KEYPEM"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(offload, offload2) {
		t.Fatal("RenderEnvoySDS is not deterministic")
	}
	for _, want := range []string{secretTypeURL, `"name": "web"`, "tls_certificate", "inline_string", "CERTPEM", "KEYPEM"} {
		if !bytes.Contains(offload, []byte(want)) {
			t.Fatalf("offload SDS missing %q;\n%s", want, offload)
		}
	}
	if bytes.Contains(offload, []byte("validation_context")) {
		t.Fatal("offload SDS must not contain a validation_context")
	}

	mutual, err := RenderEnvoySDS(EnvoySDSConfig{
		Mode:           "mutual",
		CertSecretName: "grpc",
		CertPEM:        []byte("CERTPEM"),
		KeyPEM:         []byte("KEYPEM"),
		CASecretName:   "grpc-ca",
		CAPEM:          []byte("CAPEM"),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"name": "grpc"`, `"name": "grpc-ca"`, "validation_context", "trusted_ca", "CAPEM"} {
		if !bytes.Contains(mutual, []byte(want)) {
			t.Fatalf("mutual SDS missing %q;\n%s", want, mutual)
		}
	}

	// Incomplete input is rejected.
	if _, err := RenderEnvoySDS(EnvoySDSConfig{Mode: "offload", CertSecretName: "web", CertPEM: []byte("x")}); err == nil {
		t.Fatal("expected error when the private key is empty")
	}
	if _, err := RenderEnvoySDS(EnvoySDSConfig{Mode: "mutual", CertSecretName: "g", CertPEM: []byte("c"), KeyPEM: []byte("k")}); err == nil {
		t.Fatal("expected error when mutual mode lacks CA material")
	}
	if _, err := RenderEnvoySDS(EnvoySDSConfig{Mode: "passthrough", CertSecretName: "x", CertPEM: []byte("c"), KeyPEM: []byte("k")}); err == nil {
		t.Fatal("expected error for unsupported mode")
	}
}

// TestRenderEnvoyLDS_TLSPassthrough verifies that a TCP listener with
// TLS mode "passthrough" emits a tls_inspector listener_filter and a catch-all
// filter chain (no filter_chain_match, no server_names) without a downstream
// transport_socket, so it forwards every connection regardless of SNI.
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
	// The passthrough filter chain must be catch-all: a bare server_names: ["*"]
	// is not a match-all in Envoy L4 (only exact names and *.suffix wildcards
	// match), so any real SNI or no-SNI connection would hit no filter chain and
	// be reset. The chain therefore carries no filter_chain_match at all.
	if bytes.Contains(out, []byte("filter_chain_match")) {
		t.Fatal("passthrough filter chain must be catch-all (no filter_chain_match)")
	}
	if bytes.Contains(out, []byte("server_names")) {
		t.Fatal("passthrough must not pin server_names; a bare \"*\" matches nothing")
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
					Mode:           "offload",
					SDSPath:        "/etc/envoy/tls/https_offload.sds.yaml",
					WatchedDir:     "/etc/envoy/tls",
					CertSecretName: "https_offload",
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
	if !bytes.Contains(out, []byte("tls_certificate_sds_secret_configs")) {
		t.Fatal("missing SDS secret config in offload output")
	}
	if !bytes.Contains(out, []byte("name: https_offload")) {
		t.Fatal("missing SDS cert secret name in offload output")
	}
	if !bytes.Contains(out, []byte("/etc/envoy/tls/https_offload.sds.yaml")) {
		t.Fatal("missing SDS path in offload output")
	}
	if !bytes.Contains(out, []byte("watched_directory")) {
		t.Fatal("missing watched_directory in offload output")
	}
	if bytes.Contains(out, []byte("filename:")) {
		t.Fatal("offload must not reference cert material by filename (use SDS)")
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
// and an SDS validation_context_sds_secret_config for the client CA.
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
					Mode:           "mutual",
					SDSPath:        "/etc/envoy/tls/grpc_mtls.sds.yaml",
					WatchedDir:     "/etc/envoy/tls",
					CertSecretName: "grpc_mtls",
					CASecretName:   "grpc_mtls-ca",
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
	if !bytes.Contains(out, []byte("validation_context_sds_secret_config")) {
		t.Fatal("missing validation_context SDS config in mutual output")
	}
	if !bytes.Contains(out, []byte("name: grpc_mtls-ca")) {
		t.Fatal("missing SDS CA secret name in mutual output")
	}
	if !bytes.Contains(out, []byte("name: grpc_mtls\n")) {
		t.Fatal("missing SDS cert secret name in mutual output")
	}
	if !bytes.Contains(out, []byte("/etc/envoy/tls/grpc_mtls.sds.yaml")) {
		t.Fatal("missing SDS path in mutual output")
	}
	if bytes.Contains(out, []byte("filename:")) {
		t.Fatal("mutual must not reference cert material by filename (use SDS)")
	}
	if bytes.Contains(out, []byte("tls_inspector")) {
		t.Fatal("mutual must NOT contain tls_inspector")
	}

	want := goldenRead(t, "envoy_lds_tls_mutual.golden", out)
	if !bytes.Equal(out, want) {
		t.Fatalf("LDS mutual output mismatch:\ngot:\n%s\nwant:\n%s", out, want)
	}
}
