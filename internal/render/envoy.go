package render

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"text/template"
)

const ldsTpl = `resources:
{{- if .Listeners }}
{{- range .Listeners }}
  - "@type": type.googleapis.com/envoy.config.listener.v3.Listener
    name: listener_{{ .Name }}
    address:
      socket_address:
        address: 0.0.0.0
        port_value: {{ .ListenPort }}
        {{- if eq .Protocol "UDP" }}
        protocol: UDP
        {{- end }}
    {{- if eq .Protocol "UDP" }}
    listener_filters:
      - name: envoy.filters.udp_listener.udp_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.udp.udp_proxy.v3.UdpProxyConfig
          stat_prefix: udp_{{ .Name }}
          {{- if ne .UDP.SessionTimeout "" }}
          idle_timeout: {{ .UDP.SessionTimeout }}
          {{- end }}
          matcher:
            on_no_match:
              action:
                name: route
                typed_config:
                  "@type": type.googleapis.com/envoy.extensions.filters.udp.udp_proxy.v3.Route
                  cluster: cluster_{{ .Name }}
    {{- else }}
    {{- if and .TLS (eq .TLS.Mode "passthrough") }}
    listener_filters:
      - name: envoy.filters.listener.tls_inspector
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector
    {{- end }}
    filter_chains:
      {{- if and .TLS (eq .TLS.Mode "passthrough") }}
      - filters:
          - name: envoy.filters.network.tcp_proxy
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
              stat_prefix: tcp_{{ .Name }}
              cluster: cluster_{{ .Name }}
              {{- if ne .TCP.IdleTimeout "" }}
              idle_timeout: {{ .TCP.IdleTimeout }}
              {{- end }}
      {{- else if and .TLS (eq .TLS.Mode "offload") }}
      - filters:
          - name: envoy.filters.network.tcp_proxy
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
              stat_prefix: tcp_{{ .Name }}
              cluster: cluster_{{ .Name }}
              {{- if ne .TCP.IdleTimeout "" }}
              idle_timeout: {{ .TCP.IdleTimeout }}
              {{- end }}
        transport_socket:
          name: envoy.transport_sockets.tls
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
            common_tls_context:
              tls_certificate_sds_secret_configs:
                - name: {{ .TLS.CertSecretName }}
                  sds_config:
                    path_config_source:
                      path: {{ .TLS.SDSPath }}
                      watched_directory:
                        path: {{ .TLS.WatchedDir }}
      {{- else if and .TLS (eq .TLS.Mode "mutual") }}
      - filters:
          - name: envoy.filters.network.tcp_proxy
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
              stat_prefix: tcp_{{ .Name }}
              cluster: cluster_{{ .Name }}
              {{- if ne .TCP.IdleTimeout "" }}
              idle_timeout: {{ .TCP.IdleTimeout }}
              {{- end }}
        transport_socket:
          name: envoy.transport_sockets.tls
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
            require_client_certificate: true
            common_tls_context:
              tls_certificate_sds_secret_configs:
                - name: {{ .TLS.CertSecretName }}
                  sds_config:
                    path_config_source:
                      path: {{ .TLS.SDSPath }}
                      watched_directory:
                        path: {{ .TLS.WatchedDir }}
              validation_context_sds_secret_config:
                name: {{ .TLS.CASecretName }}
                sds_config:
                  path_config_source:
                    path: {{ .TLS.SDSPath }}
                    watched_directory:
                      path: {{ .TLS.WatchedDir }}
      {{- else }}
      - filters:
          - name: envoy.filters.network.tcp_proxy
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
              stat_prefix: tcp_{{ .Name }}
              cluster: cluster_{{ .Name }}
              {{- if ne .TCP.IdleTimeout "" }}
              idle_timeout: {{ .TCP.IdleTimeout }}
              {{- end }}
      {{- end }}
    {{- end }}
{{- end }}
{{- else }} []
{{- end }}
`

const cdsTpl = `resources:
{{- if .Listeners }}
{{- range .Listeners }}
  - "@type": type.googleapis.com/envoy.config.cluster.v3.Cluster
    name: cluster_{{ .Name }}
    {{- if ne .TCP.ConnectTimeout "" }}
    connect_timeout: {{ .TCP.ConnectTimeout }}
    {{- else }}
    connect_timeout: 5s
    {{- end }}
    type: STATIC
    lb_policy: ROUND_ROBIN
    health_checks:
      - timeout: {{ .HealthCheck.Timeout }}
        interval: {{ .HealthCheck.Interval }}
        unhealthy_threshold: {{ .HealthCheck.UnhealthyThreshold }}
        healthy_threshold: {{ .HealthCheck.HealthyThreshold }}
        http_health_check:
          path: /ready
        {{- if and (eq .Protocol "TCP") .TCP.ProxyProtocol }}
        transport_socket:
          name: envoy.transport_sockets.raw_buffer
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.transport_sockets.raw_buffer.v3.RawBuffer
        {{- end }}
    # healthy_panic_threshold 0: hard-coded so Envoy fails fast when most or all uplinks are down.
    common_lb_config:
      healthy_panic_threshold:
        value: 0
    {{- if and (eq .Protocol "TCP") .TCP.ProxyProtocol }}
    transport_socket:
      name: envoy.transport_sockets.upstream_proxy_protocol
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.proxy_protocol.v3.ProxyProtocolUpstreamTransport
        config:
          version: V1
        transport_socket:
          name: envoy.transport_sockets.raw_buffer
    {{- end }}
    load_assignment:
      cluster_name: cluster_{{ .Name }}
      endpoints:
        - lb_endpoints:
{{- $hcPort := .HealthCheck.Port }}
{{- range .Upstreams }}
            - endpoint:
                address:
                  socket_address:
                    address: {{ .IP }}
                    port_value: {{ .Port }}
                health_check_config:
                  port_value: {{ $hcPort }}
{{- end }}
{{- end }}
{{- else }} []
{{- end }}
`

// sortEnvoyConfig sorts cfg.Listeners by ListenPort (then Name) and each
// listener's Upstreams by IP to guarantee deterministic template output.
func sortEnvoyConfig(cfg *EnvoyConfig) {
	sort.Slice(cfg.Listeners, func(i, j int) bool {
		if cfg.Listeners[i].ListenPort == cfg.Listeners[j].ListenPort {
			return cfg.Listeners[i].Name < cfg.Listeners[j].Name
		}
		return cfg.Listeners[i].ListenPort < cfg.Listeners[j].ListenPort
	})

	for idx := range cfg.Listeners {
		sort.Slice(cfg.Listeners[idx].Upstreams, func(i, j int) bool {
			return cfg.Listeners[idx].Upstreams[i].IP < cfg.Listeners[idx].Upstreams[j].IP
		})
	}
}

// RenderEnvoyLDS renders the lds.yaml config for Envoy's Listener Discovery Service.
// Listeners are sorted by ListenPort (then Name) before rendering so the output
// is deterministic regardless of the order in cfg.
func RenderEnvoyLDS(cfg EnvoyConfig) ([]byte, error) {
	sortEnvoyConfig(&cfg)

	t, err := template.New("lds").Parse(ldsTpl)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, cfg); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// RenderEnvoyCDS renders the cds.yaml config for Envoy's Cluster Discovery Service.
// Listeners and their Upstreams are sorted before rendering for determinism.
func RenderEnvoyCDS(cfg EnvoyConfig) ([]byte, error) {
	sortEnvoyConfig(&cfg)

	t, err := template.New("cds").Parse(cdsTpl)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, cfg); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// secretTypeURL is the type URL of an Envoy SDS Secret resource.
const secretTypeURL = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"

// EnvoySDSConfig is the input to RenderEnvoySDS: one binding's TLS material plus
// the SDS secret names the listener references. CertPEM/KeyPEM are required for
// offload and mutual; CAPEM and CASecretName are required only for mutual.
type EnvoySDSConfig struct {
	// Mode is the TLS mode: "offload" or "mutual".
	Mode string
	// CertSecretName is the SDS resource name for the server certificate secret.
	CertSecretName string
	// CertPEM is the PEM-encoded server certificate chain.
	CertPEM []byte
	// KeyPEM is the PEM-encoded server private key.
	KeyPEM []byte
	// CASecretName is the SDS resource name for the CA validation secret (mutual).
	CASecretName string
	// CAPEM is the PEM-encoded CA certificate used to validate client certs (mutual).
	CAPEM []byte
}

// sdsDocument is the on-disk SDS document Envoy reads via a file path_config_source.
type sdsDocument struct {
	Resources []sdsResource `json:"resources"`
}

// sdsResource is one Envoy SDS Secret resource (a cert/key pair or a CA context).
type sdsResource struct {
	Type              string             `json:"@type"`
	Name              string             `json:"name"`
	TLSCertificate    *sdsTLSCertificate `json:"tls_certificate,omitempty"`
	ValidationContext *sdsValidation     `json:"validation_context,omitempty"`
}

// sdsTLSCertificate carries the server cert chain and private key inline.
type sdsTLSCertificate struct {
	CertificateChain sdsInlineString `json:"certificate_chain"`
	PrivateKey       sdsInlineString `json:"private_key"`
}

// sdsValidation carries the trusted CA used to verify client certificates inline.
type sdsValidation struct {
	TrustedCA sdsInlineString `json:"trusted_ca"`
}

// sdsInlineString is an Envoy DataSource carrying its bytes inline as a string.
type sdsInlineString struct {
	InlineString string `json:"inline_string"`
}

// RenderEnvoySDS renders the SDS document for one offload/mutual binding. The
// certificate, key and (for mutual) CA are embedded inline so the whole secret
// is swapped atomically as a single file: a rotation never exposes a half-updated
// cert/key pair, and the atomic move triggers Envoy's graceful SDS reload. The
// output is deterministic JSON (valid YAML), so it participates in the state hash
// like every other artifact. It carries private key material and must be written
// with 0600 permissions.
func RenderEnvoySDS(cfg EnvoySDSConfig) ([]byte, error) {
	if cfg.Mode != "offload" && cfg.Mode != "mutual" {
		return nil, fmt.Errorf("render SDS: unsupported mode %q", cfg.Mode)
	}
	if cfg.CertSecretName == "" {
		return nil, fmt.Errorf("render SDS: cert secret name is empty")
	}
	if len(cfg.CertPEM) == 0 || len(cfg.KeyPEM) == 0 {
		return nil, fmt.Errorf("render SDS: cert and key must not be empty")
	}

	doc := sdsDocument{
		Resources: []sdsResource{
			{
				Type: secretTypeURL,
				Name: cfg.CertSecretName,
				TLSCertificate: &sdsTLSCertificate{
					CertificateChain: sdsInlineString{InlineString: string(cfg.CertPEM)},
					PrivateKey:       sdsInlineString{InlineString: string(cfg.KeyPEM)},
				},
			},
		},
	}

	if cfg.Mode == "mutual" {
		if cfg.CASecretName == "" {
			return nil, fmt.Errorf("render SDS: mutual mode requires a CA secret name")
		}
		if len(cfg.CAPEM) == 0 {
			return nil, fmt.Errorf("render SDS: mutual mode requires CA material")
		}
		doc.Resources = append(doc.Resources, sdsResource{
			Type:              secretTypeURL,
			Name:              cfg.CASecretName,
			ValidationContext: &sdsValidation{TrustedCA: sdsInlineString{InlineString: string(cfg.CAPEM)}},
		})
	}

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("render SDS: marshal: %w", err)
	}
	return append(out, '\n'), nil
}
