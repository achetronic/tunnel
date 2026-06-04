package render

import (
	"bytes"
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
      - filter_chain_match:
          server_names:
            - "*"
        filters:
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
              tls_certificates:
                - certificate_chain:
                    filename: {{ .TLS.CertPath }}
                  private_key:
                    filename: {{ .TLS.KeyPath }}
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
              tls_certificates:
                - certificate_chain:
                    filename: {{ .TLS.CertPath }}
                  private_key:
                    filename: {{ .TLS.KeyPath }}
              validation_context:
                trusted_ca:
                  filename: {{ .TLS.CAPath }}
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
    type: STRICT_DNS
    lb_policy: ROUND_ROBIN
    health_checks:
      - timeout: {{ .HealthCheck.Timeout }}
        interval: {{ .HealthCheck.Interval }}
        unhealthy_threshold: {{ .HealthCheck.UnhealthyThreshold }}
        healthy_threshold: {{ .HealthCheck.HealthyThreshold }}
        http_health_check:
          path: /ready
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
