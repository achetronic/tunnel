// Package render provides deterministic template rendering for Envoy xDS
// resources (LDS/CDS) installed on the VPS relay. All exported Render*
// functions are pure: same inputs always produce the same bytes (templates are
// sorted before execution).
package render

// EnvoyUpstreamServer represents one backend server (a tunnel replica IP).
type EnvoyUpstreamServer struct {
	// IP is the tunnel IP of the replica.
	IP string
	// Port is the port the upstream listens on.
	Port int32
}

// EnvoyTCPParams holds TCP-specific configuration for an Envoy listener.
type EnvoyTCPParams struct {
	// ProxyProtocol enables PROXY protocol v1 towards the upstream.
	ProxyProtocol bool
	// ConnectTimeout is the upstream connect timeout in Envoy duration format, e.g. "5s".
	ConnectTimeout string
	// IdleTimeout is the connection idle timeout in Envoy duration format, e.g. "3600s".
	IdleTimeout string
}

// EnvoyUDPParams holds UDP-specific configuration for an Envoy listener.
type EnvoyUDPParams struct {
	// SessionTimeout is the UDP session idle timeout in Envoy duration format, e.g. "60s".
	SessionTimeout string
}

// EnvoyTLSConfig describes the TLS behaviour for a TCP listener.
// A nil pointer means no TLS (plain TCP, current default behaviour).
type EnvoyTLSConfig struct {
	// Mode selects the TLS strategy. Accepted values:
	//   "passthrough" - Envoy inspects the SNI and forwards the raw TLS
	//                   stream to the upstream without terminating it.
	//   "offload"     - Envoy terminates TLS using CertPath/KeyPath and
	//                   forwards plain TCP to the upstream.
	//   "mutual"      - Same as offload but also requires a client
	//                   certificate validated against CAPath (mTLS).
	Mode string

	// CertPath is the path on the VPS to the server TLS certificate file
	// (e.g. /etc/envoy/tls/mylistener.crt). Used in offload and mutual modes.
	CertPath string

	// KeyPath is the path on the VPS to the server TLS private key file
	// (e.g. /etc/envoy/tls/mylistener.key). Used in offload and mutual modes.
	KeyPath string

	// CAPath is the path on the VPS to the CA certificate used to validate
	// client certificates (e.g. /etc/envoy/tls/ca.crt). Used only in mutual mode.
	CAPath string
}

// EnvoyHealthCheck holds the active health-check policy the VPS Envoy applies to
// an upstream cluster. Envoy probes each replica's readiness endpoint on Port and
// only routes traffic to replicas that pass.
type EnvoyHealthCheck struct {
	// Interval between probes in Envoy duration format, e.g. "5s".
	Interval string
	// Timeout for each probe in Envoy duration format, e.g. "2s".
	Timeout string
	// HealthyThreshold is the consecutive successful probes before a replica is healthy.
	HealthyThreshold int32
	// UnhealthyThreshold is the consecutive failed probes before a replica is ejected.
	UnhealthyThreshold int32
	// Port is the replica port Envoy sends the health probe to (the uplink
	// readiness port), independent of the traffic port.
	Port int32
}

// EnvoyListener represents one exposed port on the VPS Envoy instance.
type EnvoyListener struct {
	// Name is the unique binding name, used as suffix for listener/cluster identifiers.
	Name string
	// Protocol is either "TCP" or "UDP".
	Protocol string
	// ListenPort is the port Envoy listens on.
	ListenPort int32
	// Upstreams is the list of backend tunnel replica addresses.
	Upstreams []EnvoyUpstreamServer

	// TCP holds TCP-specific parameters; used only when Protocol == "TCP".
	TCP EnvoyTCPParams
	// UDP holds UDP-specific parameters; used only when Protocol == "UDP".
	UDP EnvoyUDPParams

	// TLS holds TLS configuration for this listener.
	// A nil value means plain TCP/UDP with no TLS handling (default).
	// TLS is only meaningful when Protocol is "TCP".
	TLS *EnvoyTLSConfig

	// HealthCheck is the active health-check policy applied to this listener's
	// upstream cluster. Envoy probes each replica's readiness endpoint and only
	// routes to replicas that pass.
	HealthCheck EnvoyHealthCheck
}

// EnvoyConfig holds all listeners for a VPS Envoy instance.
type EnvoyConfig struct {
	// Listeners is the complete list of port bindings to render.
	Listeners []EnvoyListener
}
