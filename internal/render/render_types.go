// SPDX-FileCopyrightText: 2026 Alby Hernández (Achetronic)
// SPDX-License-Identifier: Apache-2.0

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
//
// For offload/mutual the certificate material is delivered to Envoy through
// file-based SDS (Secret Discovery Service): the listener references a secret by
// name, sourced from an on-disk SDS document watched via WatchedDirectory. This
// lets Envoy hot-reload a rotated certificate gracefully (no listener rebuild,
// no dropped connections) when the operator atomically swaps the SDS file,
// instead of needing a restart.
type EnvoyTLSConfig struct {
	// Mode selects the TLS strategy. Accepted values:
	//   "passthrough" - Envoy inspects the SNI and forwards the raw TLS
	//                   stream to the upstream without terminating it.
	//   "offload"     - Envoy terminates TLS using the SDS server certificate
	//                   secret and forwards plain TCP to the upstream.
	//   "mutual"      - Same as offload but also requires a client certificate
	//                   validated against the SDS CA secret (mTLS).
	Mode string

	// SDSPath is the path on the VPS to the SDS document holding this binding's
	// secrets (server cert/key inline, plus the CA for mutual). Used in offload
	// and mutual modes, e.g. /etc/envoy/tls/mylistener.sds.yaml.
	SDSPath string

	// WatchedDir is the directory Envoy watches for atomic moves to trigger a
	// graceful reload of SDSPath (the directory holding the SDS files). Used in
	// offload and mutual modes, e.g. /etc/envoy/tls.
	WatchedDir string

	// CertSecretName is the SDS secret name for the server certificate/key,
	// matched against a resource inside SDSPath. Used in offload and mutual modes.
	CertSecretName string

	// CASecretName is the SDS secret name for the client-CA validation context,
	// matched against a resource inside SDSPath. Used only in mutual mode.
	CASecretName string
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
