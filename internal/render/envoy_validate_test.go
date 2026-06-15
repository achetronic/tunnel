// SPDX-FileCopyrightText: 2026 Alby Hernández (Achetronic)
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// ResourceList represents a list of dynamic resources parsed from templates.
type ResourceList struct {
	Resources []any `yaml:"resources"`
}

// BootstrapStatic holds the static resources to be validated by the Envoy binary.
type BootstrapStatic struct {
	Node            any             `yaml:"node"`
	StaticResources StaticResources `yaml:"static_resources"`
}

// StaticResources contains listeners and clusters for static bootstrap.
type StaticResources struct {
	Listeners []any `yaml:"listeners,omitempty"`
	Clusters  []any `yaml:"clusters,omitempty"`
}

// generateSelfSignedCert creates a temporary self-signed TLS certificate.
// This certificate is used to populate valid secret configurations for SDS.
func generateSelfSignedCert() ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Tunnel Test CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certBuf := new(bytes.Buffer)
	if err := pem.Encode(certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, nil, err
	}

	keyBuf := new(bytes.Buffer)
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	if err := pem.Encode(keyBuf, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return nil, nil, err
	}

	return certBuf.Bytes(), keyBuf.Bytes(), nil
}

// findEnvoyBinary checks several paths to locate the executable envoy binary.
// It searches in environment variables, the workspace bin/ directory, and the PATH.
func findEnvoyBinary() string {
	if eb := os.Getenv("ENVOY_BIN"); eb != "" {
		if isExecutable(eb) {
			return eb
		}
	}

	_, filename, _, ok := runtime.Caller(0)
	if ok {
		repoRoot := filepath.Dir(filepath.Dir(filepath.Dir(filename)))
		candidate := filepath.Join(repoRoot, "bin", "envoy")
		if isExecutable(candidate) {
			return candidate
		}
	}

	for _, candidate := range []string{"../../bin/envoy", "./bin/envoy", "bin/envoy"} {
		if isExecutable(candidate) {
			abs, err := filepath.Abs(candidate)
			if err == nil {
				return abs
			}
			return candidate
		}
	}

	if p, err := exec.LookPath("envoy"); err == nil {
		return p
	}

	return ""
}

// isExecutable returns true if the specified path points to a valid file with executable permissions.
func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if info.IsDir() {
		return false
	}
	return info.Mode()&0111 != 0
}

// buildStaticBootstrap combines rendered LDS and CDS dynamic resources into a single static bootstrap structure.
// This structure is then validated as static resources by the Envoy binary.
func buildStaticBootstrap(ldsYAML, cdsYAML []byte) ([]byte, error) {
	var ldsRes ResourceList
	if err := yaml.Unmarshal(ldsYAML, &ldsRes); err != nil {
		return nil, err
	}

	var cdsRes ResourceList
	if err := yaml.Unmarshal(cdsYAML, &cdsRes); err != nil {
		return nil, err
	}

	strippedListeners := make([]any, len(ldsRes.Resources))
	for i, r := range ldsRes.Resources {
		if m, ok := r.(map[string]any); ok {
			delete(m, "@type")
		}
		strippedListeners[i] = r
	}

	strippedClusters := make([]any, len(cdsRes.Resources))
	for i, r := range cdsRes.Resources {
		if m, ok := r.(map[string]any); ok {
			delete(m, "@type")
		}
		strippedClusters[i] = r
	}

	node := map[string]string{
		"id":      "tunnel-relay",
		"cluster": "tunnel-relay",
	}

	bootstrap := BootstrapStatic{
		Node: node,
		StaticResources: StaticResources{
			Listeners: strippedListeners,
			Clusters:  strippedClusters,
		},
	}

	out, err := yaml.Marshal(bootstrap)
	if err != nil {
		return nil, err
	}

	return out, nil
}

// TestEnvoyValidate runs validation checks against real Envoy binary configurations.
// This test asserts that the rendered Envoy LDS/CDS configuration is valid.
func TestEnvoyValidate(t *testing.T) {
	envoyBin := findEnvoyBinary()
	if envoyBin == "" {
		t.Skip("SKIPPED, NOT TESTED: envoy binary not found; run `make envoy`")
	}

	tmpDir, err := os.MkdirTemp("", "envoy-validate-test-*")
	if err != nil {
		t.Fatalf("failed to create temporary directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	offloadSDSPath := filepath.Join(tmpDir, "tls_offload.sds.yaml")
	mutualSDSPath := filepath.Join(tmpDir, "tls_mutual.sds.yaml")

	certPEM, keyPEM, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("failed to generate self signed certificate: %v", err)
	}

	offloadSDSBytes, err := RenderEnvoySDS(EnvoySDSConfig{
		Mode:           "offload",
		CertSecretName: "cert_tls_offload",
		CertPEM:        certPEM,
		KeyPEM:         keyPEM,
	})
	if err != nil {
		t.Fatalf("failed to render offload SDS: %v", err)
	}
	if err := os.WriteFile(offloadSDSPath, offloadSDSBytes, 0600); err != nil {
		t.Fatalf("failed to write offload SDS file: %v", err)
	}

	mutualSDSBytes, err := RenderEnvoySDS(EnvoySDSConfig{
		Mode:           "mutual",
		CertSecretName: "cert_tls_mutual",
		CertPEM:        certPEM,
		KeyPEM:         keyPEM,
		CASecretName:   "ca_tls_mutual",
		CAPEM:          certPEM,
	})
	if err != nil {
		t.Fatalf("failed to render mutual SDS: %v", err)
	}
	if err := os.WriteFile(mutualSDSPath, mutualSDSBytes, 0600); err != nil {
		t.Fatalf("failed to write mutual SDS file: %v", err)
	}

	cfg := EnvoyConfig{
		Listeners: []EnvoyListener{
			{
				Name:       "tcp_plain",
				Protocol:   "TCP",
				ListenPort: 10001,
				Upstreams: []EnvoyUpstreamServer{
					{"127.0.0.1", 20001},
				},
				TCP: EnvoyTCPParams{
					ConnectTimeout: "5s",
					IdleTimeout:    "3600s",
				},
				HealthCheck: EnvoyHealthCheck{
					Interval:           "5s",
					Timeout:            "2s",
					HealthyThreshold:   2,
					UnhealthyThreshold: 2,
					Port:               8081,
				},
			},
			{
				Name:       "udp_plain",
				Protocol:   "UDP",
				ListenPort: 10002,
				Upstreams: []EnvoyUpstreamServer{
					{"127.0.0.1", 20002},
				},
				UDP: EnvoyUDPParams{
					SessionTimeout: "60s",
				},
				HealthCheck: EnvoyHealthCheck{
					Interval:           "5s",
					Timeout:            "2s",
					HealthyThreshold:   2,
					UnhealthyThreshold: 2,
					Port:               8082,
				},
			},
			{
				Name:       "tls_passthrough",
				Protocol:   "TCP",
				ListenPort: 10003,
				Upstreams: []EnvoyUpstreamServer{
					{"127.0.0.1", 20003},
				},
				TCP: EnvoyTCPParams{
					ConnectTimeout: "5s",
					IdleTimeout:    "3600s",
				},
				TLS: &EnvoyTLSConfig{
					Mode: "passthrough",
				},
				HealthCheck: EnvoyHealthCheck{
					Interval:           "5s",
					Timeout:            "2s",
					HealthyThreshold:   2,
					UnhealthyThreshold: 2,
					Port:               8083,
				},
			},
			{
				Name:       "tls_offload",
				Protocol:   "TCP",
				ListenPort: 10004,
				Upstreams: []EnvoyUpstreamServer{
					{"127.0.0.1", 20004},
				},
				TCP: EnvoyTCPParams{
					ConnectTimeout: "5s",
					IdleTimeout:    "3600s",
				},
				TLS: &EnvoyTLSConfig{
					Mode:           "offload",
					SDSPath:        offloadSDSPath,
					WatchedDir:     tmpDir,
					CertSecretName: "cert_tls_offload",
				},
				HealthCheck: EnvoyHealthCheck{
					Interval:           "5s",
					Timeout:            "2s",
					HealthyThreshold:   2,
					UnhealthyThreshold: 2,
					Port:               8084,
				},
			},
			{
				Name:       "tls_mutual",
				Protocol:   "TCP",
				ListenPort: 10005,
				Upstreams: []EnvoyUpstreamServer{
					{"127.0.0.1", 20005},
				},
				TCP: EnvoyTCPParams{
					ConnectTimeout: "5s",
					IdleTimeout:    "3600s",
				},
				TLS: &EnvoyTLSConfig{
					Mode:           "mutual",
					SDSPath:        mutualSDSPath,
					WatchedDir:     tmpDir,
					CertSecretName: "cert_tls_mutual",
					CASecretName:   "ca_tls_mutual",
				},
				HealthCheck: EnvoyHealthCheck{
					Interval:           "5s",
					Timeout:            "2s",
					HealthyThreshold:   2,
					UnhealthyThreshold: 2,
					Port:               8085,
				},
			},
			{
				Name:       "tcp_proxy",
				Protocol:   "TCP",
				ListenPort: 10006,
				Upstreams: []EnvoyUpstreamServer{
					{"127.0.0.1", 20006},
				},
				TCP: EnvoyTCPParams{
					ConnectTimeout: "5s",
					IdleTimeout:    "3600s",
					ProxyProtocol:  true,
				},
				HealthCheck: EnvoyHealthCheck{
					Interval:           "5s",
					Timeout:            "2s",
					HealthyThreshold:   2,
					UnhealthyThreshold: 2,
					Port:               8086,
				},
			},
		},
	}

	t.Run("valid configuration passes", func(t *testing.T) {
		ldsBytes, err := RenderEnvoyLDS(cfg)
		if err != nil {
			t.Fatalf("failed to render LDS: %v", err)
		}

		cdsBytes, err := RenderEnvoyCDS(cfg)
		if err != nil {
			t.Fatalf("failed to render CDS: %v", err)
		}

		bootstrapBytes, err := buildStaticBootstrap(ldsBytes, cdsBytes)
		if err != nil {
			t.Fatalf("failed to build static bootstrap: %v", err)
		}

		bootstrapPath := filepath.Join(tmpDir, "bootstrap.yaml")
		if err := os.WriteFile(bootstrapPath, bootstrapBytes, 0644); err != nil {
			t.Fatalf("failed to write bootstrap: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, envoyBin, "--mode", "validate", "-c", bootstrapPath)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			t.Errorf("envoy validation failed with error %v:\nStdout:\n%s\nStderr:\n%s", err, stdout.String(), stderr.String())
		}
	})

	t.Run("invalid duration rejected", func(t *testing.T) {
		badCfg := EnvoyConfig{
			Listeners: []EnvoyListener{
				{
					Name:       "tcp_bad_duration",
					Protocol:   "TCP",
					ListenPort: 10007,
					Upstreams: []EnvoyUpstreamServer{
						{"127.0.0.1", 20007},
					},
					TCP: EnvoyTCPParams{
						ConnectTimeout: "5s",
						IdleTimeout:    "BOGUS",
					},
					HealthCheck: EnvoyHealthCheck{
						Interval:           "5s",
						Timeout:            "2s",
						HealthyThreshold:   2,
						UnhealthyThreshold: 2,
						Port:               8087,
					},
				},
			},
		}

		ldsBytes, err := RenderEnvoyLDS(badCfg)
		if err != nil {
			t.Fatalf("failed to render LDS: %v", err)
		}

		cdsBytes, err := RenderEnvoyCDS(badCfg)
		if err != nil {
			t.Fatalf("failed to render CDS: %v", err)
		}

		bootstrapBytes, err := buildStaticBootstrap(ldsBytes, cdsBytes)
		if err != nil {
			t.Fatalf("failed to build static bootstrap: %v", err)
		}

		bootstrapPath := filepath.Join(tmpDir, "bootstrap_bad.yaml")
		if err := os.WriteFile(bootstrapPath, bootstrapBytes, 0644); err != nil {
			t.Fatalf("failed to write bad bootstrap: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, envoyBin, "--mode", "validate", "-c", bootstrapPath)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err = cmd.Run()
		if err == nil {
			t.Fatal("expected envoy validation to fail on invalid duration, but it succeeded")
		}

		errMsg := stderr.String()
		if !strings.Contains(errMsg, "idle_timeout") && !strings.Contains(errMsg, "Duration") {
			t.Errorf("expected error message to mention 'idle_timeout' or 'Duration', got:\n%s", errMsg)
		}
	})
}
