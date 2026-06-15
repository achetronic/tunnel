// Command tunnelctl applies and inspects a tunnel node's desired state from a
// JSON document: WireGuard (always) and nftables (uplink only). It runs the same
// core on both sides. The edge invokes "apply"/"status" once over SSH; "run" is
// the daemon mode (watch the config and serve a readiness endpoint).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/achetronic/tunnel/internal/agentconfig"
	"github.com/achetronic/tunnel/internal/agentrun"
	"github.com/achetronic/tunnel/internal/configtransform"
	"github.com/achetronic/tunnel/internal/logging"
	"github.com/achetronic/tunnel/internal/wg"
)

func main() {
	logging.SetupDefault()

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "apply":
		err = cmdApply(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		slog.Error("tunnelctl failed", "subcommand", os.Args[1], "error", err)
		os.Exit(1)
	}
}

// usage prints the command synopsis to stderr.
func usage() {
	fmt.Fprintln(os.Stderr, "usage: tunnelctl <apply|status|run> --config <file> [--transforms <file>]")
}

// parseFlags parses the shared flags for a subcommand: --config (required),
// --transforms (optional CEL transforms applied to the config before use), and
// --health-addr (run only). It returns the config path, the transforms path
// (empty when unset) and the health address.
func parseFlags(name string, args []string) (configFile, transformsFile, healthAddr string, err error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	cfg := fs.String("config", "", "path to the desired-state JSON document")
	tr := fs.String("transforms", "", "optional CEL transforms document applied to the config before use")
	var ha *string
	if name == "run" {
		ha = fs.String("health-addr", ":40500", "address for the readiness server")
	}
	if err := fs.Parse(args); err != nil {
		return "", "", "", err
	}
	if *cfg == "" {
		return "", "", "", fmt.Errorf("--config is required")
	}
	addr := ":40500"
	if ha != nil {
		addr = *ha
	}
	return *cfg, *tr, addr, nil
}

// loadConfig reads the desired-state document at configFile, optionally
// postprocesses it with the CEL transforms at transformsFile, and parses the
// result. Transforms run on every call, so the run loop re-resolves any
// environment- or file-derived values on each reload.
func loadConfig(configFile, transformsFile string) (*agentconfig.Document, error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", configFile, err)
	}
	if transformsFile != "" {
		rules, err := os.ReadFile(transformsFile)
		if err != nil {
			return nil, fmt.Errorf("read transforms %q: %w", transformsFile, err)
		}
		data, err = configtransform.Apply(data, rules)
		if err != nil {
			return nil, fmt.Errorf("apply transforms: %w", err)
		}
	}
	return agentconfig.Parse(data)
}

// cmdApply applies the document once and returns.
func cmdApply(args []string) error {
	cfg, tr, _, err := parseFlags("apply", args)
	if err != nil {
		return err
	}
	doc, err := loadConfig(cfg, tr)
	if err != nil {
		return err
	}
	if err := agentrun.Apply(doc); err != nil {
		return err
	}
	slog.Info("applied desired state", "interface", doc.WireGuard.Interface.Name, "nftables", doc.Nftables != nil)
	return nil
}

// statusReport is the JSON status emitted by the status subcommand.
type statusReport struct {
	Interface string       `json:"interface"`
	Exists    bool         `json:"exists"`
	Up        bool         `json:"up"`
	Ready     bool         `json:"ready"`
	Detail    string       `json:"detail"`
	Peers     []peerReport `json:"peers"`
}

// peerReport is the per-peer slice of a statusReport.
type peerReport struct {
	PublicKey     string `json:"publicKey"`
	LastHandshake string `json:"lastHandshake,omitempty"`
	Endpoint      string `json:"endpoint,omitempty"`
}

// cmdStatus prints the device status as JSON and returns an error when the node
// is not ready, so a caller (the operator over SSH) can gate on the exit code.
func cmdStatus(args []string) error {
	cfg, tr, _, err := parseFlags("status", args)
	if err != nil {
		return err
	}
	doc, err := loadConfig(cfg, tr)
	if err != nil {
		return err
	}
	state, err := wg.Status(doc.WireGuard)
	if err != nil {
		return err
	}
	ready, detail := agentrun.Readiness(state)

	report := statusReport{
		Interface: doc.WireGuard.Interface.Name,
		Exists:    state.Exists,
		Up:        state.Up,
		Ready:     ready,
		Detail:    detail,
	}
	for _, p := range state.Peers {
		pr := peerReport{PublicKey: p.PublicKey, Endpoint: p.Endpoint}
		if !p.LastHandshake.IsZero() {
			pr.LastHandshake = p.LastHandshake.UTC().Format(time.RFC3339)
		}
		report.Peers = append(report.Peers, pr)
	}
	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("encode status: %w", err)
	}
	fmt.Println(string(out))
	if !ready {
		return fmt.Errorf("not ready: %s", detail)
	}
	return nil
}

// cmdRun applies the document, then watches it and serves a readiness endpoint,
// re-applying whenever the config changes. It binds a context to SIGTERM and
// SIGINT so a pod shutdown (rolling update, drain) triggers a graceful drain in
// agentrun.Run instead of an abrupt exit that resets in-flight connections.
func cmdRun(args []string) error {
	cfg, tr, healthAddr, err := parseFlags("run", args)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return agentrun.Run(ctx, func() (*agentconfig.Document, error) {
		return loadConfig(cfg, tr)
	}, cfg, healthAddr)
}
