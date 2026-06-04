// Package agentrun is the shared apply/run core used by both the tunnelctl
// binary and the in-cluster uplink agent. It applies a desired-state document
// (WireGuard always, nftables when present), and can run as a daemon that
// watches the document for changes and serves a readiness endpoint. Callers
// provide a Loader so the source of the document (a file, or a template with
// runtime identity injected) stays their concern.
package agentrun

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/achetronic/tunnel/internal/agentconfig"
	"github.com/achetronic/tunnel/internal/nftables"
	"github.com/achetronic/tunnel/internal/wg"
)

// handshakeFreshness is how recent a WireGuard handshake must be for a node to
// be considered ready. WireGuard refreshes the latest handshake only on rekey
// (about every 120s), so the threshold sits above that to avoid flapping.
const handshakeFreshness = 180 * time.Second

// Loader returns the fully-resolved desired-state document ready to apply. It is
// called for the initial apply, on every config-change re-apply, and by the
// readiness probe, so a caller that injects runtime identity (for example the
// uplink private key and address) does it inside the Loader and the result stays
// consistent across all three paths.
type Loader func() (*agentconfig.Document, error)

// Apply applies the WireGuard config and, when present, the nftables config of
// doc. It is idempotent: re-running with the same document is a no-op.
func Apply(doc *agentconfig.Document) error {
	if err := wg.Apply(doc.WireGuard); err != nil {
		return err
	}
	if doc.Nftables != nil {
		if err := nftables.Apply(*doc.Nftables); err != nil {
			return err
		}
	}
	return nil
}

// Readiness decides whether a node is ready from its observed WireGuard state:
// the interface must exist, be up, and have at least one peer with a handshake
// within handshakeFreshness.
func Readiness(state wg.State) (bool, string) {
	if !state.Exists {
		return false, "interface not present"
	}
	if !state.Up {
		return false, "interface is down"
	}
	for _, p := range state.Peers {
		if !p.LastHandshake.IsZero() && time.Since(p.LastHandshake) <= handshakeFreshness {
			return true, "healthy"
		}
	}
	return false, "no recent handshake"
}

// Run applies the document from load, watches watchPath and re-applies on change,
// and serves a readiness endpoint at healthAddr backed by the same status core.
// It blocks until the readiness server stops.
func Run(ctx context.Context, load Loader, watchPath, healthAddr string) error {
	doc, err := load()
	if err != nil {
		return err
	}
	if err := Apply(doc); err != nil {
		slog.Error("initial apply failed", "error", err)
	} else {
		slog.Info("applied desired state", "interface", doc.WireGuard.Interface.Name)
	}

	go watchConfig(load, watchPath)

	mux := http.NewServeMux()
	mux.HandleFunc("/ready", readyHandler(load))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	srv := &http.Server{
		Addr:              healthAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	slog.Info("agent run listening", "addr", healthAddr, "config", watchPath)
	if err := srv.ListenAndServe(); err != nil {
		return fmt.Errorf("readiness server: %w", err)
	}
	return nil
}

// watchConfig watches the directory holding the config file and re-applies on
// change. Kubernetes swaps a mounted ConfigMap through a "..data" symlink, so
// both that and the file itself are treated as triggers. Apply failures are
// logged, not fatal, so a transient bad config can recover when it is fixed.
func watchConfig(load Loader, path string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		slog.Error("failed to create config watcher", "error", err)
		return
	}
	defer func() { _ = watcher.Close() }()

	dir := filepath.Dir(path)
	if err := watcher.Add(dir); err != nil {
		slog.Error("failed to watch config directory", "dir", dir, "error", err)
		return
	}
	base := filepath.Base(path)
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if !event.Has(fsnotify.Create) && !event.Has(fsnotify.Write) {
				continue
			}
			if !strings.Contains(event.Name, "..data") && filepath.Base(event.Name) != base {
				continue
			}
			doc, err := load()
			if err != nil {
				slog.Error("reload config failed", "error", err)
				continue
			}
			if err := Apply(doc); err != nil {
				slog.Error("re-apply failed", "error", err)
				continue
			}
			slog.Info("re-applied desired state on config change")
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			slog.Warn("config watcher error", "error", err)
		}
	}
}

// readyHandler returns an HTTP handler that reports node readiness, reusing the
// same status core as the status subcommand.
func readyHandler(load Loader) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		doc, err := load()
		if err != nil {
			http.Error(w, fmt.Sprintf("config error: %v", err), http.StatusServiceUnavailable)
			return
		}
		state, err := wg.Status(doc.WireGuard)
		if err != nil {
			http.Error(w, fmt.Sprintf("status error: %v", err), http.StatusServiceUnavailable)
			return
		}
		if ready, detail := Readiness(state); !ready {
			http.Error(w, detail, http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		if _, err := fmt.Fprintln(w, "OK"); err != nil {
			slog.Warn("failed to write readiness response", "error", err)
		}
	}
}
