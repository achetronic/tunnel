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
	"sync"
	"sync/atomic"
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

// Backoff bounds for retrying the initial apply. The first attempt already
// failed when the retry loop starts, so it begins at the floor and doubles
// up to the cap.
const (
	initialApplyBackoffFloor = 1 * time.Second
	initialApplyBackoffCap   = 60 * time.Second
)

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

// applyState serializes Apply calls issued by the daemon's goroutines (the
// initial-apply retry loop and the config watcher) and remembers whether any
// apply has succeeded, so the retry loop can stop once the node converged
// through either path. fn defaults to Apply; tests inject a fake.
type applyState struct {
	mu        sync.Mutex
	succeeded atomic.Bool
	fn        func(*agentconfig.Document) error
}

// apply runs the apply function under the lock and records success.
func (s *applyState) apply(doc *agentconfig.Document) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn := s.fn
	if fn == nil {
		fn = Apply
	}
	if err := fn(doc); err != nil {
		return err
	}
	s.succeeded.Store(true)
	return nil
}

// Run applies the document from load, watches watchPath and re-applies on change,
// and serves a readiness endpoint at healthAddr backed by the same status core.
// It blocks until the readiness server stops.
func Run(ctx context.Context, load Loader, watchPath, healthAddr string) error {
	// st serializes Apply calls between the retry loop and the watcher and
	// records whether any of them has succeeded yet.
	st := &applyState{}

	doc, err := load()
	if err != nil {
		return err
	}
	if err := st.apply(doc); err != nil {
		// Without a retry, a failed initial apply (e.g. a race with the
		// WireGuard kernel module at startup) leaves the daemon Running
		// but NotReady forever: nothing re-applies until the config
		// changes and there is no CrashLoop to rescue it. Retry in the
		// background until something applies successfully.
		slog.Error("initial apply failed, retrying with backoff", "error", err)
		go retryInitialApply(st, load, time.Sleep)
	} else {
		slog.Info("applied desired state", "interface", doc.WireGuard.Interface.Name)
	}

	var watcherAlive atomic.Bool
	go watchConfig(st, load, watchPath, &watcherAlive)

	mux := http.NewServeMux()
	mux.HandleFunc("/ready", readyHandler(load, &watcherAlive))
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

// retryInitialApply re-attempts the initial apply with exponential backoff
// (floor 1s, cap 60s) until an apply succeeds, reloading the document on each
// attempt so a config fix is picked up. It exits as soon as st records a
// success, including one achieved by the config watcher. sleep is injected
// for tests.
func retryInitialApply(st *applyState, load Loader, sleep func(time.Duration)) {
	backoff := initialApplyBackoffFloor
	for {
		sleep(backoff)
		if st.succeeded.Load() {
			return
		}
		doc, err := load()
		if err != nil {
			slog.Error("initial apply retry: reload config failed", "error", err, "next_attempt_in", backoff*2)
		} else if err := st.apply(doc); err != nil {
			slog.Error("initial apply retry failed", "error", err, "next_attempt_in", backoff*2)
		} else {
			slog.Info("initial apply succeeded after retry", "interface", doc.WireGuard.Interface.Name)
			return
		}
		if backoff < initialApplyBackoffCap {
			backoff *= 2
			if backoff > initialApplyBackoffCap {
				backoff = initialApplyBackoffCap
			}
		}
	}
}

// watchConfig watches the directory holding the config file and re-applies on
// change. Kubernetes swaps a mounted ConfigMap through a "..data" symlink, so
// both that and the file itself are treated as triggers. Apply failures are
// logged, not fatal, so a transient bad config can recover when it is fixed.
func watchConfig(st *applyState, load Loader, path string, watcherAlive *atomic.Bool) {
	defer watcherAlive.Store(false)

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
	watcherAlive.Store(true)
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
			if err := st.apply(doc); err != nil {
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

// wgStatus retrieves the WireGuard interface state. It is a package variable to
// allow tests to override the status retrieval with a mock function.
var wgStatus = wg.Status

// readyHandler returns an HTTP handler that reports node readiness, reusing the
// same status core as the status subcommand.
// The handler treats not yet started watchers as not ready.
func readyHandler(load Loader, watcherAlive *atomic.Bool) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if !watcherAlive.Load() {
			http.Error(w, "config watcher is not active", http.StatusServiceUnavailable)
			return
		}
		doc, err := load()
		if err != nil {
			http.Error(w, fmt.Sprintf("config error: %v", err), http.StatusServiceUnavailable)
			return
		}
		state, err := wgStatus(doc.WireGuard)
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
