// SPDX-FileCopyrightText: 2026 Alby Hernández (Achetronic)
// SPDX-License-Identifier: Apache-2.0

// Package agentrun is the shared apply/run core used by both the tunnelctl
// binary and the in-cluster uplink agent. It applies a desired-state document
// (WireGuard always, nftables when present), and can run as a daemon that
// watches the document for changes and serves a readiness endpoint. Callers
// provide a Loader so the source of the document (a file, or a template with
// runtime identity injected) stays their concern.
package agentrun

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/achetronic/tunnel/internal/agentconfig"
	"github.com/achetronic/tunnel/internal/netdev"
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

// Apply applies the WireGuard config and, when present, the nftables and netdev
// configs of doc. It is idempotent: re-running with the same document is a no-op.
// The three appliers are package variables so tests can substitute fakes; the
// defaults are the real native appliers.
func Apply(doc *agentconfig.Document) error {
	if err := applyWireGuard(doc.WireGuard); err != nil {
		return err
	}
	if doc.Nftables != nil {
		if err := applyNftables(*doc.Nftables); err != nil {
			return err
		}
	}
	if doc.Netdev != nil {
		if err := applyNetdev(*doc.Netdev); err != nil {
			return err
		}
	}
	return nil
}

// applyWireGuard, applyNftables and applyNetdev are the native appliers Apply
// dispatches to. They are package variables so tests can replace them without
// touching the kernel; production uses the real implementations.
var (
	applyWireGuard = wg.Apply
	applyNftables  = nftables.Apply
	applyNetdev    = netdev.Apply
)

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
	// runWatchConfig terminates the process when watchConfig returns, so the
	// kubelet can restart the pod instead of leaving it silently broken.
	go runWatchConfig(st, load, watchPath, &watcherAlive)

	// draining flips to true on shutdown (SIGTERM via ctx) so readiness reports
	// 503 and Envoy ejects this replica from rotation before the link is torn
	// down, instead of resetting in-flight connections on an abrupt exit.
	var draining atomic.Bool

	mux := http.NewServeMux()
	mux.HandleFunc("/ready", readyHandler(load, &watcherAlive, &st.succeeded, &draining))
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

	// Serve in the background so the main goroutine can react to ctx
	// cancellation (SIGTERM) and drain gracefully.
	serveErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- fmt.Errorf("readiness server: %w", err)
			return
		}
		serveErr <- nil
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		drainAndShutdown(srv, &draining, time.Sleep)
		<-serveErr
		return nil
	}
}

// Backoff and drain timing constants.
const (
	// drainWindow is how long readiness reports 503 before the readiness server
	// is shut down on SIGTERM, giving Envoy's active health checks time to
	// observe the failure and eject this replica so new connections stop
	// arriving while in-flight ones keep working.
	drainWindow = 15 * time.Second
	// shutdownTimeout bounds the graceful HTTP server shutdown after the drain
	// window so a stuck connection cannot block the exit indefinitely.
	shutdownTimeout = 5 * time.Second
)

// drainAndShutdown flips the draining flag so readiness returns 503, waits the
// drain window for Envoy to eject this replica, then gracefully shuts the
// readiness server down. sleep is injected so tests can shrink the window.
func drainAndShutdown(srv *http.Server, draining *atomic.Bool, sleep func(time.Duration)) {
	draining.Store(true)
	slog.Info("draining: reporting NotReady so Envoy ejects this replica", "window", drainWindow)
	sleep(drainWindow)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Warn("readiness server shutdown returned an error", "error", err)
	}
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
// watchConfig returns only when the watch cannot be maintained (NewWatcher
// failure, Add failure, or the Events channel closing); callers must treat a
// return as a fatal condition.
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

// watchFatal is called when the config watcher cannot be maintained.
// The default implementation calls os.Exit(1), which causes CrashLoopBackOff
// so the kubelet restarts the pod. Tests override this var to record the call
// without killing the test process.
var watchFatal = func() { os.Exit(1) }

// runWatchConfig calls watchConfig and, when it returns (which only happens
// when the watch cannot be maintained: NewWatcher failure, Add failure, or the
// Events channel closing), logs a fatal message and calls watchFatal. The
// kubelet restart triggered by watchFatal is the self-healing recovery path
// when no LivenessProbe is configured.
func runWatchConfig(st *applyState, load Loader, path string, watcherAlive *atomic.Bool) {
	watchConfig(st, load, path, watcherAlive)
	slog.Error("config watcher terminated; process will exit so the kubelet can restart it")
	watchFatal()
}

// wgStatus retrieves the WireGuard interface state. It is a package variable to
// allow tests to override the status retrieval with a mock function.
var wgStatus = wg.Status

// readyHandler returns an HTTP handler that reports node readiness. The handler
// returns 503 when the pod is draining (SIGTERM received), when the config
// watcher is not active (covering the startup window and the brief period before
// process exit on watcher death), when the initial full apply (WireGuard and
// nftables) has not yet succeeded, or when the WireGuard handshake is not fresh.
// All conditions must hold for the handler to return 200.
func readyHandler(load Loader, watcherAlive *atomic.Bool, succeeded *atomic.Bool, draining *atomic.Bool) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		// Draining is checked first: on SIGTERM the pod must report NotReady
		// immediately so Envoy ejects it before the link is torn down.
		if draining.Load() {
			http.Error(w, "draining", http.StatusServiceUnavailable)
			return
		}
		if !watcherAlive.Load() {
			http.Error(w, "config watcher is not active", http.StatusServiceUnavailable)
			return
		}
		// Require at least one successful full apply (WireGuard and nftables)
		// before reporting ready. Without this gate the pod would report 200
		// while DNAT rules are absent, silently blackholing forwarded connections.
		if !succeeded.Load() {
			http.Error(w, "initial apply not yet succeeded", http.StatusServiceUnavailable)
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
