package agentrun

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/achetronic/tunnel/internal/agentconfig"
	"github.com/achetronic/tunnel/internal/wg"
)

// testDoc returns a minimal document for exercising the retry loop. The fake
// apply functions never inspect it, so only the interface name matters (it is
// logged on success).
func testDoc() *agentconfig.Document {
	return &agentconfig.Document{
		WireGuard: agentconfig.WireGuardConfig{
			Interface: agentconfig.WireGuardInterface{Name: "wg-test"},
		},
	}
}

// The retry loop must keep attempting with exponentially increasing sleeps
// until an apply succeeds, then stop.
func TestRetryInitialApply_RetriesUntilSuccess(t *testing.T) {
	attempts := 0
	st := &applyState{fn: func(*agentconfig.Document) error {
		attempts++
		if attempts < 3 {
			return errors.New("netlink not ready")
		}
		return nil
	}}

	var sleeps []time.Duration
	sleep := func(d time.Duration) { sleeps = append(sleeps, d) }

	retryInitialApply(st, func() (*agentconfig.Document, error) { return testDoc(), nil }, sleep)

	if attempts != 3 {
		t.Fatalf("expected 3 apply attempts, got %d", attempts)
	}
	if !st.succeeded.Load() {
		t.Error("success was not recorded")
	}
	want := []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second}
	if len(sleeps) != len(want) {
		t.Fatalf("expected %d sleeps, got %v", len(want), sleeps)
	}
	for i := range want {
		if sleeps[i] != want[i] {
			t.Errorf("sleep %d: got %v, want %v", i, sleeps[i], want[i])
		}
	}
}

// A success recorded elsewhere (the config watcher re-applied after a config
// fix) must stop the retry loop without another apply attempt.
func TestRetryInitialApply_StopsWhenWatcherSucceeded(t *testing.T) {
	st := &applyState{fn: func(*agentconfig.Document) error {
		t.Fatal("apply must not be called once success is recorded")
		return nil
	}}
	st.succeeded.Store(true)

	retryInitialApply(st, func() (*agentconfig.Document, error) { return testDoc(), nil }, func(time.Duration) {})
}

// A Loader failure must not abort the loop: the document may be fixed on the
// next config sync, so the loop keeps backing off and reloading.
func TestRetryInitialApply_SurvivesLoaderErrors(t *testing.T) {
	loads := 0
	load := func() (*agentconfig.Document, error) {
		loads++
		if loads < 2 {
			return nil, errors.New("config not mounted yet")
		}
		return testDoc(), nil
	}
	applied := 0
	st := &applyState{fn: func(*agentconfig.Document) error {
		applied++
		return nil
	}}

	retryInitialApply(st, load, func(time.Duration) {})

	if loads != 2 || applied != 1 {
		t.Errorf("expected 2 loads and 1 apply, got %d loads and %d applies", loads, applied)
	}
}

// The backoff must double up to the cap and then stay there.
func TestRetryInitialApply_BackoffCaps(t *testing.T) {
	attempts := 0
	st := &applyState{fn: func(*agentconfig.Document) error {
		attempts++
		if attempts < 10 {
			return errors.New("still failing")
		}
		return nil
	}}

	var sleeps []time.Duration
	sleep := func(d time.Duration) { sleeps = append(sleeps, d) }

	retryInitialApply(st, func() (*agentconfig.Document, error) { return testDoc(), nil }, sleep)

	last := sleeps[len(sleeps)-1]
	if last != initialApplyBackoffCap {
		t.Errorf("expected final sleep at the cap (%v), got %v", initialApplyBackoffCap, last)
	}
	for i := 1; i < len(sleeps); i++ {
		if sleeps[i] < sleeps[i-1] {
			t.Errorf("backoff decreased at step %d: %v -> %v", i, sleeps[i-1], sleeps[i])
		}
		if sleeps[i] > initialApplyBackoffCap {
			t.Errorf("backoff exceeded cap: %v", sleeps[i])
		}
	}
}

// TestReadyHandler_WatcherNotActive verifies that the readiness handler returns
// a Service Unavailable status when the config watcher is not active.
func TestReadyHandler_WatcherNotActive(t *testing.T) {
	var watcherAlive atomic.Bool
	watcherAlive.Store(false)
	// succeeded=true so only the watcherAlive=false gate is under test.
	var succeeded atomic.Bool
	succeeded.Store(true)

	load := func() (*agentconfig.Document, error) {
		return testDoc(), nil
	}

	handler := readyHandler(load, &watcherAlive, &succeeded)
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, rr.Code)
	}

	wantBody := "config watcher is not active\n"
	if rr.Body.String() != wantBody {
		t.Errorf("expected body %q, got %q", wantBody, rr.Body.String())
	}
}

// TestReadyHandler_Healthy verifies that the readiness handler returns OK when
// the config watcher is active, the initial apply has succeeded, and the
// WireGuard interface is healthy.
func TestReadyHandler_Healthy(t *testing.T) {
	var watcherAlive atomic.Bool
	watcherAlive.Store(true)
	var succeeded atomic.Bool
	succeeded.Store(true)

	load := func() (*agentconfig.Document, error) {
		return testDoc(), nil
	}

	// Override wgStatus to return a healthy state
	oldStatus := wgStatus
	defer func() { wgStatus = oldStatus }()
	wgStatus = func(cfg agentconfig.WireGuardConfig) (wg.State, error) {
		return wg.State{
			Exists: true,
			Up:     true,
			Peers: []wg.PeerState{
				{
					LastHandshake: time.Now(),
				},
			},
		}, nil
	}

	handler := readyHandler(load, &watcherAlive, &succeeded)
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
	}

	wantBody := "OK\n"
	if rr.Body.String() != wantBody {
		t.Errorf("expected body %q, got %q", wantBody, rr.Body.String())
	}
}

// TestReadyHandler_SucceededFalse is the M-2 canary. It verifies that the
// readiness handler returns 503 when the initial full apply (WireGuard and
// nftables) has not yet succeeded, even though the config watcher is active
// and the WireGuard interface reports a fresh handshake. On HEAD 04b8774
// this test fails because the old readyHandler does not inspect the succeeded
// flag and returns 200 once WireGuard is healthy, silently hiding an absent
// nftables ruleset.
func TestReadyHandler_SucceededFalse(t *testing.T) {
	var watcherAlive atomic.Bool
	watcherAlive.Store(true)
	var succeeded atomic.Bool
	succeeded.Store(false)

	load := func() (*agentconfig.Document, error) {
		return testDoc(), nil
	}

	// Override wgStatus to return a healthy state so that the only source of
	// a 503 is the succeeded=false gate, not the WireGuard check.
	oldStatus := wgStatus
	defer func() { wgStatus = oldStatus }()
	wgStatus = func(cfg agentconfig.WireGuardConfig) (wg.State, error) {
		return wg.State{
			Exists: true,
			Up:     true,
			Peers:  []wg.PeerState{{LastHandshake: time.Now()}},
		}, nil
	}

	handler := readyHandler(load, &watcherAlive, &succeeded)
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status %d (initial apply not yet succeeded), got %d",
			http.StatusServiceUnavailable, rr.Code)
	}
	wantBody := "initial apply not yet succeeded\n"
	if rr.Body.String() != wantBody {
		t.Errorf("expected body %q, got %q", wantBody, rr.Body.String())
	}
}

// TestWatchFatal_CalledOnBadPath is the M-1 canary. It verifies that
// runWatchConfig calls watchFatal when the watched directory does not exist
// (watcher.Add fails), triggering process termination so the kubelet restarts
// the pod. On HEAD 04b8774 this test fails to compile because runWatchConfig
// and watchFatal do not exist; the old code silently returns from the goroutine,
// leaving the pod excluded from rotation with no recovery path.
func TestWatchFatal_CalledOnBadPath(t *testing.T) {
	var called atomic.Bool
	old := watchFatal
	defer func() { watchFatal = old }()
	watchFatal = func() { called.Store(true) }

	// nosuchdir is never created, so watcher.Add fails and watchConfig returns.
	dir := filepath.Join(t.TempDir(), "nosuchdir")
	path := filepath.Join(dir, "config.yaml")

	var watcherAlive atomic.Bool
	// Call runWatchConfig synchronously; the watchFatal stub returns normally
	// so runWatchConfig returns after recording the call.
	runWatchConfig(
		&applyState{fn: func(*agentconfig.Document) error { return nil }},
		func() (*agentconfig.Document, error) { return testDoc(), nil },
		path,
		&watcherAlive,
	)

	if !called.Load() {
		t.Fatal("watchFatal was not called after watcher.Add failed on a nonexistent directory")
	}
}
