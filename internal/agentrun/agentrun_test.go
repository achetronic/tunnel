package agentrun

import (
	"errors"
	"testing"
	"time"

	"github.com/achetronic/tunnel/internal/agentconfig"
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
