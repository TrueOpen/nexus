package app

import (
	"context"
	"errors"
	"testing"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatchevidence"
)

// A member copy's windows are those of the params its session froze, read from the chain; an
// unreadable session is an error (the copy reads it again later), one the chain no longer holds
// has none.
func TestSessionWindowsAreTheSessionsFrozenOnes(t *testing.T) {
	frozen := &taskv1.DispatchParamsV1{RecordDeadlineBlocks: 20, MaxOrderLifetimeBlocks: 120, DispatchCompensationClaimWindowBlocks: 90}
	var state chaincli.SessionState
	var readErr error
	od := &orderDispatch{readSession: func(_ context.Context, sessionID string) (chaincli.SessionState, error) {
		if sessionID != "aa" {
			t.Errorf("session %s read", sessionID)
		}
		return state, readErr
	}}
	state.FrozenDispatch = frozen
	w, err := od.sessionWindows(context.Background(), "aa")
	if want := dispatchevidence.ParamsFromChain(frozen); err != nil || w == nil || *w != want {
		t.Fatalf("windows = %+v, %v", w, err)
	}
	readErr = errors.New("chain unreachable")
	if w, err := od.sessionWindows(context.Background(), "aa"); err == nil || w != nil {
		t.Fatalf("unreadable session = %+v, %v", w, err)
	}
	readErr = chaincli.ErrNotFound
	if w, err := od.sessionWindows(context.Background(), "aa"); err != nil || w != nil {
		t.Fatalf("session the chain no longer holds = %+v, %v", w, err)
	}
}
