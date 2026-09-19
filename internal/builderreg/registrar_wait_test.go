package builderreg

import (
	"context"
	"strings"
	"testing"
	"time"
)

// After broadcasting a descriptor update, `nexus builder register` must wait for it to actually be
// committed before returning: the operator runs `nexus start` next, and start only checks and never
// submits, so it would be rejected while the update is still in the mempool.

func TestEnsureWaitsUntilTheDescriptorUpdateIsEffective(t *testing.T) {
	sg := testSigner(t)
	state := registeredBuilderState(sg, "https://old.example")
	sub := &captureSubmitter{state: state, deferUpdates: true}
	// The update is only committed on the third QueryBuilder call.
	state.onQueryBuilder = func(queries int) {
		if queries == 3 {
			sub.applyPendingUpdate()
		}
	}
	reg := newTestRegistrar(state, sub, sg, identityConfig("https://builder.example"))
	WithDescriptorWait(time.Millisecond, time.Second)(reg)

	if err := reg.Ensure(context.Background()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if len(sub.updates) != 1 {
		t.Fatalf("updates = %d, want exactly one broadcast while waiting", len(sub.updates))
	}
	if state.builder.CurrentDescriptorVersion != 2 {
		t.Fatalf("descriptor version on chain = %d, want 2 after the update landed", state.builder.CurrentDescriptorVersion)
	}
	if state.queries < 3 {
		t.Fatalf("QueryBuilder polls = %d, want the registrar to keep polling until the update lands", state.queries)
	}
}

func TestEnsureReportsADescriptorUpdateThatDoesNotLand(t *testing.T) {
	sg := testSigner(t)
	state := registeredBuilderState(sg, "https://old.example")
	sub := &captureSubmitter{state: state, deferUpdates: true} // never committed
	reg := newTestRegistrar(state, sub, sg, identityConfig("https://builder.example"))
	WithDescriptorWait(time.Millisecond, 20*time.Millisecond)(reg)

	err := reg.Ensure(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not yet effective") {
		t.Fatalf("Ensure with an update that never lands = %v, want an error saying it is not yet effective", err)
	}
	if len(sub.updates) != 1 {
		t.Fatalf("updates = %d, want one broadcast, no resubmission", len(sub.updates))
	}
}
