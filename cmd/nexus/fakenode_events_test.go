package main

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

// The fake node keeps a Builder role event stream open with no events until the client leaves, so
// a Nexus started with direct dispatch configured does not reconnect and warn in a loop.
func TestFakeStartNodeRoleEventStreamStaysOpenEmpty(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- fakeStartTaskEvents{}.SubscribeRoleEvents(ctx, connect.NewRequest(&taskv1.SubscribeRoleEventsRequest{}), nil)
	}()
	select {
	case err := <-done:
		t.Fatalf("role event stream ended before the client left: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("role event stream ended with %v", err)
	}
}
