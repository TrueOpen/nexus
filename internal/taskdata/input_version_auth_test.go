package taskdata

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

// INPUT is served only in the version the chain accepted: its accepted_task_hash, and its
// accepted_input_hash once the chain query carries it. A refusal is logged with both values.
func TestInputRequestsAreBoundToTheAcceptedVersion(t *testing.T) {
	fx := newAuthorizerFixture(t)
	var logs bytes.Buffer
	fx.authorizer.log = slog.New(slog.NewTextHandler(&logs, nil))
	input := fx.metadata[ObjectKindInput].Key
	otherTask := input
	otherTask.TaskHash = strings.Repeat("6f", 32)
	nonce := byte(40)
	allowed := func(key ObjectKey) (fetch, metadata error) {
		t.Helper()
		nonce++
		rng := &ByteRange{Offset: 0, Length: 4}
		_, fetch = fx.authorizer.AuthorizeFetch(context.Background(), fx.fixtureFetch(t, fx.worker, key, rng, nonce, 110), rng)
		nonce++
		metadata = fx.authorizer.AuthorizeMetadata(context.Background(),
			fx.fixtureRequest(t, fx.worker, MethodGetMetadata, key, nil, nonce, 110), nil)
		return fetch, metadata
	}

	if fetch, metadata := allowed(otherTask); !errors.Is(fetch, ErrUnauthorized) || !errors.Is(metadata, ErrUnauthorized) {
		t.Fatalf("other task_hash: fetch=%v metadata=%v, want ErrUnauthorized", fetch, metadata)
	}
	if !strings.Contains(logs.String(), "task input request names a version the chain did not accept") ||
		!strings.Contains(logs.String(), "accepted_task_hash="+testTaskHash) {
		t.Fatalf("refusal log = %s", logs.String())
	}
	if fetch, metadata := allowed(input); fetch != nil || metadata != nil {
		t.Fatalf("accepted version: fetch=%v metadata=%v", fetch, metadata)
	}

	fx.authority.task.Assignment.AcceptedInputHash = strings.Repeat("7a", 32)
	if fetch, metadata := allowed(input); !errors.Is(fetch, ErrUnauthorized) || !errors.Is(metadata, ErrUnauthorized) {
		t.Fatalf("other input_hash: fetch=%v metadata=%v, want ErrUnauthorized", fetch, metadata)
	}
	fx.authority.task.Assignment.AcceptedInputHash = input.ContentHash
	if fetch, metadata := allowed(input); fetch != nil || metadata != nil {
		t.Fatalf("accepted input_hash: fetch=%v metadata=%v", fetch, metadata)
	}
}
