package taskdata

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/TrueOpen/nexus/internal/kv"
)

// The nonce write is one batch: an expired record of another nonce is pruned with its index, an
// expired record of the same nonce is replaced, and the new record and index are both stored.
func TestConsumeNonceWritesOneConsistentBatch(t *testing.T) {
	fx := newAuthorizerFixture(t)
	ctx := context.Background()
	user := fx.user.Address()
	nonceA, nonceB := bytes.Repeat([]byte{0xa}, 16), bytes.Repeat([]byte{0xb}, 16)
	if err := fx.authorizer.AuthorizeOpenTaskRequest(ctx, user, nonceA, 105, 1000); err != nil {
		t.Fatal(err)
	}
	if err := fx.authorizer.AuthorizeOpenTaskRequest(ctx, user, nonceB, 106, 1000); err != nil {
		t.Fatal(err)
	}
	fx.authority.height = 107
	// nonceA again: its old record expired (105 < 107) and is replaced; nonceB's (106) is pruned.
	if err := fx.authorizer.AuthorizeOpenTaskRequest(ctx, user, nonceA, 120, 1000); err != nil {
		t.Fatalf("reused expired nonce: %v", err)
	}
	records := map[string][]byte{}
	if err := fx.backend.Scan(kv.NSTaskDataReplay, func(key string, val []byte) bool {
		records[key] = val
		return true
	}); err != nil {
		t.Fatal(err)
	}
	var index []string
	if err := fx.backend.Scan(kv.NSTaskDataReplayExpiry, func(key string, _ []byte) bool {
		index = append(index, key)
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || len(index) != 1 {
		t.Fatalf("records = %d, index = %v; want only nonceA's new record and index", len(records), index)
	}
	expiry, replayKey, err := parseReplayExpiryKey(index[0])
	if err != nil || expiry != 120 || records[replayKey] == nil {
		t.Fatalf("index %q does not name the stored record at expiry 120", index[0])
	}
	if err := fx.authorizer.AuthorizeOpenTaskRequest(ctx, user, nonceA, 120, 1000); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay after the batch: %v, want ErrReplay", err)
	}
}

type failingBatchStore struct{ kv.Store }

func (failingBatchStore) WriteBatch(...kv.WriteOp) error { return errors.New("disk full") }

func TestConsumeNonceBatchFailureStoresNothing(t *testing.T) {
	fx := newAuthorizerFixture(t)
	authorizer, err := NewAuthorizer(fx.authorizer.cfg, failingBatchStore{fx.backend}, fx.authority, fx.service)
	if err != nil {
		t.Fatal(err)
	}
	if err := authorizer.AuthorizeOpenTaskRequest(context.Background(), fx.user.Address(), bytes.Repeat([]byte{1}, 16), 110, 1000); !errors.Is(err, ErrStorage) {
		t.Fatalf("batch failure: %v, want ErrStorage", err)
	}
	found := false
	_ = fx.backend.Scan(kv.NSTaskDataReplay, func(string, []byte) bool { found = true; return false })
	if found {
		t.Fatal("a replay record was stored although the batch failed")
	}
}
