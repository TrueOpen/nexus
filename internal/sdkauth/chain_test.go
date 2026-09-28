package sdkauth

import (
	"context"
	"errors"
	"testing"
)

var errMissing = errors.New("missing")

// A found key is cached; a miss is not, so a key that reaches the chain later is seen at once.
func TestCachedChainCachesOnlyFoundKeys(t *testing.T) {
	calls := 0
	onChain := map[string][]byte{}
	chain := NewCachedChain(
		func(context.Context) (uint64, error) { return 7, nil },
		func(_ context.Context, address string) ([]byte, error) {
			calls++
			key, ok := onChain[address]
			if !ok {
				return nil, errMissing
			}
			return key, nil
		},
		func(err error) bool { return errors.Is(err, errMissing) },
		2,
	)
	ctx := context.Background()
	if _, err := chain.AccountPubKey(ctx, "a"); !errors.Is(err, ErrNoAccountKey) {
		t.Fatalf("missing key: %v", err)
	}
	onChain["a"] = []byte{1}
	if key, err := chain.AccountPubKey(ctx, "a"); err != nil || key[0] != 1 {
		t.Fatalf("key after first transaction: %v %v", key, err)
	}
	if _, err := chain.AccountPubKey(ctx, "a"); err != nil || calls != 2 {
		t.Fatalf("cached key re-read: calls=%d err=%v", calls, err)
	}
	onChain["b"], onChain["c"] = []byte{2}, []byte{3}
	_, _ = chain.AccountPubKey(ctx, "b")
	_, _ = chain.AccountPubKey(ctx, "c") // evicts "a"
	before := calls
	_, _ = chain.AccountPubKey(ctx, "a")
	if calls != before+1 {
		t.Fatal("evicted key was not re-read")
	}
}
