package app

import (
	"context"
	"errors"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/types"
)

type sessionChain struct {
	chaincli.Client
	state chaincli.SessionState
	err   error
}

func (c sessionChain) QuerySession(context.Context, string) (chaincli.SessionState, error) {
	return c.state, c.err
}

func TestRegisteredKeysRead(t *testing.T) {
	keys, err := newRegisteredKeys(config.IngressConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.read(context.Background(), "s"); err == nil {
		t.Fatal("a read before the chain client is set must fail")
	}
	key := make([]byte, 20)
	key[0] = 7
	keys.chain = sessionChain{state: chaincli.SessionState{
		Owner: "trueopen1owner", Key: key, ExpiryHeight: 10, SetHeight: 3, SpendCap: "5", Spent: "1",
	}}
	state, err := keys.read(context.Background(), "s")
	if err != nil || !state.Found || state.Key == nil || state.Key[0] != 7 || state.Owner != "trueopen1owner" ||
		state.ExpiryHeight != 10 || state.SetHeight != 3 || state.SpendCap != "5" || state.Spent != "1" {
		t.Fatalf("state = %+v, %v", state, err)
	}
	keys.chain = sessionChain{err: chaincli.ErrNotFound}
	if state, err := keys.read(context.Background(), "s"); err != nil || state.Found {
		t.Fatalf("missing session = %+v, %v; want not found and no error", state, err)
	}
	keys.chain = sessionChain{err: errors.New("endpoint unavailable")}
	if _, err := keys.read(context.Background(), "s"); err == nil {
		t.Fatal("a failed read must be an error")
	}
	if _, err := newRegisteredKeys(config.IngressConfig{SessionKeyCacheTTLBlocks: 11}); err == nil {
		t.Fatal("a ttl above the limit must be refused")
	}
}

func TestLocalTaskRecord(t *testing.T) {
	for name, c := range map[string]struct {
		err       error
		found     bool
		wantError bool
	}{
		"on record":   {found: true},
		"not found":   {err: types.ErrTaskNotFound},
		"read failed": {err: errors.New("disk"), wantError: true},
	} {
		local := localTaskRecord(func(context.Context, string, string) (string, error) { return "owner", c.err })
		found, err := local(context.Background(), "s", "t")
		if found != c.found || (err != nil) != c.wantError {
			t.Fatalf("%s: found=%v err=%v", name, found, err)
		}
	}
}
