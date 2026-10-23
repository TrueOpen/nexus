package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/registeredkey"
	"github.com/TrueOpen/nexus/internal/stagetiming"
	"github.com/TrueOpen/nexus/internal/types"
)

// registeredKeys is the ingress view of keys owners register on their sessions: a cache of session
// state read from the Task chain. The cache also observes the task event streams of the sessions
// this Builder tracks, so it is built before the chain client and given the client afterwards.
type registeredKeys struct {
	cache *registeredkey.Cache
	chain chaincli.Client
}

func newRegisteredKeys(ingress config.IngressConfig) (*registeredKeys, error) {
	r := &registeredKeys{}
	cache, err := registeredkey.NewCache(registeredkey.CacheConfig{
		Read: r.read, TTLBlocks: ingress.SessionKeyCacheTTLBlocks, LookupsPerSecond: ingress.SessionKeyLookupsPerSecond,
	})
	if err != nil {
		return nil, err
	}
	r.cache = cache
	return r, nil
}

func (r *registeredKeys) read(ctx context.Context, sessionID string) (registeredkey.State, error) {
	if r.chain == nil {
		return registeredkey.State{}, fmt.Errorf("task chain client is not set")
	}
	start := time.Now()
	s, err := r.chain.QuerySession(ctx, sessionID)
	stagetiming.From(ctx).Since("chain_session_state", start)
	if errors.Is(err, chaincli.ErrNotFound) {
		return registeredkey.State{}, nil
	}
	if err != nil {
		return registeredkey.State{}, err
	}
	state := registeredkey.State{
		Found: true, Owner: s.Owner, Closed: s.Closed, ExpiryHeight: s.ExpiryHeight, SetHeight: s.SetHeight,
		SpendCap: s.SpendCap, Spent: s.Spent,
	}
	if s.Key != nil {
		var key [20]byte
		copy(key[:], s.Key)
		state.Key = &key
	}
	return state, nil
}

// localTaskRecord reports whether this Builder holds a record of the Task: the session a Task data
// request signed by a registered key is judged against is the one of this record.
func localTaskRecord(owner func(ctx context.Context, sessionID, taskID string) (string, error)) func(context.Context, string, string) (bool, error) {
	return func(ctx context.Context, sessionID, taskID string) (bool, error) {
		_, err := owner(ctx, sessionID, taskID)
		if errors.Is(err, types.ErrTaskNotFound) {
			return false, nil
		}
		return err == nil, err
	}
}
