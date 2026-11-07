// Package kvtest provides a kv.Store for tests that counts synced and deferred writes and keeps
// the log of writes, so a test can see what a crash at the current point would leave.
package kvtest

import (
	"sync"

	"github.com/TrueOpen/nexus/internal/kv"
)

// Store is an in-memory kv.Store and kv.DeferredWriter. Set, Delete and WriteBatch are synced
// writes; WriteBatchDeferred is not. Like the pebble store, a crash keeps every write up to the
// last synced one and loses the rest (see kv.WriteDeferred).
type Store struct {
	// BeforeSync, when set, is called with the ops of every synced write before it is applied, so a
	// test can take Crash() at the instant before that write lands. It must not write to the store.
	BeforeSync func(ops []kv.WriteOp)

	mu       sync.Mutex
	live     kv.Store
	log      [][]kv.WriteOp
	durable  int // writes in log a crash keeps
	synced   int
	deferred int
}

var (
	_ kv.Store          = (*Store)(nil)
	_ kv.DeferredWriter = (*Store)(nil)
)

// New returns an empty Store.
func New() *Store { return &Store{live: kv.NewMemStore()} }

func (s *Store) Get(ns kv.Namespace, key string) ([]byte, bool) { return s.live.Get(ns, key) }

func (s *Store) GetWithError(ns kv.Namespace, key string) ([]byte, bool, error) {
	return s.live.GetWithError(ns, key)
}

func (s *Store) Scan(ns kv.Namespace, fn func(key string, val []byte) bool) error {
	return s.live.Scan(ns, fn)
}

func (s *Store) Set(ns kv.Namespace, key string, val []byte) error {
	return s.write(true, []kv.WriteOp{{NS: ns, Key: key, Val: val}})
}

func (s *Store) Delete(ns kv.Namespace, key string) error {
	return s.write(true, []kv.WriteOp{{NS: ns, Key: key, Delete: true}})
}

func (s *Store) WriteBatch(ops ...kv.WriteOp) error { return s.write(true, ops) }

func (s *Store) WriteBatchDeferred(ops ...kv.WriteOp) error { return s.write(false, ops) }

func (s *Store) Close() error { return nil }

func (s *Store) write(synced bool, ops []kv.WriteOp) error {
	if len(ops) == 0 {
		return nil
	}
	entry := make([]kv.WriteOp, len(ops))
	for i, op := range ops {
		op.Val = append([]byte(nil), op.Val...)
		entry[i] = op
	}
	if synced && s.BeforeSync != nil {
		s.BeforeSync(entry)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.live.WriteBatch(entry...); err != nil {
		return err
	}
	s.log = append(s.log, entry)
	if synced {
		s.synced++
		s.durable = len(s.log)
	} else {
		s.deferred++
	}
	return nil
}

// Synced is the number of synced writes made so far.
func (s *Store) Synced() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.synced
}

// Deferred is the number of deferred writes made so far.
func (s *Store) Deferred() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deferred
}

// Crash returns a new Store holding what a crash now would leave: every write up to and including
// the last synced one. Its counts start from zero.
func (s *Store) Crash() *Store {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := New()
	for _, entry := range s.log[:s.durable] {
		_ = out.live.WriteBatch(entry...)
		out.log = append(out.log, entry)
	}
	out.durable = len(out.log)
	return out
}
