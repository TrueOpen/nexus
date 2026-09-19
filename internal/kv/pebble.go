package kv

import (
	"bytes"
	"fmt"
	"log/slog"
	"sync"

	"github.com/cockroachdb/pebble"
)

// pebbleStore is the production persistence implementation (Implementation Design §4.6 selects pebble).
// Key encoding: <ns> 0x00 <key> -- neither ns nor key contains 0x00 (ns is a constant of this package and key is a
// session|task composite key or a subject name, which satisfy this naturally).
// Writes use pebble.Sync. Besides rebuildable task snapshots, this store also keeps held credential keys and plaintext
// delivery state that cannot be recovered from the chain, so a successful return must mean the data is already durable.
type pebbleStore struct {
	log *slog.Logger
	db  *pebble.DB

	lifecycleMu sync.Mutex
	activeOps   sync.WaitGroup
	closed      bool
	closeOnce   sync.Once
	closeErr    error
}

// NewPebble opens (or creates) the pebble store under dir.
func NewPebble(dir string, log *slog.Logger) (Store, error) {
	db, err := pebble.Open(dir, &pebble.Options{Logger: pebbleQuietLogger{}})
	if err != nil {
		return nil, fmt.Errorf("kv: open pebble at %s: %w", dir, err)
	}
	return &pebbleStore{log: log, db: db}, nil
}

func encodeKey(ns Namespace, key string) []byte {
	b := make([]byte, 0, len(ns)+1+len(key))
	b = append(b, ns...)
	b = append(b, 0)
	b = append(b, key...)
	return b
}

func (s *pebbleStore) Get(ns Namespace, key string) ([]byte, bool) {
	val, ok, err := s.GetWithError(ns, key)
	if err != nil {
		s.log.Warn("kv get failed", "ns", ns, "key", key, "err", err)
		return nil, false
	}
	return val, ok
}

func (s *pebbleStore) GetWithError(ns Namespace, key string) ([]byte, bool, error) {
	if err := s.beginOperation(); err != nil {
		return nil, false, err
	}
	defer s.activeOps.Done()
	val, closer, err := s.db.Get(encodeKey(ns, key))
	if err != nil {
		if err == pebble.ErrNotFound {
			return nil, false, nil
		}
		return nil, false, err
	}
	cp := append([]byte(nil), val...)
	if err := closer.Close(); err != nil {
		return nil, false, err
	}
	return cp, true, nil
}

func (s *pebbleStore) Set(ns Namespace, key string, val []byte) error {
	if err := s.beginOperation(); err != nil {
		return err
	}
	defer s.activeOps.Done()
	if err := s.db.Set(encodeKey(ns, key), val, pebble.Sync); err != nil {
		s.log.Warn("kv set failed", "ns", ns, "key", key, "err", err)
		return err
	}
	return nil
}

func (s *pebbleStore) Delete(ns Namespace, key string) error {
	if err := s.beginOperation(); err != nil {
		return err
	}
	defer s.activeOps.Done()
	if err := s.db.Delete(encodeKey(ns, key), pebble.Sync); err != nil {
		s.log.Warn("kv delete failed", "ns", ns, "key", key, "err", err)
		return err
	}
	return nil
}

// WriteBatch commits through a single pebble batch: a pebble batch is atomic, so a crash halfway leaves either
// everything or nothing, never an intermediate state where the frame record is durable but the progress lags behind.
func (s *pebbleStore) WriteBatch(ops ...WriteOp) error {
	if len(ops) == 0 {
		return nil
	}
	if err := s.beginOperation(); err != nil {
		return err
	}
	defer s.activeOps.Done()
	batch := s.db.NewBatch()
	defer func() { _ = batch.Close() }()
	for _, op := range ops {
		var err error
		if op.Delete {
			err = batch.Delete(encodeKey(op.NS, op.Key), nil)
		} else {
			err = batch.Set(encodeKey(op.NS, op.Key), op.Val, nil)
		}
		if err != nil {
			s.log.Warn("kv batch stage failed", "ns", op.NS, "key", op.Key, "err", err)
			return err
		}
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		s.log.Warn("kv batch commit failed", "ops", len(ops), "err", err)
		return err
	}
	return nil
}

func (s *pebbleStore) Scan(ns Namespace, fn func(key string, val []byte) bool) error {
	if err := s.beginOperation(); err != nil {
		return err
	}
	defer s.activeOps.Done()
	prefix := encodeKey(ns, "")
	upper := append(append([]byte(nil), ns...), 1) // the separator right after 0x00 -> scan this partition only
	iter, err := s.db.NewIter(&pebble.IterOptions{LowerBound: prefix, UpperBound: upper})
	if err != nil {
		s.log.Warn("kv scan failed", "ns", ns, "err", err)
		return err
	}
	for iter.First(); iter.Valid(); iter.Next() {
		k := iter.Key()
		if !bytes.HasPrefix(k, prefix) {
			break
		}
		val, err := iter.ValueAndErr()
		if err != nil {
			s.log.Warn("kv scan value failed", "ns", ns, "err", err)
			_ = iter.Close()
			return err
		}
		if !fn(string(k[len(prefix):]), append([]byte(nil), val...)) {
			break
		}
	}
	if err := iter.Error(); err != nil {
		s.log.Warn("kv scan iteration failed", "ns", ns, "err", err)
		_ = iter.Close()
		return err
	}
	if err := iter.Close(); err != nil {
		s.log.Warn("kv scan close failed", "ns", ns, "err", err)
		return err
	}
	return nil
}

func (s *pebbleStore) Close() error {
	s.closeOnce.Do(func() {
		s.lifecycleMu.Lock()
		s.closed = true
		s.lifecycleMu.Unlock()
		s.activeOps.Wait()
		s.closeErr = s.db.Close()
	})
	return s.closeErr
}

func (s *pebbleStore) beginOperation() error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.closed {
		return pebble.ErrClosed
	}
	s.activeOps.Add(1)
	return nil
}

// pebbleQuietLogger silences pebble's internal logging (the event table is noisy; errors are reported through method return values).
type pebbleQuietLogger struct{}

func (pebbleQuietLogger) Infof(string, ...any)  {}
func (pebbleQuietLogger) Errorf(string, ...any) {}
func (pebbleQuietLogger) Fatalf(format string, args ...any) {
	panic(fmt.Sprintf("pebble fatal: "+format, args...))
}
