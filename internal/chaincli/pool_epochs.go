package chaincli

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/TrueOpen/nexus/internal/kv"
)

// maxPoolEpochs bounds the epoch -> candidate pool snapshot table. Only orders whose
// earliest_submit_height lies in a recent epoch can still be dispatched or challenged by this
// Builder, so older epochs are forgotten.
const maxPoolEpochs = 64

const poolEpochKeyPrefix = "candidate_pool_epoch/"

// poolEpochTable remembers the candidate pool snapshot of each epoch seen in a
// CANDIDATE_POOL_PUBLISHED or CANDIDATE_POOL_EXPIRED event: the chain answers only the current
// pool, while an order is drawn on the pool of the epoch its earliest_submit_height falls in. The
// table is kept in the chain_state namespace so a restart keeps the epochs already seen.
type poolEpochTable struct {
	mu      sync.Mutex
	store   kv.Store
	chainID string
	loaded  bool
	byEpoch map[uint64][]byte
}

func poolEpochKey(chainID string, epoch uint64) string {
	return fmt.Sprintf("%s%s/%020d", poolEpochKeyPrefix, chainID, epoch)
}

func (t *poolEpochTable) loadLocked() error {
	if t.loaded {
		return nil
	}
	t.byEpoch = map[uint64][]byte{}
	if t.store != nil {
		prefix := poolEpochKeyPrefix + t.chainID + "/"
		var bad error
		err := t.store.Scan(kv.NSChainState, func(key string, value []byte) bool {
			rest, ok := strings.CutPrefix(key, prefix)
			if !ok {
				return true
			}
			epoch, err := strconv.ParseUint(rest, 10, 64)
			if err != nil || len(value) != 32 {
				bad = fmt.Errorf("malformed candidate pool epoch entry %q", key)
				return false
			}
			t.byEpoch[epoch] = bytes.Clone(value)
			return true
		})
		if err == nil {
			err = bad
		}
		if err != nil {
			return fmt.Errorf("load candidate pool epochs: %w", err)
		}
	}
	t.loaded = true
	return nil
}

// record keeps snapshotID as the pool of epoch and forgets the oldest epochs beyond maxPoolEpochs.
func (t *poolEpochTable) record(epoch uint64, snapshotID []byte) error {
	if len(snapshotID) != 32 {
		return fmt.Errorf("candidate pool snapshot_id is %d bytes, want 32", len(snapshotID))
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.loadLocked(); err != nil {
		return err
	}
	if bytes.Equal(t.byEpoch[epoch], snapshotID) {
		return nil
	}
	ops := []kv.WriteOp{{NS: kv.NSChainState, Key: poolEpochKey(t.chainID, epoch), Val: bytes.Clone(snapshotID)}}
	epochs := make([]uint64, 0, len(t.byEpoch)+1)
	for e := range t.byEpoch {
		if e != epoch {
			epochs = append(epochs, e)
		}
	}
	epochs = append(epochs, epoch)
	sort.Slice(epochs, func(i, j int) bool { return epochs[i] < epochs[j] })
	var dropped []uint64
	for len(epochs) > maxPoolEpochs {
		dropped = append(dropped, epochs[0])
		ops = append(ops, kv.WriteOp{NS: kv.NSChainState, Key: poolEpochKey(t.chainID, epochs[0]), Delete: true})
		epochs = epochs[1:]
	}
	if t.store != nil {
		if err := t.store.WriteBatch(ops...); err != nil {
			return fmt.Errorf("store candidate pool epoch: %w", err)
		}
	}
	t.byEpoch[epoch] = bytes.Clone(snapshotID)
	for _, e := range dropped {
		delete(t.byEpoch, e)
	}
	return nil
}

func (t *poolEpochTable) lookup(epoch uint64) ([]byte, bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.loadLocked(); err != nil {
		return nil, false, err
	}
	snapshot, ok := t.byEpoch[epoch]
	return bytes.Clone(snapshot), ok, nil
}

func (c *client) epochTable() *poolEpochTable {
	c.poolEpochsOnce.Do(func() {
		c.poolEpochs = &poolEpochTable{store: c.cursorStore.store, chainID: c.cfg.ChainID}
	})
	return c.poolEpochs
}

// CandidatePoolSnapshotOfEpoch returns the snapshot_id the chain published as the candidate pool
// of epoch, as seen on the protocol event stream. ErrNotFound when no such event was seen (the
// stream is off, or the epoch is older than the table keeps).
func (c *client) CandidatePoolSnapshotOfEpoch(_ context.Context, epoch uint64) ([]byte, error) {
	snapshot, ok, err := c.epochTable().lookup(epoch)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("candidate pool of epoch %d: %w", epoch, ErrNotFound)
	}
	return snapshot, nil
}

func (c *stubClient) CandidatePoolSnapshotOfEpoch(context.Context, uint64) ([]byte, error) {
	return nil, ErrNotFound
}

// recordPoolEpoch keeps the epoch -> snapshot pair of a candidate pool event.
func (c *client) recordPoolEpoch(typed TypedEvent) error {
	switch e := typed.(type) {
	case CandidatePoolPublished:
		return c.epochTable().record(e.Epoch, e.SnapshotID)
	case CandidatePoolExpired:
		return c.epochTable().record(e.Epoch, e.SnapshotID)
	}
	return nil
}
