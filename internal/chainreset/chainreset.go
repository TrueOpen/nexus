// Package chainreset notices that the chain behind this Builder was re-initialised with the same
// chain_id (a devnet or testnet reset) and keeps local state from one chain from being used on the
// next.
//
// Everything in the local kv and task data store is bound to chain heights and tasks of the chain
// it was written on: task snapshots, event cursors, retention heights, request nonces, bus
// positions. None of it means anything on a new chain, and some of it is harmful there (task
// snapshots reconciled forever, an observed height far above the new chain's). A production chain
// is not reset with the same chain_id, so rather than making each store survive a reset, a reset is
// answered with a new, empty local state: at startup the old kv and task data directories are moved
// aside, and a reset seen while running stops the process so that the next start does that.
//
// The chain identity is chain_id plus the hash of the block at height 1. A node that has pruned
// that block cannot answer, and the check is then off.
package chainreset

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/TrueOpen/nexus/internal/kv"
)

// ErrChainReset is returned by the process when the chain was reset while it was running. The
// state is left for the next start to archive.
var ErrChainReset = errors.New("chain identity changed: the chain was reset, restart nexus")

// ExitCode is the process exit code for ErrChainReset, distinct from the generic failure code 1
// so a supervisor or operator can tell "restart me" from a crash.
const ExitCode = 75

const (
	identityKey = "chain_identity"
	// legacyHeightKey keeps the observed height of state written before an identity was recorded,
	// taken at the first start that finds no identity and kept until one is recorded. The
	// coordinator overwrites its own record with the connected chain's height as soon as it runs,
	// so without this copy one start that could not check the chain would make the old state look
	// like the new chain's for good.
	legacyHeightKey = "legacy_observed_height"
	// identityHeight is the block whose hash identifies the chain.
	identityHeight int64 = 1
	// HeightRegressionBlocks is how far the latest height must fall below an observed one before it
	// is taken as a sign of a reset rather than a lagging node.
	HeightRegressionBlocks uint64 = 100
	// coordinatorStateKey and coordinatorState mirror the coordinator's chain state record
	// (coordinator/chainstate.go): only its last observed height is read.
	coordinatorStateKey = "coordinator"
)

type coordinatorState struct {
	LastObservedHeight uint64 `json:"last_observed_height"`
}

// Source is the chain query surface the check needs.
type Source interface {
	BlockHash(ctx context.Context, height int64) ([]byte, error)
	Syncing(ctx context.Context) (bool, error)
	LatestHeight(ctx context.Context) (uint64, error)
}

// Identity names one chain.
type Identity struct {
	ChainID        string `json:"chain_id"`
	FirstBlockHash string `json:"first_block_hash"`
}

func (i Identity) String() string {
	return i.ChainID + "/" + i.FirstBlockHash
}

// Query reads the identity of the chain src is connected to.
func Query(ctx context.Context, src Source, chainID string) (Identity, error) {
	hash, err := src.BlockHash(ctx, identityHeight)
	if err != nil {
		return Identity{}, err
	}
	return Identity{ChainID: chainID, FirstBlockHash: hex.EncodeToString(hash)}, nil
}

// Load returns the identity recorded in store.
func Load(store kv.Store) (Identity, bool, error) {
	raw, ok, err := store.GetWithError(kv.NSChainState, identityKey)
	if err != nil || !ok {
		return Identity{}, false, err
	}
	var identity Identity
	if err := json.Unmarshal(raw, &identity); err != nil {
		return Identity{}, false, fmt.Errorf("decode chain identity: %w", err)
	}
	return identity, true, nil
}

// Record stores identity and drops the legacy height kept for the check before it.
func Record(store kv.Store, identity Identity) error {
	raw, err := json.Marshal(identity)
	if err != nil {
		return err
	}
	return store.WriteBatch(
		kv.WriteOp{NS: kv.NSChainState, Key: identityKey, Val: raw},
		kv.WriteOp{NS: kv.NSChainState, Key: legacyHeightKey, Delete: true},
	)
}

// Verdict is what the startup check concluded.
type Verdict int

const (
	// Unchecked: the chain could not tell its identity; nothing is recorded or changed.
	Unchecked Verdict = iota
	// Same: the recorded identity matches the chain.
	Same
	// Recorded: nothing was recorded and nothing suggests a reset; the identity is to be recorded.
	Recorded
	// Reset: the local state belongs to another chain.
	Reset
)

// Decision is the startup check's result.
type Decision struct {
	Verdict Verdict
	Current Identity
	// Previous is the recorded identity, zero when none is recorded.
	Previous Identity
	Reason   string
}

// Check compares the chain's identity with the one recorded in store.
//
// Without a recorded identity (state written by a version before this check, or a first start) a
// reset is inferred from the observed height: state that has seen a height more than
// HeightRegressionBlocks above the chain's latest one was written on another chain. A node that is
// still catching up also reports a low height, so the inference is skipped while it syncs. The
// inference is only used until an identity is recorded; after that, only the identity decides.
//
// The inference has a blind spot: when the new chain has already grown past the old state's
// height by the time this check first runs, the old state is taken as the new chain's.
func Check(ctx context.Context, store kv.Store, src Source, chainID string) (Decision, error) {
	previous, recorded, err := Load(store)
	if err != nil {
		return Decision{}, err
	}
	var observed uint64
	if !recorded {
		// Taken before any chain query, so that a failed query cannot lose it.
		if observed, err = preserveLegacyHeight(store); err != nil {
			return Decision{}, err
		}
	}
	current, err := Query(ctx, src, chainID)
	if err != nil {
		return Decision{Verdict: Unchecked, Previous: previous, Reason: err.Error()}, nil
	}
	if recorded {
		if previous == current {
			return Decision{Verdict: Same, Current: current, Previous: previous}, nil
		}
		return Decision{Verdict: Reset, Current: current, Previous: previous,
			Reason: fmt.Sprintf("recorded chain %s, connected chain %s", previous, current)}, nil
	}
	if observed == 0 {
		return Decision{Verdict: Recorded, Current: current}, nil
	}
	syncing, err := src.Syncing(ctx)
	if err != nil {
		return Decision{Verdict: Unchecked, Reason: err.Error()}, nil
	}
	if syncing {
		return Decision{Verdict: Unchecked, Reason: "node is catching up, its height says nothing about a reset"}, nil
	}
	latest, err := src.LatestHeight(ctx)
	if err != nil {
		return Decision{Verdict: Unchecked, Reason: err.Error()}, nil
	}
	if observed > latest+HeightRegressionBlocks {
		return Decision{Verdict: Reset, Current: current,
			Reason: fmt.Sprintf("local state observed height %d, chain latest height %d", observed, latest)}, nil
	}
	return Decision{Verdict: Recorded, Current: current}, nil
}

// preserveLegacyHeight returns the observed height of unrecorded state, copying the coordinator's
// value the first time so later starts keep reading the height the old state saw.
func preserveLegacyHeight(store kv.Store) (uint64, error) {
	if raw, ok, err := store.GetWithError(kv.NSChainState, legacyHeightKey); err != nil {
		return 0, err
	} else if ok {
		height, err := strconv.ParseUint(string(raw), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("decode legacy observed height: %w", err)
		}
		return height, nil
	}
	raw, ok, err := store.GetWithError(kv.NSChainState, coordinatorStateKey)
	if err != nil || !ok {
		return 0, err
	}
	var state coordinatorState
	if err := json.Unmarshal(raw, &state); err != nil {
		return 0, fmt.Errorf("decode chain state: %w", err)
	}
	if state.LastObservedHeight == 0 {
		return 0, nil
	}
	if err := store.Set(kv.NSChainState, legacyHeightKey, []byte(strconv.FormatUint(state.LastObservedHeight, 10))); err != nil {
		return 0, fmt.Errorf("keep legacy observed height: %w", err)
	}
	return state.LastObservedHeight, nil
}

// Archive moves each existing directory in dirs to "<dir>.stale-<tag>" and returns the new paths.
// Nothing is deleted.
func Archive(dirs []string, tag string) ([]string, error) {
	var moved []string
	for _, dir := range dirs {
		if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return moved, err
		}
		target := filepath.Clean(dir) + ".stale-" + tag
		if err := os.Rename(dir, target); err != nil {
			return moved, fmt.Errorf("archive %s: %w", dir, err)
		}
		moved = append(moved, target)
	}
	return moved, nil
}

// Monitor confirms a suspected reset while the process runs. Suspect is cheap and may be called on
// every hint; a confirmed reset is delivered once on Fatal. SameChain answers a single question
// without acting on it.
type Monitor struct {
	log      *slog.Logger
	src      Source
	recorded Identity
	// confirmations is how many identity reads in a row must disagree, interval apart.
	confirmations int
	interval      time.Duration
	// cooldown is the least time between two confirmation runs.
	cooldown time.Duration
	now      func() time.Time

	mu       sync.Mutex
	checking bool
	lastRun  time.Time
	fatal    chan error
	fired    bool
}

// NewMonitor watches for the chain to stop being recorded.
func NewMonitor(log *slog.Logger, src Source, recorded Identity) *Monitor {
	return &Monitor{
		log: log, src: src, recorded: recorded,
		confirmations: 3, interval: 3 * time.Second, cooldown: time.Minute,
		now: time.Now, fatal: make(chan error, 1),
	}
}

// Fatal delivers ErrChainReset once a reset is confirmed.
func (m *Monitor) Fatal() <-chan error {
	if m == nil {
		return nil
	}
	return m.fatal
}

// ErrCheckOff is returned by SameChain when there is no recorded identity to compare with.
var ErrCheckOff = errors.New("chain identity check is off")

// SameChain reads the chain's identity once and reports whether it is still the recorded one.
func (m *Monitor) SameChain(ctx context.Context) (bool, error) {
	if m == nil {
		return false, ErrCheckOff
	}
	identity, err := Query(ctx, m.src, m.recorded.ChainID)
	if err != nil {
		return false, err
	}
	return identity == m.recorded, nil
}

// Suspect starts a confirmation run in the background unless one is running or ran recently.
func (m *Monitor) Suspect(reason string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.fired || m.checking || (!m.lastRun.IsZero() && m.now().Sub(m.lastRun) < m.cooldown) {
		m.mu.Unlock()
		return
	}
	m.checking = true
	m.lastRun = m.now()
	m.mu.Unlock()
	go m.confirm(reason)
}

func (m *Monitor) confirm(reason string) {
	defer func() {
		m.mu.Lock()
		m.checking = false
		m.mu.Unlock()
	}()
	var current Identity
	for i := 0; i < m.confirmations; i++ {
		if i > 0 {
			time.Sleep(m.interval)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		identity, err := Query(ctx, m.src, m.recorded.ChainID)
		cancel()
		if err != nil {
			m.log.Warn("suspected chain reset could not be confirmed: chain identity query failed",
				"reason", reason, "err", err)
			return
		}
		if identity == m.recorded {
			m.log.Warn("suspected chain reset, but the chain identity is unchanged", "reason", reason)
			return
		}
		if i > 0 && identity != current {
			m.log.Warn("suspected chain reset, but the chain identity is not stable", "reason", reason)
			return
		}
		current = identity
	}
	m.log.Error("chain identity changed: the chain was reset, restart nexus; the next start moves the old local state aside",
		"reason", reason, "recorded", m.recorded.String(), "current", current.String(), "exit_code", ExitCode)
	m.mu.Lock()
	m.fired = true
	m.mu.Unlock()
	m.fatal <- ErrChainReset
}
