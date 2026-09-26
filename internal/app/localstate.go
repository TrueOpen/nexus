package app

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/TrueOpen/nexus/internal/chainreset"
	"github.com/TrueOpen/nexus/internal/kv"
)

// localStateCheckTimeout bounds the chain identity queries at startup.
const localStateCheckTimeout = 30 * time.Second

// openLocalState opens the local kv and checks it belongs to the chain src is connected to. When it
// belongs to a chain that was since reset, the kv and task data directories are moved aside and an
// empty kv is opened in their place; the TLS directory is left alone, its fingerprint is on chain.
// The returned monitor watches for a reset while running; it is nil when no identity is recorded.
func openLocalState(log *slog.Logger, dataDir, chainID string, src chainreset.Source) (kv.Store, *chainreset.Monitor, error) {
	kvDir := filepath.Join(dataDir, "kv")
	store, err := kv.NewPebble(kvDir, log)
	if err != nil {
		return nil, nil, fmt.Errorf("kv: %w", err)
	}
	log.Info("local kv opened (pebble)", "dir", kvDir)
	if src == nil {
		log.Warn("chain identity check not enabled: the chain client cannot read block hashes")
		return store, nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), localStateCheckTimeout)
	defer cancel()
	decision, err := chainreset.Check(ctx, store, src, chainID)
	if err != nil {
		_ = store.Close()
		return nil, nil, fmt.Errorf("chain identity: %w", err)
	}
	switch decision.Verdict {
	case chainreset.Unchecked:
		if decision.Previous == (chainreset.Identity{}) {
			log.Warn("chain identity check not enabled for this run; a chain reset will not be noticed until the next start",
				"reason", decision.Reason)
			return store, nil, nil
		}
		// The recorded identity still lets a reset be noticed while running.
		log.Warn("chain identity could not be checked at startup; comparing against the recorded one while running",
			"reason", decision.Reason, "recorded", decision.Previous.String())
		return store, chainreset.NewMonitor(log, src, decision.Previous), nil
	case chainreset.Same:
		log.Info("chain identity matches local state", "chain", decision.Current.String())
	case chainreset.Recorded:
		if err := chainreset.Record(store, decision.Current); err != nil {
			_ = store.Close()
			return nil, nil, fmt.Errorf("record chain identity: %w", err)
		}
		log.Info("chain identity recorded", "chain", decision.Current.String())
	case chainreset.Reset:
		if err := store.Close(); err != nil {
			return nil, nil, fmt.Errorf("close kv of the previous chain: %w", err)
		}
		moved, err := chainreset.Archive([]string{kvDir, taskDataRoot(dataDir)}, time.Now().UTC().Format("20060102T150405Z"))
		if err != nil {
			return nil, nil, fmt.Errorf("move aside local state of the previous chain (moved %v): %w", moved, err)
		}
		log.Error("chain was reset: local state of the previous chain moved aside, starting with empty state; "+
			"delete the moved directories by hand when they are no longer needed",
			"reason", decision.Reason, "previous", decision.Previous.String(), "current", decision.Current.String(),
			"moved", moved)
		store, err = kv.NewPebble(kvDir, log)
		if err != nil {
			return nil, nil, fmt.Errorf("kv: %w", err)
		}
		if err := chainreset.Record(store, decision.Current); err != nil {
			_ = store.Close()
			return nil, nil, fmt.Errorf("record chain identity: %w", err)
		}
	}
	return store, chainreset.NewMonitor(log, src, decision.Current), nil
}
