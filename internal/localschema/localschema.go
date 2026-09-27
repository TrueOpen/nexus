// Package localschema versions the layout of this Builder's local state (the kv store and the task
// data directory) so that it can move forward across software upgrades without being wiped.
//
// A chain upgraded in place keeps its identity, so package chainreset keeps the local state; any
// later change to how that state is laid out must then be carried out by a migration here. The
// version is a single number in the kv store. At startup a state older than the running binary is
// migrated one step at a time, and a state written by a newer binary is refused: running an older
// binary on it could misread records it does not know.
package localschema

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/TrueOpen/nexus/internal/kv"
)

// Current is the local state layout this binary reads and writes. Raise it together with a new
// entry in Migrations whenever a change to local records needs existing data rewritten.
const Current uint32 = 1

// Baseline is the version of state written before the version was recorded: the layout of the
// first binary that knew about versions.
const Baseline uint32 = 1

const versionKey = "version"

// Migration rewrites local state from version To-1 to version To. Run must be safe to run again
// after a crash part way through: the version only advances once Run returns nil.
type Migration struct {
	To   uint32
	Name string
	Run  func(Env) error
}

// Env is what a migration may touch.
type Env struct {
	Log          *slog.Logger
	Store        kv.Store
	TaskDataRoot string
}

// Migrations lists every migration in ascending To order, starting at Baseline+1.
var Migrations []Migration

// ErrNewerState is returned when the local state was written by a newer binary.
var ErrNewerState = errors.New("local state was written by a newer nexus")

// Stamp records current as the version of a freshly created, empty state.
func Stamp(store kv.Store, current uint32) error {
	return store.Set(kv.NSLocalSchema, versionKey, []byte(strconv.FormatUint(uint64(current), 10)))
}

// Read returns the recorded version, or Baseline when none is recorded.
func Read(store kv.Store) (uint32, error) {
	raw, found, err := store.GetWithError(kv.NSLocalSchema, versionKey)
	if err != nil {
		return 0, fmt.Errorf("read local state version: %w", err)
	}
	if !found {
		return Baseline, nil
	}
	version, err := strconv.ParseUint(string(raw), 10, 32)
	if err != nil || version == 0 {
		return 0, fmt.Errorf("local state version %q is not a positive integer", raw)
	}
	return uint32(version), nil
}

// Upgrade brings the local state to version current by running migrations in order, recording the
// version after each one. It refuses a state newer than current and a gap in migrations.
func Upgrade(env Env, current uint32, migrations []Migration) error {
	version, err := Read(env.Store)
	if err != nil {
		return err
	}
	if version > current {
		return fmt.Errorf("%w: its version is %d, this binary reads up to %d", ErrNewerState, version, current)
	}
	for version < current {
		next := version + 1
		var step *Migration
		for i := range migrations {
			if migrations[i].To == next {
				step = &migrations[i]
				break
			}
		}
		if step == nil {
			return fmt.Errorf("no migration from local state version %d to %d", version, next)
		}
		env.Log.Info("migrating local state", "from", version, "to", next, "migration", step.Name)
		if err := step.Run(env); err != nil {
			return fmt.Errorf("local state migration %d (%s): %w", next, step.Name, err)
		}
		if err := Stamp(env.Store, next); err != nil {
			return fmt.Errorf("record local state version %d: %w", next, err)
		}
		version = next
	}
	return nil
}
