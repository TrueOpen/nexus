package localschema

import (
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/TrueOpen/nexus/internal/kv"
)

func testEnv(store kv.Store) Env {
	return Env{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Store: store}
}

// rename moves every record of one namespace key to a new key: a real change of record layout.
func renameMigration(to uint32, from, into string) Migration {
	return Migration{To: to, Name: "rename " + from, Run: func(env Env) error {
		raw, found, err := env.Store.GetWithError(kv.NSTask, from)
		if err != nil || !found {
			return err
		}
		if err := env.Store.Set(kv.NSTask, into, raw); err != nil {
			return err
		}
		return env.Store.Delete(kv.NSTask, from)
	}}
}

// State without a recorded version is the baseline layout and is migrated step by step.
func TestUpgradeMigratesUnversionedStateInOrder(t *testing.T) {
	store := kv.NewMemStore()
	if err := store.Set(kv.NSTask, "a", []byte("record")); err != nil {
		t.Fatal(err)
	}
	migrations := []Migration{renameMigration(3, "b", "c"), renameMigration(2, "a", "b")}
	if err := Upgrade(testEnv(store), 3, migrations); err != nil {
		t.Fatal(err)
	}
	if raw, ok := store.Get(kv.NSTask, "c"); !ok || string(raw) != "record" {
		t.Fatalf("record not carried through both migrations: %q %v", raw, ok)
	}
	if version, err := Read(store); err != nil || version != 3 {
		t.Fatalf("version = %d, %v; want 3", version, err)
	}
	// Running again at the current version does nothing.
	if err := Upgrade(testEnv(store), 3, migrations); err != nil {
		t.Fatal(err)
	}
}

// A failed step leaves the version at the last completed one, and the next start resumes there.
func TestUpgradeResumesAfterFailedStep(t *testing.T) {
	store := kv.NewMemStore()
	fail := true
	migrations := []Migration{
		{To: 2, Name: "ok", Run: func(Env) error { return nil }},
		{To: 3, Name: "flaky", Run: func(Env) error {
			if fail {
				return errors.New("disk full")
			}
			return nil
		}},
	}
	if err := Upgrade(testEnv(store), 3, migrations); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("error = %v, want the step's failure", err)
	}
	if version, _ := Read(store); version != 2 {
		t.Fatalf("version = %d after a failed step, want 2", version)
	}
	fail = false
	if err := Upgrade(testEnv(store), 3, migrations); err != nil {
		t.Fatal(err)
	}
	if version, _ := Read(store); version != 3 {
		t.Fatalf("version = %d, want 3", version)
	}
}

func TestUpgradeRefusesNewerStateAndMissingSteps(t *testing.T) {
	store := kv.NewMemStore()
	if err := Stamp(store, 5); err != nil {
		t.Fatal(err)
	}
	if err := Upgrade(testEnv(store), 4, nil); !errors.Is(err, ErrNewerState) {
		t.Fatalf("error = %v, want ErrNewerState", err)
	}
	if err := Upgrade(testEnv(store), 7, []Migration{{To: 7, Run: func(Env) error { return nil }}}); err == nil ||
		!strings.Contains(err.Error(), "no migration from local state version 5 to 6") {
		t.Fatalf("error = %v, want a missing step", err)
	}
}

// The shipped migrations are consecutive from Baseline and end at Current.
func TestShippedMigrationsReachCurrent(t *testing.T) {
	for i, m := range Migrations {
		if m.To != Baseline+uint32(i)+1 || m.Run == nil || m.Name == "" {
			t.Fatalf("migration %d: To %d, want %d, with a name and a Run", i, m.To, Baseline+uint32(i)+1)
		}
	}
	if Baseline+uint32(len(Migrations)) != Current {
		t.Fatalf("migrations end at %d, Current is %d", Baseline+uint32(len(Migrations)), Current)
	}
}
