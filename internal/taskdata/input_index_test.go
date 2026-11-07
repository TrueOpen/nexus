package taskdata

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
)

// otherVersion returns the header of another INPUT version of the same task.
func otherVersion(body []byte) UploadHeader {
	header := testHeader(body)
	header.Key.TaskHash = strings.Repeat("6f", 32)
	return header
}

func resolvedInput(t *testing.T, store *Store) (ObjectRef, bool) {
	t.Helper()
	ref, err := store.ResolveObject(context.Background(), testSessionID, testTaskID, ObjectKindInput)
	if errors.Is(err, ErrNotFound) {
		return ObjectRef{}, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return ref, true
}

func TestInputIndexWrittenOnlyAtReady(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig())
	body := []byte("abcdefgh")
	prepared := prepareObject(t, store, testHeader(body), body)
	if ref, found := resolvedInput(t, store); found {
		t.Fatalf("PREPARED input is indexed: %#v", ref)
	}
	if _, err := store.MarkReady(context.Background(), prepared.Key); err != nil {
		t.Fatal(err)
	}
	if ref, found := resolvedInput(t, store); !found || ref != prepared.Key {
		t.Fatalf("index after MarkReady = %#v, %t", ref, found)
	}
}

// A refused version prepared next to the tracked one is removed without dropping the tracked
// version's index, whether by rollback or by delete.
func TestRemovingAnotherVersionKeepsTrackedIndex(t *testing.T) {
	for _, remove := range []string{"rollback", "delete"} {
		t.Run(remove, func(t *testing.T) {
			store, _, _ := newTestStore(t, testStoreConfig())
			body := []byte("abcdefgh")
			tracked := prepareObject(t, store, testHeader(body), body)
			if _, err := store.MarkReady(context.Background(), tracked.Key); err != nil {
				t.Fatal(err)
			}
			refused := prepareObject(t, store, otherVersion([]byte("12345678")), []byte("12345678"))
			var err error
			if remove == "rollback" {
				err = store.RollbackPrepared(context.Background(), refused.Key)
			} else {
				err = store.DeleteObject(context.Background(), refused.Key)
			}
			if err != nil {
				t.Fatal(err)
			}
			if ref, found := resolvedInput(t, store); !found || ref != tracked.Key {
				t.Fatalf("index after %s = %#v, %t; want the tracked version", remove, ref, found)
			}
		})
	}
}

func TestDeleteObjectClearsItsOwnIndex(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig())
	body := []byte("abcdefgh")
	tracked := prepareObject(t, store, testHeader(body), body)
	if _, err := store.MarkReady(context.Background(), tracked.Key); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteObject(context.Background(), tracked.Key); err != nil {
		t.Fatal(err)
	}
	if ref, found := resolvedInput(t, store); found {
		t.Fatalf("index survived its object: %#v", ref)
	}
}

// A re-signed retry of an order whose dispatch failed (same task_id, new task_hash) is the only
// way a second INPUT version turns READY: the dispatcher refused every other version before its
// input was marked READY. The retried version takes the index, so its Worker is served its own
// input; the earlier version stays stored until its retention ends.
func TestReadyRetriedInputTakesTheIndex(t *testing.T) {
	var logs bytes.Buffer
	store, _, _ := newTestStore(t, testStoreConfig())
	store.log = slog.New(slog.NewTextHandler(&logs, nil))
	body := []byte("abcdefgh")
	first := prepareObject(t, store, testHeader(body), body)
	if _, err := store.MarkReady(context.Background(), first.Key); err != nil {
		t.Fatal(err)
	}
	retried := prepareObject(t, store, otherVersion([]byte("12345678")), []byte("12345678"))
	if _, err := store.MarkReady(context.Background(), retried.Key); err != nil {
		t.Fatal(err)
	}
	if ref, found := resolvedInput(t, store); !found || ref != retried.Key {
		t.Fatalf("index = %#v, %t; want the retried version", ref, found)
	}
	if strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("retry logged an error: %s", logs.String())
	}
	if metadata, err := store.Metadata(context.Background(), first.Key); err != nil || metadata.State != StateReady {
		t.Fatalf("earlier version = %+v, %v; want it kept READY", metadata, err)
	}
	// A repeated MarkReady of the earlier version only repairs a missing index: it does not take
	// the index back.
	if _, err := store.MarkReady(context.Background(), first.Key); err != nil {
		t.Fatal(err)
	}
	if ref, found := resolvedInput(t, store); !found || ref != retried.Key {
		t.Fatalf("index after a repeated MarkReady of the earlier version = %#v, %t", ref, found)
	}
}

func TestRecoverIndexesPromotedInputAndClearsRejectedOne(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig())
	body := []byte("abcdefgh")
	accepted := prepareObject(t, store, testHeader(body), body)
	resolver := recoveryResolver{accepted: map[string]bool{objectKeyString(accepted.Key): true}}
	if err := store.Recover(context.Background(), resolver); err != nil {
		t.Fatal(err)
	}
	if ref, found := resolvedInput(t, store); !found || ref != accepted.Key {
		t.Fatalf("index after Recover promotion = %#v, %t", ref, found)
	}

	// A rejected version found by a later recovery does not take the index with it.
	rejected := prepareObject(t, store, otherVersion([]byte("12345678")), []byte("12345678"))
	if err := store.Recover(context.Background(), resolver); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Metadata(context.Background(), rejected.Key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rejected version metadata error = %v", err)
	}
	if ref, found := resolvedInput(t, store); !found || ref != accepted.Key {
		t.Fatalf("index after rejecting another version = %#v, %t", ref, found)
	}
}

func TestSweepIndexesPromotedQuarantinedInput(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig())
	body := []byte("abcdefgh")
	input := prepareObject(t, store, testHeader(body), body)
	if err := store.Recover(context.Background(), recoveryResolver{acceptedErr: errors.New("authority unavailable")}); err != nil {
		t.Fatal(err)
	}
	if ref, found := resolvedInput(t, store); found {
		t.Fatalf("QUARANTINED input is indexed: %#v", ref)
	}
	resolver := recoveryResolver{
		accepted:  map[string]bool{objectKeyString(input.Key): true},
		retention: map[string]RetentionDecision{objectKeyString(input.Key): {Status: RetentionActive}},
	}
	if err := store.Sweep(context.Background(), 10, resolver); err != nil {
		t.Fatal(err)
	}
	if ref, found := resolvedInput(t, store); !found || ref != input.Key {
		t.Fatalf("index after Sweep promotion = %#v, %t", ref, found)
	}
}

func TestSweepRetentionDeleteClearsInputIndex(t *testing.T) {
	store, _, _ := newTestStore(t, testStoreConfig())
	body := []byte("abcdefgh")
	input := prepareObject(t, store, testHeader(body), body)
	if _, err := store.MarkReady(context.Background(), input.Key); err != nil {
		t.Fatal(err)
	}
	resolver := recoveryResolver{retention: map[string]RetentionDecision{
		objectKeyString(input.Key): {Status: RetentionEligibleForCleanup, RetainUntilHeight: 100, Delete: true},
	}}
	if err := store.Sweep(context.Background(), 100, resolver); err != nil {
		t.Fatal(err)
	}
	if ref, found := resolvedInput(t, store); found {
		t.Fatalf("index survived retention delete: %#v", ref)
	}
}

// Recover reports, without changing it, an INPUT index naming a version that has no accepted order
// when no other version has one: retention releases the version once its retention ends.
func TestRecoverReportsInputIndexWithoutAcceptedOrder(t *testing.T) {
	var logs bytes.Buffer
	store, _, _ := newTestStore(t, testStoreConfig())
	store.log = slog.New(slog.NewTextHandler(&logs, nil))
	body := []byte("abcdefgh")
	input := prepareObject(t, store, testHeader(body), body)
	if _, err := store.MarkReady(context.Background(), input.Key); err != nil {
		t.Fatal(err)
	}
	if err := store.Recover(context.Background(), recoveryResolver{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "task input index names a version without an accepted order") {
		t.Fatalf("missing index check warning: %s", logs.String())
	}
	if strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("index check logged an error: %s", logs.String())
	}
	if ref, found := resolvedInput(t, store); !found || ref != input.Key {
		t.Fatalf("index check changed the index: %#v, %t", ref, found)
	}
	logs.Reset()
	accepted := recoveryResolver{accepted: map[string]bool{objectKeyString(input.Key): true}}
	if err := store.Recover(context.Background(), accepted); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "task input index") {
		t.Fatalf("index check logged for an accepted version: %s", logs.String())
	}
}

// An INPUT index left on an earlier version by a release that kept it when a re-signed retry
// turned READY moves at startup to the READY version with an accepted order, as a version turning
// READY takes it; with no accepted version the index is left, warned about once per version.
func TestRecoverMovesStaleInputIndexToTheAcceptedVersion(t *testing.T) {
	var logs bytes.Buffer
	store, _, _ := newTestStore(t, testStoreConfig())
	store.log = slog.New(slog.NewTextHandler(&logs, nil))
	body := []byte("abcdefgh")
	failed := prepareObject(t, store, testHeader(body), body)
	if _, err := store.MarkReady(context.Background(), failed.Key); err != nil {
		t.Fatal(err)
	}
	retried := prepareObject(t, store, otherVersion([]byte("12345678")), []byte("12345678"))
	if _, err := store.MarkReady(context.Background(), retried.Key); err != nil {
		t.Fatal(err)
	}
	stale := func() {
		t.Helper()
		if err := store.indexInput(failed.Key, true); err != nil {
			t.Fatal(err)
		}
		logs.Reset()
	}

	// No version has an accepted order: the index stays, for retention to release both versions.
	stale()
	if err := store.Recover(context.Background(), recoveryResolver{}); err != nil {
		t.Fatal(err)
	}
	if ref, found := resolvedInput(t, store); !found || ref != failed.Key {
		t.Fatalf("index with no accepted version = %#v, %t; want it left", ref, found)
	}
	if got := strings.Count(logs.String(), "level=WARN"); got != 1 || strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("index with no accepted version logged %d warnings: %s", got, logs.String())
	}

	// The retried version has the accepted order: it takes the index.
	stale()
	accepted := recoveryResolver{accepted: map[string]bool{objectKeyString(retried.Key): true}}
	if err := store.Recover(context.Background(), accepted); err != nil {
		t.Fatal(err)
	}
	if ref, found := resolvedInput(t, store); !found || ref != retried.Key {
		t.Fatalf("index after Recover = %#v, %t; want the accepted version", ref, found)
	}
	if strings.Contains(logs.String(), "level=WARN") || strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("index move logged a warning or an error: %s", logs.String())
	}
	if metadata, err := store.Metadata(context.Background(), failed.Key); err != nil || metadata.State != StateReady {
		t.Fatalf("earlier version = %+v, %v; want it kept for retention", metadata, err)
	}

	// An index check that cannot ask about the other versions changes nothing.
	stale()
	if err := store.Recover(context.Background(), recoveryResolver{
		accepted: map[string]bool{objectKeyString(retried.Key): true}, acceptedErr: errors.New("authority unavailable"),
	}); err != nil {
		t.Fatal(err)
	}
	if ref, found := resolvedInput(t, store); !found || ref != failed.Key {
		t.Fatalf("index after a failed check = %#v, %t; want it left", ref, found)
	}
}

// A group member keeps no order of its own for the input copies it stores of another Builder's
// orders: an index naming such a copy is not warned about, as long as the copy is held as a member
// (or the chain accepted that version); a check that fails warns as before and changes nothing.
func TestRecoverSkipsInputIndexOfAMemberCopy(t *testing.T) {
	var logs bytes.Buffer
	store, _, _ := newTestStore(t, testStoreConfig())
	store.log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	body := []byte("abcdefgh")
	input := prepareObject(t, store, testHeader(body), body)
	if _, err := store.MarkReady(context.Background(), input.Key); err != nil {
		t.Fatal(err)
	}
	if err := store.Recover(context.Background(), recoveryResolver{held: map[string]bool{objectKeyString(input.Key): true}}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "task input index names a copy held as a group member") {
		t.Fatalf("member copy index check logged: %s", logs.String())
	}
	if ref, found := resolvedInput(t, store); !found || ref != input.Key {
		t.Fatalf("member copy index = %#v, %t; want it left", ref, found)
	}

	logs.Reset()
	if err := store.Recover(context.Background(), recoveryResolver{heldErr: errors.New("authority unavailable")}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "task input index names a version without an accepted order") {
		t.Fatalf("failed member check did not warn: %s", logs.String())
	}
	if ref, found := resolvedInput(t, store); !found || ref != input.Key {
		t.Fatalf("index after a failed member check = %#v, %t; want it left", ref, found)
	}
}

// fakeMemberCopies answers HeldAsMember from a fixed set of keys.
type fakeMemberCopies struct {
	held  map[string]bool
	err   error
	calls int
}

func (f *fakeMemberCopies) HeldAsMember(_ context.Context, key ObjectKey) (bool, error) {
	f.calls++
	return f.held[objectKeyString(key)], f.err
}

// Through the recovery policy: a copy the member stream holds, or one whose member stream is
// pruned but whose version the chain accepted, is not warned about; an index naming a version
// whose order never reached the chain still is.
func TestRecoverWithPolicyWarnsOnlyForAStaleIndex(t *testing.T) {
	var logs bytes.Buffer
	store, _, _ := newTestStore(t, testStoreConfig())
	store.log = slog.New(slog.NewTextHandler(&logs, nil))
	body := []byte("abcdefgh")
	input := prepareObject(t, store, testHeader(body), body)
	if _, err := store.MarkReady(context.Background(), input.Key); err != nil {
		t.Fatal(err)
	}
	authority := &fakeAuthority{height: 100, taskErr: chaincli.ErrNotFound}
	policy, err := NewRecoveryPolicy(authority, &fakeCleanup{err: chaincli.ErrNotFound}, nil, recoveryOrderState{})
	if err != nil {
		t.Fatal(err)
	}
	members := &fakeMemberCopies{held: map[string]bool{}}
	policy.SetMemberCopies(members)
	recoverLogs := func() string {
		t.Helper()
		logs.Reset()
		if err := store.Recover(context.Background(), policy); err != nil {
			t.Fatal(err)
		}
		if ref, found := resolvedInput(t, store); !found || ref != input.Key {
			t.Fatalf("index = %#v, %t; want it left", ref, found)
		}
		return logs.String()
	}

	// The member stream holds the copy.
	members.held[objectKeyString(input.Key)] = true
	if got := recoverLogs(); strings.Contains(got, "level=WARN") {
		t.Fatalf("held member copy warned: %s", got)
	}

	// The member stream is pruned; the chain accepted this version.
	delete(members.held, objectKeyString(input.Key))
	authority.taskErr = nil
	authority.task = chaincli.OnChainTask{SessionID: testSessionID, TaskID: testTaskID, Assignment: chaincli.TaskAssignmentState{
		AcceptedTaskHash: input.Key.TaskHash, AcceptedInputHash: input.Key.ContentHash,
	}}
	if got := recoverLogs(); strings.Contains(got, "level=WARN") {
		t.Fatalf("copy of the chain's accepted version warned: %s", got)
	}

	// The chain accepted another version, or does not know the task: a stale index, warned about.
	authority.task.Assignment.AcceptedTaskHash = strings.Repeat("6f", 32)
	if got := recoverLogs(); !strings.Contains(got, "task input index names a version without an accepted order") {
		t.Fatalf("index of a version the chain did not accept was not warned about: %s", got)
	}
	authority.task.Assignment.AcceptedTaskHash = input.Key.TaskHash
	authority.task.Assignment.AcceptedInputHash = strings.Repeat("7a", 32)
	if got := recoverLogs(); !strings.Contains(got, "task input index names a version without an accepted order") {
		t.Fatalf("index of another input than the chain's accepted one was not warned about: %s", got)
	}
	authority.taskErr = chaincli.ErrNotFound
	if got := recoverLogs(); !strings.Contains(got, "task input index names a version without an accepted order") {
		t.Fatalf("pre-chain index was not warned about: %s", got)
	}

	// A member stream that cannot be read warns, without asking the chain.
	members.err = errors.New("kv unavailable")
	authority.taskErr = nil
	authority.task.Assignment.AcceptedInputHash = input.Key.ContentHash
	if got := recoverLogs(); !strings.Contains(got, "task input index names a version without an accepted order") {
		t.Fatalf("failed member check was not warned about: %s", got)
	}

	// Without member copies wired (no order path), only the chain is asked.
	members.err = nil
	bare, err := NewRecoveryPolicy(authority, &fakeCleanup{err: chaincli.ErrNotFound}, nil, recoveryOrderState{})
	if err != nil {
		t.Fatal(err)
	}
	if held, err := bare.HeldAsMember(context.Background(), input.Key); err != nil || !held {
		t.Fatalf("chain-only HeldAsMember = %t, %v", held, err)
	}
	authority.taskErr = errors.New("node unavailable")
	if held, err := bare.HeldAsMember(context.Background(), input.Key); err == nil || held {
		t.Fatalf("HeldAsMember with the chain down = %t, %v", held, err)
	}
}
