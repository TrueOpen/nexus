package dispatchevidence

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
)

// ErrRosterNotFound means this Builder holds no rosters of the task as the chain recorded it.
var ErrRosterNotFound = errors.New("DATA_NOT_FOUND: no recorded dispatch of the task is held here")

// RecordReader reads the dispatch record the chain admitted for a session order.
type RecordReader interface {
	QueryDispatchRecordByOrder(ctx context.Context, sessionID string, orderSequence uint64) (*taskv1.DispatchRecordState, error)
}

// RosterFor returns the stored roster of round number when its recomputed roster_hash is want:
// only a roster the chain's record commits is ever handed out.
func (o *Order) RosterFor(chainID string, number uint32, want []byte) (*taskv1.DispatchRosterV1, bool) {
	round, ok := o.Round(number)
	if !ok {
		return nil, false
	}
	var msg taskv1.DispatchRosterV1
	if proto.Unmarshal(round.Roster, &msg) != nil || len(msg.GetTaskId()) != 32 || len(msg.GetCandidatePoolSnapshotId()) != 32 {
		return nil, false
	}
	members := make([]dispatch.RosterMember, len(msg.GetMembers()))
	for i, m := range msg.GetMembers() {
		members[i] = dispatch.RosterMember{Slot: m.GetSlot(), SlotVersion: m.GetSlotVersion(), OperatorAddress: m.GetOperatorAddress(), CandidateWeight: m.GetCandidateWeight()}
	}
	hash, err := dispatch.RosterDigest(chainID, [32]byte(msg.GetTaskId()), msg.GetReferenceHeight(), [32]byte(msg.GetCandidatePoolSnapshotId()), members)
	if err != nil || !bytes.Equal(hash[:], want) {
		return nil, false
	}
	return &msg, true
}

// Rosters answers GetDispatchRoster from the evidence, for tasks the chain recorded.
type Rosters struct {
	ChainID  string
	Evidence *Store
	// Chain reads the record the chain holds; the stored rosters are matched against it, so the
	// answer never depends on whether the evidence was marked recorded.
	Chain RecordReader
	// Root finds an issued handraise root by its handraise_root_digest (handraise.Registry); the
	// roots retained evidence binds are never pruned. A group member's copy carries its roots.
	Root func(digest [32]byte) (*taskv1.SignedHandraiseRootV1, bool, error)
}

// DispatchRoster returns every round of the recorded task (session and task ids in hex) with the
// stored roster whose hash the chain's record holds and the signed root that round binds, and the
// chain's dispatch_record_hash.
func (r Rosters) DispatchRoster(ctx context.Context, sessionID, taskID string) (*nexusv1.GetDispatchRosterResponse, error) {
	orders, err := r.Evidence.ByTask(taskID)
	if err != nil {
		return nil, err
	}
	var record *taskv1.DispatchRecordState
	for _, o := range orders {
		if o.SessionID != sessionID {
			continue
		}
		if record == nil {
			record, err = r.Chain.QueryDispatchRecordByOrder(ctx, o.SessionID, o.Sequence)
			if errors.Is(err, chaincli.ErrNotFound) {
				return nil, ErrRosterNotFound
			}
			if err != nil {
				return nil, fmt.Errorf("chain record of the task: %w", err)
			}
			if hex.EncodeToString(record.GetTaskId()) != taskID {
				return nil, ErrRosterNotFound
			}
		}
		resp, ok, err := r.answer(o, record)
		if err != nil || ok {
			return resp, err
		}
	}
	return nil, ErrRosterNotFound
}

// answer builds the response from o when every round of the chain's record has its roster and
// root in o.
func (r Rosters) answer(o *Order, record *taskv1.DispatchRecordState) (*nexusv1.GetDispatchRosterResponse, bool, error) {
	resp := &nexusv1.GetDispatchRosterResponse{DispatchRecordHash: record.GetDispatchRecordHash()}
	for _, recorded := range record.GetRounds() {
		roster, ok := o.RosterFor(r.ChainID, recorded.GetDispatchRound(), recorded.GetRosterHash())
		stored, _ := o.Round(recorded.GetDispatchRound())
		if !ok || !bytes.Equal(stored.RootDigest, recorded.GetHandraiseRootDigest()) || len(stored.RootDigest) != 32 {
			return nil, false, nil
		}
		root, found, err := r.root(stored)
		if err != nil {
			return nil, false, fmt.Errorf("handraise root of round %d: %w", stored.Number, err)
		}
		if !found {
			return nil, false, fmt.Errorf("handraise root %x of round %d is missing", stored.RootDigest, stored.Number)
		}
		resp.Rounds = append(resp.Rounds, &nexusv1.DispatchRosterRoundV1{DispatchRound: stored.Number, Roster: roster, HandraiseRoot: root})
	}
	return resp, len(resp.Rounds) > 0, nil
}

// root is the signed root a round binds: the synced one in a member's copy, otherwise the one
// this Builder issued.
func (r Rosters) root(round *Round) (*taskv1.SignedHandraiseRootV1, bool, error) {
	if len(round.SignedRoot) == 0 {
		return r.Root([32]byte(round.RootDigest))
	}
	var root taskv1.SignedHandraiseRootV1
	if err := proto.Unmarshal(round.SignedRoot, &root); err != nil {
		return nil, false, fmt.Errorf("synced handraise root: %w", err)
	}
	return &root, true, nil
}
