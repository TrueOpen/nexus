package dispatchevidence

import (
	"errors"
	"fmt"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

// ErrRosterNotFound means this Builder holds no evidence of the task as recorded.
var ErrRosterNotFound = errors.New("DATA_NOT_FOUND: no recorded dispatch of the task is held here")

// Rosters answers GetDispatchRoster from the evidence of recorded tasks.
type Rosters struct {
	Evidence *Store
	// Root finds an issued handraise root by its handraise_root_digest (handraise.Registry); the
	// roots retained evidence binds are never pruned.
	Root func(digest [32]byte) (*taskv1.SignedHandraiseRootV1, bool, error)
}

// DispatchRoster returns every round of the recorded task (session and task ids in hex) with its
// roster and the signed root it binds, and the dispatch_record_hash of the record.
func (r Rosters) DispatchRoster(sessionID, taskID string) (*nexusv1.GetDispatchRosterResponse, error) {
	orders, err := r.Evidence.ByTask(taskID)
	if err != nil {
		return nil, err
	}
	for _, o := range orders {
		if !o.Recorded || o.SessionID != sessionID {
			continue
		}
		recordHash, err := dispatch.SigningDigest("task.v1.DispatchRecordV1", o.Record)
		if err != nil {
			return nil, fmt.Errorf("stored record: %w", err)
		}
		resp := &nexusv1.GetDispatchRosterResponse{DispatchRecordHash: recordHash[:]}
		for _, round := range o.Rounds {
			roster := &taskv1.DispatchRosterV1{}
			if err := proto.Unmarshal(round.Roster, roster); err != nil {
				return nil, fmt.Errorf("stored roster of round %d: %w", round.Number, err)
			}
			if len(round.RootDigest) != 32 {
				return nil, fmt.Errorf("round %d binds a malformed root digest", round.Number)
			}
			root, found, err := r.Root([32]byte(round.RootDigest))
			if err != nil {
				return nil, fmt.Errorf("handraise root of round %d: %w", round.Number, err)
			}
			if !found {
				return nil, fmt.Errorf("handraise root %x of round %d is missing", round.RootDigest, round.Number)
			}
			resp.Rounds = append(resp.Rounds, &nexusv1.DispatchRosterRoundV1{DispatchRound: round.Number, Roster: roster, HandraiseRoot: root})
		}
		return resp, nil
	}
	return nil, ErrRosterNotFound
}
