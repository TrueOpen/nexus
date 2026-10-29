package buildersync

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/TrueOpen/nexus/internal/attempt"
	"github.com/TrueOpen/nexus/internal/kv"
)

// memberStream is how far this Builder, as a group member, applied the sync stream of one order
// from its dispatching Builder.
type memberStream struct {
	Sender    string `json:"sender"`
	SessionID string `json:"session_id"`
	Sequence  uint64 `json:"sequence"`
	TaskID    string `json:"task_id,omitempty"`
	// User is the order's user_address as the rounds name it; the synced order must agree.
	User           string `json:"user,omitempty"`
	BuilderSetID   string `json:"builder_set_id"`
	BuilderSetHash []byte `json:"builder_set_hash"`
	// Applied is the last item sequence applied.
	Applied uint64 `json:"applied"`
	// Inputs follows each order version's input by task_hash.
	Inputs map[string]*memberInput `json:"inputs,omitempty"`
	// Recorded is set once the order item was applied: the chain admitted the order's dispatch
	// entry with Winner, at RecordedHeight.
	Recorded       bool          `json:"recorded,omitempty"`
	RecordedHeight uint64        `json:"recorded_height,omitempty"`
	Winner         *memberWinner `json:"winner,omitempty"`
	// ExpireHeight is the last height the stream is kept at: the retention of its evidence.
	ExpireHeight uint64 `json:"expire_height"`
}

// memberInput is an order version's input: the pieces received so far, until it is whole and
// stored with the task data.
type memberInput struct {
	InputHash []byte   `json:"input_hash"`
	Size      uint64   `json:"size"`
	Received  uint64   `json:"received"`
	Offsets   []uint64 `json:"offsets,omitempty"`
	Stored    bool     `json:"stored,omitempty"`
	// Skipped is set for an input over what this Builder stores: its pieces are taken and dropped.
	Skipped bool `json:"skipped,omitempty"`
}

// memberWinner is the recorded winner of a synced order: what a member's output replica and
// resumed subscriptions go by.
type memberWinner struct {
	TaskHash     string `json:"task_hash"`
	TicketHash   []byte `json:"ticket_hash"`
	Ticket       []byte `json:"ticket"`
	Accept       []byte `json:"accept"`
	AcceptDigest []byte `json:"accept_digest"`
	Worker       string `json:"worker"`
	// Header is the dispatching Builder's DispatchResultHeaderV1 at RECORDED, as synced.
	Header []byte `json:"header"`
	// User is the order's user_address: the one subscriber of the task's output.
	User string `json:"user"`
}

// Keys of kv.NSBuilderSyncMember:
//
//	stream/<sender>/<stream key>               the memberStream as JSON
//	task/<task id>                             member key of the task's latest synced order
//	input/<member key>/<task hash>/<offset>    an input piece not assembled yet
const (
	memberStreamPrefix = "stream/"
	memberTaskPrefix   = "task/"
	memberInputPrefix  = "input/"
)

func memberKey(sender, sessionID string, sequence uint64) string {
	return sender + "/" + streamKey(sessionID, sequence)
}

func (m *memberStream) key() string { return memberKey(m.Sender, m.SessionID, m.Sequence) }

func inputPieceKey(member, taskHash string, offset uint64) string {
	return fmt.Sprintf("%s%s/%s/%020d", memberInputPrefix, member, taskHash, offset)
}

func (m *memberStream) clone() *memberStream {
	next := *m
	next.BuilderSetHash = append([]byte(nil), m.BuilderSetHash...)
	next.Inputs = make(map[string]*memberInput, len(m.Inputs))
	for k, v := range m.Inputs {
		in := *v
		in.Offsets = append([]uint64(nil), v.Offsets...)
		next.Inputs[k] = &in
	}
	if m.Winner != nil {
		w := *m.Winner
		next.Winner = &w
	}
	return &next
}

func memberOp(m *memberStream) (kv.WriteOp, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return kv.WriteOp{}, fmt.Errorf("encode member sync stream: %w", err)
	}
	return kv.WriteOp{NS: kv.NSBuilderSyncMember, Key: memberStreamPrefix + m.key(), Val: raw}, nil
}

func (r *Receiver) loadMember(key string) (*memberStream, bool, error) {
	raw, found, err := r.cfg.Store.GetWithError(kv.NSBuilderSyncMember, memberStreamPrefix+key)
	if err != nil || !found {
		return nil, false, err
	}
	var m memberStream
	if err := json.Unmarshal(raw, &m); err != nil || m.key() != key {
		return nil, false, fmt.Errorf("member sync stream %q is malformed", key)
	}
	return &m, true, nil
}

// Replica returns the synced attempt of a task this Builder holds as a member of its Task
// Builders group (session and task ids in hex): RECORDED with the dispatching Builder's signed
// header once the chain admitted the order, PENDING (no header) while only its dispatch is
// synced. held is false when no dispatching Builder synced the task here.
func (r *Receiver) Replica(sessionID, taskID string) (attempt.Attempt, bool) {
	m, found := r.memberOfTask(sessionID, taskID)
	if !found {
		return attempt.Attempt{}, false
	}
	a := attempt.Attempt{SessionID: m.SessionID, Sequence: m.Sequence, TaskID: taskID, Status: attempt.Pending, User: m.User}
	if !m.Recorded || m.Winner == nil {
		return a, true
	}
	w := m.Winner
	a.Status, a.TaskHash, a.Worker, a.User = attempt.Recorded, w.TaskHash, w.Worker, w.User
	a.Ticket, a.Accept, a.Header = w.Ticket, w.Accept, w.Header
	copy(a.TicketHash[:], w.TicketHash)
	copy(a.AcceptDigest[:], w.AcceptDigest)
	return a, true
}

// memberOfTask finds the member stream of a task through the task index.
func (r *Receiver) memberOfTask(sessionID, taskID string) (*memberStream, bool) {
	key, found, err := r.cfg.Store.GetWithError(kv.NSBuilderSyncMember, memberTaskPrefix+taskID)
	if err != nil || !found {
		return nil, false
	}
	m, ok, err := r.loadMember(string(key))
	if err != nil || !ok || m.SessionID != sessionID {
		return nil, false
	}
	return m, true
}

// prune drops the member streams whose retention ended before head, with their input pieces and
// task index entries. The evidence, the input and the output replica follow their own retention.
func (r *Receiver) prune(head uint64) {
	var expired []*memberStream
	err := r.cfg.Store.Scan(kv.NSBuilderSyncMember, func(key string, val []byte) bool {
		if !strings.HasPrefix(key, memberStreamPrefix) {
			return key < memberStreamPrefix
		}
		var m memberStream
		if json.Unmarshal(val, &m) == nil && m.ExpireHeight != 0 && m.ExpireHeight < head {
			expired = append(expired, &m)
		}
		return true
	})
	if err != nil {
		r.log.Warn("member sync streams not scanned for pruning", "err", err)
		return
	}
	for _, m := range expired {
		unlock := r.lock(m.key())
		ops := []kv.WriteOp{{NS: kv.NSBuilderSyncMember, Key: memberStreamPrefix + m.key(), Delete: true}}
		for taskHash, in := range m.Inputs {
			for _, offset := range in.Offsets {
				ops = append(ops, kv.WriteOp{NS: kv.NSBuilderSyncMember, Key: inputPieceKey(m.key(), taskHash, offset), Delete: true})
			}
		}
		if m.TaskID != "" {
			if key, found, _ := r.cfg.Store.GetWithError(kv.NSBuilderSyncMember, memberTaskPrefix+m.TaskID); found && string(key) == m.key() {
				ops = append(ops, kv.WriteOp{NS: kv.NSBuilderSyncMember, Key: memberTaskPrefix + m.TaskID, Delete: true})
			}
		}
		if err := r.cfg.Store.WriteBatch(ops...); err != nil {
			r.log.Warn("expired member sync stream not deleted", "order", m.key(), "err", err)
		}
		unlock()
	}
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }
