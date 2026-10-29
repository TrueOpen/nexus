package chaincli

import (
	"fmt"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/nodecontract"
)

// recordDispatchBatchKind is the batch_kind of MsgRecordDispatch in the batch result digest.
const recordDispatchBatchKind = "DISPATCH_RECORD"

// Every BatchItemResultV1 of a MsgRecordDispatch echoes the entry's own key as object_id: the
// dispatch_record_entry_digest of a dispatch entry, the takeover_entry_digest of a takeover entry.
// Checking each object_id against the entry sent at that index, and batch_digest against the
// results, keeps a misaligned result from being attributed to the wrong entry.

// DispatchEntryObjectID is the dispatch_record_entry_digest of a dispatch entry: chain, task,
// the record's signing digest and the winner accept's signing digest.
func DispatchEntryObjectID(chainID string, entry *taskv1.DispatchEntryV1) ([32]byte, error) {
	ticket := entry.GetWinnerTicket()
	taskID, err := hash32Array("task_id", ticket.GetTaskId())
	if err != nil {
		return [32]byte{}, err
	}
	taskHash, err := hash32Array("task_hash", ticket.GetTaskHash())
	if err != nil {
		return [32]byte{}, err
	}
	recordHash, err := messageSigningDigest("task.v1.DispatchRecordV1", entry.GetRecord())
	if err != nil {
		return [32]byte{}, err
	}
	acceptDigest, err := messageSigningDigest("task.v1.DispatchAcceptV1", entry.GetAccept())
	if err != nil {
		return [32]byte{}, err
	}
	return dispatch.DispatchEntryDigest(chainID, taskID, taskHash, recordHash, acceptDigest), nil
}

// TakeoverEntryObjectID is the takeover_entry_digest of a takeover entry submitted by candidate
// while the session's bound_change_height is boundChangeHeight.
func TakeoverEntryObjectID(chainID, candidate string, entry *taskv1.TakeoverEntryV1, boundChangeHeight uint64) ([32]byte, error) {
	order := entry.GetSignedOrder().GetOrder()
	sessionID, err := hash32Array("session_id", order.GetSessionId())
	if err != nil {
		return [32]byte{}, err
	}
	taskHash, err := nodecontract.TaskOrderHashV3(order)
	if err != nil {
		return [32]byte{}, fmt.Errorf("takeover entry task_hash: %w", err)
	}
	return dispatch.TakeoverEntryDigest(chainID, sessionID, order.GetOrderSequence(), taskHash, candidate, boundChangeHeight)
}

// RecordDispatchBatchDigest is the batch_digest the chain returns for MsgRecordDispatch results:
// chain, batch kind, item count and every (object_id, status) in item order.
func RecordDispatchBatchDigest(chainID string, results []*taskv1.BatchItemResultV1) [32]byte {
	return batchResultDigest(chainID, recordDispatchBatchKind, results)
}

func batchResultDigest(chainID, kind string, results []*taskv1.BatchItemResultV1) [32]byte {
	items := make([][]byte, 0, len(results)+1)
	items = append(items, dispatch.Uint32(uint32(len(results))))
	for _, r := range results {
		items = append(items, dispatch.FieldFrame(r.GetObjectId(), dispatch.Uint32(uint32(r.GetStatus()))))
	}
	return dispatch.HashFields("TRUEOPEN_BATCH_RESULT_V1", []byte(chainID), []byte(kind),
		dispatch.Uint32(uint32(len(results))), dispatch.FieldFrame(items...))
}

func messageSigningDigest(name string, m proto.Message) ([32]byte, error) {
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		return [32]byte{}, fmt.Errorf("encode %s: %w", name, err)
	}
	digest, err := dispatch.SigningDigest(name, raw)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%s signing digest: %w", name, err)
	}
	return digest, nil
}

func hash32Array(field string, value []byte) ([32]byte, error) {
	var out [32]byte
	if err := checkHash32(field, value); err != nil {
		return out, err
	}
	copy(out[:], value)
	return out, nil
}
