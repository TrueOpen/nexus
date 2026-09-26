package taskdata

import (
	"context"
	"encoding/hex"
	"errors"
)

// ResultReadyQuery names one Worker result on this Builder: the OUTPUT object (by the accepted
// task_hash and the receipt's output_hash) and the receipt it must have been finalized with.
// All hashes are canonical lowercase hex.
type ResultReadyQuery struct {
	TaskHash         string
	SessionID        string
	TaskID           string
	OutputHash       string
	InferReceiptHash string
}

// ResultFinalizedObserver is told that FinalizeTaskResult first committed a task's result (not on
// an exact replay). It runs on the Finalize caller's goroutine after the result is durable.
type ResultFinalizedObserver func(sessionID, taskID string)

// SetResultFinalizedObserver installs the observer. Call it before the service starts serving.
func (s *Service) SetResultFinalizedObserver(observer ResultFinalizedObserver) {
	s.resultFinalized = observer
}

// ResultReady reports this Builder's local data-ready for one Worker result (04 §326): the OUTPUT
// is READY and was finalized with exactly this receipt. commitReady switches the OUTPUT last, so a
// READY OUTPUT means the manifest and artifacts of the same Finalize are READY too; the answer is
// derived from storage and needs no recovery of its own after a restart.
func (s *Service) ResultReady(ctx context.Context, q ResultReadyQuery) (bool, error) {
	metadata, err := s.store.Metadata(ctx, ObjectRef{
		TaskHash: q.TaskHash, SessionID: q.SessionID, TaskID: q.TaskID,
		Kind: ObjectKindOutput, ContentHash: q.OutputHash,
	})
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if metadata.State != StateReady || metadata.RetentionStatus == RetentionDeleted || metadata.Receipt == nil {
		return false, nil
	}
	// The receipt hash covers output_hash and the evidence commitments, so comparing it alone is
	// the whole binding.
	digest, err := receiptDigest(*metadata.Receipt)
	if err != nil {
		return false, err
	}
	return hex.EncodeToString(digest[:]) == q.InferReceiptHash, nil
}
