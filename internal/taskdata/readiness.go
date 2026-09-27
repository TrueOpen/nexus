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

// ResultFinalizedObserver is told that a FinalizeTaskResult call completed a task's result (not on
// an exact replay). It runs on the Finalize caller's goroutine after the result is durable.
type ResultFinalizedObserver func(sessionID, taskID string)

// SetResultFinalizedObserver installs the observer. Call it before the service starts serving.
func (s *Service) SetResultFinalizedObserver(observer ResultFinalizedObserver) {
	s.resultFinalized = observer
}

// ResultReady reports this Builder's local data-ready for one Worker result: the OUTPUT is READY,
// was finalized with exactly this receipt, and both Worker bundles the receipt commits to are READY.
// The answer is derived from storage and needs no recovery of its own after a restart. With only
// one bundle finalized the result stays not ready, so no Verifier is invited to fetch it.
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
	// The receipt hash covers output_hash and the evidence commitments, so comparing it alone binds
	// the receipt; the bundles are then looked up by its commitments.
	receipt := *metadata.Receipt
	digest, err := receiptDigest(receipt)
	if err != nil {
		return false, err
	}
	if hex.EncodeToString(digest[:]) != q.InferReceiptHash || len(receipt.EvidenceCommitments) == 0 {
		return false, nil
	}
	for _, commitment := range receipt.EvidenceCommitments {
		bundle, err := s.store.Metadata(ctx, ObjectRef{
			TaskHash: q.TaskHash, SessionID: q.SessionID, TaskID: q.TaskID,
			Kind: ObjectKindEvidenceManifest, ContentHash: commitment.HashOrRoot,
			EvidenceProducerKind: EvidenceProducerWorker, VerifyRound: 1,
			ProducerOperator: receipt.WorkerOperatorAddress, EvidenceKind: EvidenceKind(commitment.Kind),
		})
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if bundle.State != StateReady || bundle.RetentionStatus == RetentionDeleted {
			return false, nil
		}
	}
	return true, nil
}
