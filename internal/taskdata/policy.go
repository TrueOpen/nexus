package taskdata

import (
	"context"
	"errors"
	"fmt"

	"github.com/TrueOpen/nexus/internal/chaincli"
)

type OrderRecoveryState interface {
	HasAcceptedOrder(context.Context, ObjectKey) (bool, error)
	HasTerminatedOrder(context.Context, ObjectKey) (bool, error)
}

// RecoveryPolicy rechecks current Task Chain facts before promoting or
// deleting durable objects after a restart.
type RecoveryPolicy struct {
	authorizer *Authorizer
	authority  Authority
	orders     OrderRecoveryState
}

func NewRecoveryPolicy(authority Authority, authorizer *Authorizer, orders OrderRecoveryState) (*RecoveryPolicy, error) {
	if authority == nil || orders == nil {
		return nil, fmt.Errorf("%w: recovery policy dependencies", ErrMalformed)
	}
	return &RecoveryPolicy{authorizer: authorizer, authority: authority, orders: orders}, nil
}

func (p *RecoveryPolicy) HasAcceptedOrder(ctx context.Context, key ObjectKey) (bool, error) {
	return p.orders.HasAcceptedOrder(ctx, key)
}

func (p *RecoveryPolicy) RevalidatePrepared(ctx context.Context, metadata Metadata) (bool, error) {
	if metadata.State != StatePrepared || metadata.Key.Kind == ObjectKindInput || !canonicalText(metadata.Uploader) {
		if metadata.State == StateQuarantined && metadata.Key.Kind != ObjectKindInput && canonicalText(metadata.Uploader) {
			// Quarantined records use the same authority checks on retry.
		} else {
			return false, fmt.Errorf("%w: prepared metadata", ErrUnauthorized)
		}
	}
	height, err := p.authority.LatestHeight(ctx)
	if err != nil || height == 0 {
		return false, fmt.Errorf("%w: latest height", ErrAuthorityUnavailable)
	}
	task, err := p.authority.QueryTask(ctx, chaincli.TaskKey{SessionID: metadata.Key.SessionID, TaskID: metadata.Key.TaskID})
	if err != nil || task.SessionID != metadata.Key.SessionID || task.TaskID != metadata.Key.TaskID {
		return false, fmt.Errorf("%w: current task", ErrAuthorityUnavailable)
	}
	permissions, err := permissionsFor(task, metadata.Uploader, height)
	if err != nil {
		return false, err
	}
	if !permissions.canUpload(metadata.Key, metadata.Uploader) {
		return false, fmt.Errorf("%w: prepared uploader role", ErrUnauthorized)
	}
	if metadata.Key.Kind == ObjectKindOutput {
		if p.authorizer == nil {
			return false, fmt.Errorf("%w: output verifier unavailable", ErrServiceKeyUnavailable)
		}
		header := UploadHeader{
			Key: metadata.Key, Uploader: metadata.Uploader, SizeBytes: metadata.SizeBytes,
			SemanticHash: metadata.SemanticHash, MediaType: metadata.MediaType,
			Receipt: metadata.Receipt, AcceptedReceiptHash: metadata.AcceptedReceiptHash,
		}
		if err := p.authorizer.verifyOutputReceipt(ctx, task, header); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (p *RecoveryPolicy) Retention(ctx context.Context, metadata Metadata, height uint64) (RetentionDecision, error) {
	if height == 0 {
		return RetentionDecision{}, fmt.Errorf("%w: retention height", ErrMalformed)
	}
	if _, err := validateObjectKey(metadata.Key); err != nil {
		return RetentionDecision{}, err
	}
	task, err := p.authority.QueryTask(ctx, chaincli.TaskKey{
		SessionID: metadata.Key.SessionID,
		TaskID:    metadata.Key.TaskID,
	})
	if err == nil {
		if task.SessionID != metadata.Key.SessionID || task.TaskID != metadata.Key.TaskID {
			return RetentionDecision{}, fmt.Errorf("%w: retention task identity", ErrAuthorityUnavailable)
		}
		cleanupHeight := task.Settlement.EvidenceCleanupHeight
		if cleanupHeight == 0 {
			// The task is not settled yet and the chain has no cleanup height: keep the
			// object's existing retention height (the lease signed in the storage
			// confirmation). Returning 0 would let the periodic sweep erase a signed
			// commitment (issue #66).
			return RetentionDecision{Status: RetentionActive, RetainUntilHeight: metadata.RetainUntilHeight}, nil
		}
		if height < cleanupHeight {
			return RetentionDecision{Status: RetentionRetainedForChallenge, RetainUntilHeight: cleanupHeight}, nil
		}
		return RetentionDecision{Status: RetentionEligibleForCleanup, RetainUntilHeight: cleanupHeight, Delete: true}, nil
	}
	if !errors.Is(err, chaincli.ErrNotFound) || metadata.Key.Kind != ObjectKindInput {
		return RetentionDecision{}, fmt.Errorf("%w: retention task query", ErrAuthorityUnavailable)
	}
	if metadata.RetainUntilHeight == 0 || height < metadata.RetainUntilHeight {
		return RetentionDecision{Status: RetentionActive}, nil
	}
	terminated, terminalErr := p.orders.HasTerminatedOrder(ctx, metadata.Key)
	if terminalErr != nil {
		return RetentionDecision{}, fmt.Errorf("%w: local order state", ErrAuthorityUnavailable)
	}
	if !terminated {
		return RetentionDecision{Status: RetentionActive}, nil
	}
	return RetentionDecision{
		Status: RetentionEligibleForCleanup, RetainUntilHeight: metadata.RetainUntilHeight, Delete: true,
	}, nil
}
