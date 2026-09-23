package taskdata

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/TrueOpen/nexus/internal/chaincli"
)

type OrderRecoveryState interface {
	HasAcceptedOrder(context.Context, ObjectKey) (bool, error)
	HasTerminatedOrder(context.Context, ObjectKey) (bool, error)
}

// CleanupAuthority reads the chain's evidence cleanup progress for a task.
type CleanupAuthority interface {
	QueryEvidenceCleanup(ctx context.Context, taskID string) (chaincli.EvidenceCleanupStatus, error)
}

// cleanupCacheLimit bounds the per-task cleanup cache. Clearing it only costs a repeated query.
const cleanupCacheLimit = 4096

// RecoveryPolicy rechecks current Task Chain facts before promoting or
// deleting durable objects after a restart.
type RecoveryPolicy struct {
	authorizer *Authorizer
	authority  Authority
	cleanup    CleanupAuthority
	orders     OrderRecoveryState

	// cleanupMu guards the cleanup query cache. A task whose cleanup has started stays
	// started, so it is cached until the cache is cleared; a task not scheduled yet is cached
	// only for the height it was read at, so one sweep asks once per task rather than once per
	// object.
	cleanupMu      sync.Mutex
	cleanupStarted map[string]struct{}
	cleanupPending map[string]uint64
}

func NewRecoveryPolicy(authority Authority, cleanup CleanupAuthority, authorizer *Authorizer, orders OrderRecoveryState) (*RecoveryPolicy, error) {
	if authority == nil || cleanup == nil || orders == nil {
		return nil, fmt.Errorf("%w: recovery policy dependencies", ErrMalformed)
	}
	return &RecoveryPolicy{
		authorizer: authorizer, authority: authority, cleanup: cleanup, orders: orders,
		cleanupStarted: map[string]struct{}{}, cleanupPending: map[string]uint64{},
	}, nil
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
	permissions := permissionsFor(task, metadata.Uploader, height)
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

// Retention decides how long an object is kept. For a task on chain the only signal is the
// chain's own evidence cleanup (06 §10): once the chain has started compacting the task
// (RUNNING or COMPACTED) the Builder deletes its copy; until then, or when the chain cannot be
// asked, the object is kept with its existing lease. The cleanup preconditions (task finality,
// no open round, max_evidence_retention_blocks) are not recomputed here.
//
// A task the chain does not know is only legitimate for an INPUT whose order never reached the
// chain; it follows the pre-chain lease and the local order termination.
func (p *RecoveryPolicy) Retention(ctx context.Context, metadata Metadata, height uint64) (RetentionDecision, error) {
	if height == 0 {
		return RetentionDecision{}, fmt.Errorf("%w: retention height", ErrMalformed)
	}
	if _, err := validateObjectKey(metadata.Key); err != nil {
		return RetentionDecision{}, err
	}
	started, err := p.taskCleanupStarted(ctx, metadata.Key.TaskID, height)
	if err == nil {
		if started {
			return RetentionDecision{Status: RetentionEligibleForCleanup, RetainUntilHeight: height, Delete: true}, nil
		}
		// Not scheduled: keep the object's existing retention height (the lease signed in the
		// storage confirmation). Returning 0 would let a later sweep erase a signed commitment.
		return RetentionDecision{Status: RetentionActive, RetainUntilHeight: metadata.RetainUntilHeight}, nil
	}
	if !errors.Is(err, chaincli.ErrNotFound) || metadata.Key.Kind != ObjectKindInput {
		return RetentionDecision{}, fmt.Errorf("%w: retention cleanup query", ErrAuthorityUnavailable)
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

// taskCleanupStarted asks the chain, through the cache, whether the task's evidence cleanup has
// started. Errors are returned uncached, so an outage is retried on the next sweep.
func (p *RecoveryPolicy) taskCleanupStarted(ctx context.Context, taskID string, height uint64) (bool, error) {
	p.cleanupMu.Lock()
	if _, ok := p.cleanupStarted[taskID]; ok {
		p.cleanupMu.Unlock()
		return true, nil
	}
	if readAt, ok := p.cleanupPending[taskID]; ok && readAt == height {
		p.cleanupMu.Unlock()
		return false, nil
	}
	p.cleanupMu.Unlock()

	status, err := p.cleanup.QueryEvidenceCleanup(ctx, taskID)
	if err != nil {
		return false, err
	}
	p.cleanupMu.Lock()
	defer p.cleanupMu.Unlock()
	if len(p.cleanupStarted)+len(p.cleanupPending) >= cleanupCacheLimit {
		p.cleanupStarted, p.cleanupPending = map[string]struct{}{}, map[string]uint64{}
	}
	if status.Started() {
		delete(p.cleanupPending, taskID)
		p.cleanupStarted[taskID] = struct{}{}
		return true, nil
	}
	p.cleanupPending[taskID] = height
	return false, nil
}
