package taskdata

import (
	"context"
	"crypto/sha256"
	"fmt"
)

// OpenReplicaStream opens (or resumes) the OUTPUT stream of key as a copy of the stream a
// recorded winner uploaded to another Builder: a member of the task's Task Builders group writes
// the frames the dispatching Builder synced to it, already checked against the winner's
// signature. The stream is bound to the winner's dispatch ticket like an upload under that
// ticket's header, so replays and FetchTaskData read it as the task's OUTPUT.
func (s *Store) OpenReplicaStream(ctx context.Context, key ObjectKey, worker string, cfg OutputStreamConfig, ticket []byte) (*OutputStream, OutputStreamProgress, error) {
	if len(ticket) != sha256.Size {
		return nil, OutputStreamProgress{}, fmt.Errorf("%w: replica dispatch ticket", ErrMalformed)
	}
	return s.openOutputStream(ctx, key, worker, cfg, &OutputStreamHeaderRecord{DispatchTicketHash: append([]byte(nil), ticket...)})
}

// OutputFramesUpTo is OutputFrames reading at most maxBytes of chunk text (at least one chunk) for
// a group member's sync batch; the Fin is appended only when every chunk after afterSeq fits.
func (s *Store) OutputFramesUpTo(_ context.Context, key ObjectKey, afterSeq *uint64, maxBytes int) ([]OutputFrame, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("%w: maxBytes must be positive", ErrRangeInvalid)
	}
	return s.outputFrames(key, afterSeq, maxBytes)
}
