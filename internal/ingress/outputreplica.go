package ingress

import (
	"bytes"
	"context"
	"errors"

	"connectrpc.com/connect"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/internal/attempt"
	"github.com/TrueOpen/nexus/internal/taskdata"
)

// MemberReplicas holds what the dispatching Builders synced to this Builder as a member of their
// orders' Task Builders groups (buildersync.Receiver).
type MemberReplicas interface {
	// Replica returns the synced attempt of a task (internal hex spelling of the ids): RECORDED
	// with the dispatching Builder's signed header once the chain admitted the order, PENDING
	// before; false when nothing of the task was synced here.
	Replica(sessionID, taskID string) (attempt.Attempt, bool)
}

// WithMemberReplicas serves SubscribeOutput / ResumeOutput and the user's GetDispatchRoster for
// tasks this Builder holds as a group member.
func WithMemberReplicas(replicas MemberReplicas) Option {
	return func(s *Server) { s.memberReplicas = replicas }
}

func withMemberReplicas(replicas MemberReplicas) serviceOption {
	return func(s *service) { s.memberReplicas = replicas }
}

var errSessionUnbound = connect.NewError(connect.CodeFailedPrecondition,
	errors.New("NEXUS_INGRESS_SESSION_UNBOUND: this Builder is not the task's dispatching Builder and the chain has not recorded the task's dispatch yet"))

// serveReplica serves a task's output from the replica this Builder holds as a member of its
// Task Builders group, when it holds no attempt of the task itself. Only the order user is
// answered. Before the chain recorded the order a member does not serve it
// (NEXUS_INGRESS_SESSION_UNBOUND); after, it serves the recorded winner's ticket, which the request must name
// (NEXUS_INGRESS_ATTEMPT_STALE otherwise): the dispatching Builder's RECORDED header first, the
// stored frames after the cursor, then the frames as they are synced in, until the Fin. handled
// is false when the task is not this member's to serve.
func (s *service) serveReplica(ctx context.Context, ids taskIDs, requester string, resumeAfter *uint64, ticket []byte,
	send func(*nexusv1.SubscribeOutputResponse) error) (bool, error) {
	if s.memberReplicas == nil {
		return false, nil
	}
	rt := s.outputStream
	if _, own := rt.attempts.Current(ids.task); own {
		return false, nil
	}
	replica, held := s.memberReplicas.Replica(ids.session, ids.task)
	if !held {
		return false, nil
	}
	// The user is checked first: no one else learns whether the order was recorded.
	switch {
	case replica.User == "" || replica.User != requester:
		return true, connect.NewError(connect.CodePermissionDenied, errors.New("NEXUS_OUTPUT_UNAUTHORIZED: only the order user may read this task"))
	case replica.Status != attempt.Recorded:
		return true, errSessionUnbound
	case ticket == nil || !bytes.Equal(ticket, replica.TicketHash[:]):
		return true, errAttemptStale
	}
	key := taskdata.ObjectKey{SessionID: ids.session, TaskID: ids.task, Kind: taskdata.ObjectKindOutput}
	sub := rt.dispatcher.Subscribe(key)
	defer sub.Close()
	d := &outputDelivery{service: s, key: key, attempt: replica, lastSent: resumeAfter, send: send}
	if err := d.sendHeader(); err != nil {
		return true, err
	}
	if err := d.pump(ctx); err != nil {
		return true, err
	}
	for !d.finSent {
		select {
		case frame, ok := <-sub.Frames:
			if !ok {
				if sub.Overflowed() {
					return true, connect.NewError(connect.CodeResourceExhausted,
						errors.New("NEXUS_OUTPUT_SUBSCRIBER_OVERFLOW: subscriber buffer full, re-subscribe with resume_after_seq"))
				}
				return true, connect.NewError(connect.CodeUnavailable, errors.New("NEXUS_OUTPUT_STREAM_STOPPED: builder is shutting down"))
			}
			var err error
			if d.inOrder(frame) {
				err = d.offer(frame)
			} else {
				err = d.pump(ctx)
			}
			if err != nil {
				return true, err
			}
		case <-ctx.Done():
			return true, nil
		}
	}
	return true, nil
}

// requireTaskOrReplicaOwner is requireTaskOwner, except that a task this Builder only holds as a
// group member, recorded on chain, is the user's of the synced order.
func (s *service) requireTaskOrReplicaOwner(ctx context.Context, sessionID, taskID, requester string) error {
	err := s.requireTaskOwner(ctx, sessionID, taskID, requester)
	if connect.CodeOf(err) != connect.CodeNotFound || s.memberReplicas == nil {
		return err
	}
	replica, held := s.memberReplicas.Replica(sessionID, taskID)
	if !held || replica.Status != attempt.Recorded {
		return err
	}
	if replica.User == "" || replica.User != requester {
		return connect.NewError(connect.CodePermissionDenied, errors.New("NEXUS_OUTPUT_UNAUTHORIZED: only the order user may read this task"))
	}
	return nil
}
