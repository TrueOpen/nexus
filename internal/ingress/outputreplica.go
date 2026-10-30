package ingress

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/internal/attempt"
	"github.com/TrueOpen/nexus/internal/taskdata"
	"github.com/TrueOpen/nexus/internal/types"
)

// MemberReplicas holds what the dispatching Builders synced to this Builder as a member of their
// orders' Task Builders groups (buildersync.Receiver).
type MemberReplicas interface {
	// Replica returns the synced attempt of a task (internal hex spelling of the ids): RECORDED
	// with the dispatching Builder's signed header once the chain admitted the order, PENDING
	// before; false when nothing of the task was synced here.
	Replica(sessionID, taskID string) (attempt.Attempt, bool)
	// Watch returns a channel that receives a value whenever the task's replica may have changed,
	// and the function that stops the watch.
	Watch(taskID string) (<-chan struct{}, func())
}

// WithMemberReplicas serves SubscribeOutput / ResumeOutput and the user's GetDispatchRoster for
// tasks this Builder holds as a group member. chain confirms that the chain recorded a task with
// this Builder in its group; a replica that has not caught up with such a task is waited for at
// most wait (ingress.output_replica_wait).
func WithMemberReplicas(replicas MemberReplicas, chain TaskBuilders, wait time.Duration) Option {
	return func(s *Server) { s.memberReplicas, s.taskBuilders, s.replicaWait = replicas, chain, wait }
}

func withMemberReplicas(replicas MemberReplicas, chain TaskBuilders, wait time.Duration) serviceOption {
	return func(s *service) {
		s.memberReplicas, s.taskRecords, s.replicaWait = replicas, newTaskRecords(chain), wait
	}
}

var (
	errSessionUnbound = connect.NewError(connect.CodeFailedPrecondition,
		errors.New("NEXUS_INGRESS_SESSION_UNBOUND: this Builder is not the task's dispatching Builder and the chain has not recorded the task's dispatch yet"))
	errReplicaNotReady = connect.NewError(connect.CodeUnavailable,
		errors.New("NEXUS_OUTPUT_REPLICA_NOT_READY: the chain recorded the task's dispatch but this Builder's replica has not caught up; retry, or fetch the output with FetchTaskData(OUTPUT)"))
	errNotReplicaOwner = connect.NewError(connect.CodePermissionDenied,
		errors.New("NEXUS_OUTPUT_UNAUTHORIZED: only the order user may read this task"))
)

// serveReplica serves a task's output from the replica this Builder holds as a member of its
// Task Builders group, when it holds no attempt of the task itself. Only the order user is
// answered. A member serves a task once the chain recorded it with the member in its group: a
// replica that has not caught up is waited for (memberReplica), and the request must name the
// recorded winner's ticket (NEXUS_INGRESS_ATTEMPT_STALE otherwise). It then sends the dispatching
// Builder's RECORDED header first, the stored frames after the cursor, then the frames as they are
// synced in, until the Fin. Before the record a member does not serve the task
// (NEXUS_INGRESS_SESSION_UNBOUND). handled is false when the task is not this member's to serve.
func (s *service) serveReplica(ctx context.Context, ids taskIDs, requester string, resumeAfter *uint64, ticket []byte,
	send func(*nexusv1.SubscribeOutputResponse) error) (bool, error) {
	if s.memberReplicas == nil {
		return false, nil
	}
	rt := s.outputStream
	if _, own := rt.attempts.Current(ids.task); own {
		return false, nil
	}
	replica, handled, err := s.memberReplica(ctx, ids, requester, func(a attempt.Attempt) bool { return a.Status == attempt.Recorded })
	if !handled || err != nil {
		return handled, err
	}
	if ticket == nil || !bytes.Equal(ticket, replica.TicketHash[:]) {
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

// requireTaskOrReplicaOwner is requireTaskOwner, except that a task this Builder only holds, or
// will hold, as a group member of a task the chain recorded is the user's of the synced order.
func (s *service) requireTaskOrReplicaOwner(ctx context.Context, sessionID, taskID, requester string) error {
	err := s.requireTaskOwner(ctx, sessionID, taskID, requester)
	if connect.CodeOf(err) != connect.CodeNotFound || s.memberReplicas == nil {
		return err
	}
	// Once the chain recorded the task, the synced rounds name its user; a replica not recorded yet
	// leaves the task unknown here, as before.
	ids := taskIDs{session: sessionID, task: taskID}
	_, handled, replicaErr := s.memberReplica(ctx, ids, requester, func(a attempt.Attempt) bool { return a.User != "" })
	if !handled || errors.Is(replicaErr, errSessionUnbound) {
		return err
	}
	return replicaErr
}

// memberReplica returns the replica of a task this Builder holds as a member of its Task Builders
// group, once the chain recorded the task and ready accepts the replica, checking that requester
// is the order user. handled is false when the task is not this member's: nothing is synced here,
// this Builder knows the task itself, or the chain has not recorded it with this Builder in the
// group.
//
// A held replica names its user, which is checked first; a RECORDED one is answered at once.
// Otherwise the chain decides (cached): a task it has not recorded with this Builder in the group
// is NEXUS_INGRESS_SESSION_UNBOUND for a held replica; for a recorded one the replica is waited for
// at most replicaWait, and then the answer is NEXUS_OUTPUT_REPLICA_NOT_READY, so the SDK retries or
// falls back to FetchTaskData(OUTPUT). The chain's records are public, so answering before the
// user can be checked tells no one anything new.
func (s *service) memberReplica(ctx context.Context, ids taskIDs, requester string, ready func(attempt.Attempt) bool) (attempt.Attempt, bool, error) {
	replica, held := s.memberReplicas.Replica(ids.session, ids.task)
	if held {
		if replica.User == "" || replica.User != requester {
			return attempt.Attempt{}, true, errNotReplicaOwner
		}
		if replica.Status == attempt.Recorded {
			return replica, true, nil
		}
	} else if _, err := s.h.TaskOwner(ctx, ids.session, ids.task); !errors.Is(err, types.ErrTaskNotFound) {
		return attempt.Attempt{}, false, nil
	}
	recorded, member, err := s.taskRecords.member(ctx, ids.session, ids.task, s.auth.BuilderAddress)
	switch {
	case err != nil:
		return attempt.Attempt{}, true, connect.NewError(connect.CodeUnavailable, fmt.Errorf("read the task's record from the chain: %w", err))
	case !recorded || !member:
		if held {
			return attempt.Attempt{}, true, errSessionUnbound
		}
		return attempt.Attempt{}, false, nil
	}
	replica, err = s.awaitReplica(ctx, ids, ready)
	if err != nil {
		return attempt.Attempt{}, true, err
	}
	if replica.User == "" || replica.User != requester {
		return attempt.Attempt{}, true, errNotReplicaOwner
	}
	return replica, true, nil
}

// awaitReplica waits until the task's replica is held and ready accepts it: at most replicaWait,
// and at most half the time left to ctx's deadline, so the answer still reaches the caller.
func (s *service) awaitReplica(ctx context.Context, ids taskIDs, ready func(attempt.Attempt) bool) (attempt.Attempt, error) {
	changed, stop := s.memberReplicas.Watch(ids.task)
	defer stop()
	wait := s.replicaWait
	if deadline, ok := ctx.Deadline(); ok {
		wait = min(wait, time.Until(deadline)/2)
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		if replica, held := s.memberReplicas.Replica(ids.session, ids.task); held && ready(replica) {
			return replica, nil
		}
		select {
		case <-changed:
		case <-timer.C:
			return attempt.Attempt{}, errReplicaNotReady
		case <-ctx.Done():
			return attempt.Attempt{}, ctx.Err()
		}
	}
}
