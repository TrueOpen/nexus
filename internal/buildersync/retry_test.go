package buildersync

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/attempt"
	"github.com/TrueOpen/nexus/internal/dispatchevidence"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/servicekey"
)

const outcomeTimeout = taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_TIMEOUT

// retried is a fixture order whose first version failed (its rank 0 ticket timed out, no rank
// left in round 0) and that the user re-signed: the same task_id under a new task_hash (a later
// earliest_submit_height and another input), dispatched by D as round 1 of the same epoch and
// binding generation, from rank 1, which the worker accepted.
type retried struct {
	f          *fixture
	failed     *dispatchevidence.Order // D's evidence of the failed first version
	taskHash   []byte
	input      []byte
	order      *taskv1.TaskOrderV3
	signed     []byte
	ticket     []byte
	hash       [32]byte
	accept     []byte
	acceptDig  [32]byte
	record     []byte
	evidence   *dispatchevidence.Order // D's evidence once the retry's winner accepted
	firstRound dispatchevidence.Round
}

func newRetried(e *env) *retried {
	t, f := e.t, e.fx
	r := &retried{f: f, input: []byte("the retried order's input")}
	timedOut := dispatchevidence.Attempt{Ticket: f.tickets[0], Hash: f.hashes[0][:], Rank: 0, Operator: f.rejecter.op, Sent: true, Outcome: outcomeTimeout}
	r.firstRound = dispatchevidence.Round{Number: 0, TaskHash: hex.EncodeToString(f.taskHash), RootDigest: f.rootDigest[:], Roster: f.roster,
		RosterHash: f.rosterHash[:], Attempts: []dispatchevidence.Attempt{timedOut}}
	firstRecordRound := &taskv1.DispatchRoundV1{DispatchRound: 0, HandraiseRootDigest: f.rootDigest[:], RosterHash: f.rosterHash[:], Attempts: []*taskv1.DispatchAttemptV1{
		{DispatchTicketHash: f.hashes[0][:], Rank: 0, Member: memberRef(f.rejecter.op, 1), Outcome: outcomeTimeout, RejectDigestOrZero32: make([]byte, 32), TimeoutTierOrZero: 1},
	}}
	unfinished := &taskv1.DispatchRecordV1{
		SchemaVersion: 1, ChainId: testChainID, TaskId: f.taskID, TaskHash: f.taskHash, SessionId: f.sessionID, OrderSequence: f.sequence,
		BuilderAddress: e.d.op, ReferenceHeight: 90, CandidatePoolSnapshotId: fill(0x66), VrfEpoch: testEpoch, VrfOutput: fill(0x99),
		BoundChangeHeight: testBound, DispatchTicketHash: make([]byte, 32), ServiceAuthorizationNonce: 1,
		Rounds: []*taskv1.DispatchRoundV1{firstRecordRound},
	}
	unfinishedRaw, _ := signWith(t, e.d.key, recordName, unfinished, func(s []byte) { unfinished.BuilderServiceSignature = s })
	r.failed = cloneView(f.view)
	r.failed.Rounds = []dispatchevidence.Round{r.firstRound}
	r.failed.Record = unfinishedRaw

	inputHash := sha256.Sum256(r.input)
	r.order = proto.Clone(f.order).(*taskv1.TaskOrderV3)
	r.order.EarliestSubmitHeight, r.order.InputHash, r.order.InputSizeBytes = testESH+2, inputHash[:], uint64(len(r.input))
	taskHash, err := nodecontract.TaskOrderHashV3(r.order)
	if err != nil {
		t.Fatal(err)
	}
	r.taskHash = taskHash[:]
	e.inputs[hex.EncodeToString(r.taskHash)] = r.input
	r.signed = signOrder(t, userKey, r.order)
	ticket := &taskv1.DispatchTicketV1{
		SchemaVersion: 1, ChainId: testChainID, TaskId: f.taskID, TaskHash: r.taskHash, SessionId: f.sessionID, OrderSequence: f.sequence,
		BuilderAddress: e.d.op, ReferenceHeight: 90, CandidatePoolSnapshotId: fill(0x66), VrfEpoch: testEpoch, VrfOutput: fill(0x99),
		RosterHash: f.rosterHash[:], HandraiseRootDigest: f.rootDigest[:], DispatchRound: 1, Rank: 1, Target: memberRef(e.worker.op, 3),
		AcceptDeadlineMs: 1, InputHash: inputHash[:], BoundChangeHeight: testBound, ServiceAuthorizationNonce: 1,
	}
	r.ticket, r.hash = signWith(t, e.d.key, ticketName, ticket, func(s []byte) { ticket.BuilderServiceSignature = s })
	accept := &taskv1.DispatchAcceptV1{SchemaVersion: 1, ChainId: testChainID, TaskId: f.taskID, TaskHash: r.taskHash,
		DispatchTicketHash: r.hash[:], Member: memberRef(e.worker.op, 3), ServiceAuthorizationNonce: 1}
	r.accept, r.acceptDig = signWith(t, e.worker.key, acceptName, accept, func(s []byte) { accept.ServiceSignature = s })
	record := &taskv1.DispatchRecordV1{
		SchemaVersion: 1, ChainId: testChainID, TaskId: f.taskID, TaskHash: r.taskHash, SessionId: f.sessionID, OrderSequence: f.sequence,
		BuilderAddress: e.d.op, ReferenceHeight: 90, CandidatePoolSnapshotId: fill(0x66), VrfEpoch: testEpoch, VrfOutput: fill(0x99),
		BoundChangeHeight: testBound, DispatchTicketHash: r.hash[:], ServiceAuthorizationNonce: 1,
		Rounds: []*taskv1.DispatchRoundV1{firstRecordRound, {DispatchRound: 1, HandraiseRootDigest: f.rootDigest[:], RosterHash: f.rosterHash[:],
			Attempts: []*taskv1.DispatchAttemptV1{{DispatchTicketHash: r.hash[:], Rank: 1, Member: memberRef(e.worker.op, 3), Outcome: outcomeAccepted, RejectDigestOrZero32: make([]byte, 32)}}}},
	}
	r.record, _ = signWith(t, e.d.key, recordName, record, func(s []byte) { record.BuilderServiceSignature = s })
	r.evidence = &dispatchevidence.Order{
		SessionID: f.sessionHex(), Sequence: f.sequence, TaskID: f.taskHex(), TaskHash: hex.EncodeToString(r.taskHash),
		Epoch: testEpoch, BoundChangeHeight: testBound, SignedOrder: r.signed, DeadlineBase: testESH + 2,
		Rounds: []dispatchevidence.Round{r.firstRound, {Number: 1, TaskHash: hex.EncodeToString(r.taskHash), RootDigest: f.rootDigest[:], Roster: f.roster,
			RosterHash: f.rosterHash[:], Attempts: []dispatchevidence.Attempt{{Ticket: r.ticket, Hash: r.hash[:], Rank: 1, Operator: e.worker.op, Sent: true, Outcome: outcomeAccepted}}}},
		Accept: r.accept, Record: r.record,
	}
	return r
}

// recordOnChain makes the chain hold the retry's record with the worker's ticket.
func (r *retried) recordOnChain() {
	f := r.f
	f.e.records.set(f.sessionHex(), f.sequence, &taskv1.DispatchRecordState{
		TaskId: f.taskID, DispatchTicketHash: r.hash[:], BuilderAddress: f.e.d.op, RecordedHeight: 110, DispatchRecordHash: fill(0x7a),
	})
}

// recordedAttempt is D's attempt book entry of the retry's winner once RECORDED.
func (r *retried) recordedAttempt() attempt.Attempt {
	f := r.f
	t := f.e.t
	var ticket taskv1.DispatchTicketV1
	var accept taskv1.DispatchAcceptV1
	if proto.Unmarshal(r.ticket, &ticket) != nil || proto.Unmarshal(r.accept, &accept) != nil {
		t.Fatal("retry messages do not parse")
	}
	header, err := attempt.SignResultHeader(servicekey.Key{Signer: f.e.d.key, Nonce: 1}, &nexusv1.DispatchResultHeaderV1{
		TaskId: f.taskID, WinnerTicket: &ticket, Accept: &accept, RecordStatus: attempt.Recorded,
	})
	if err != nil {
		t.Fatal(err)
	}
	return attempt.Attempt{
		SessionID: f.sessionHex(), Sequence: f.sequence, TaskID: f.taskHex(), TaskHash: hex.EncodeToString(r.taskHash),
		Worker: f.e.worker.op, TicketHash: r.hash, AcceptDigest: r.acceptDig, Status: attempt.Recorded,
		Ticket: r.ticket, Accept: r.accept, Header: header, User: f.user,
	}
}

// caughtUp fails the test unless M acknowledged every item D queued for the order.
func (e *env) caughtUp() {
	e.t.Helper()
	st := e.s.streams[streamKey(e.fx.sessionHex(), e.fx.sequence)]
	if st == nil || st.Last == 0 || st.Acked[e.m.op] != st.Last {
		e.t.Fatalf("member did not take every item: %+v", st)
	}
}

// A re-signed retry of a failed order continues its rounds in the same epoch and binding
// generation under a new task_hash: the member holds the failed version's rounds and the retry's
// side by side, takes the retry's input, record and, once the chain recorded it, its order, so it
// can stand in for D on the retry.
func TestRetriedOrderSyncsItsNewRounds(t *testing.T) {
	e := newEnv(t)
	r := newRetried(e)
	e.s.OrderChanged(r.failed)
	e.sync()
	e.caughtUp()
	if err := e.dEvidence.Put(r.evidence); err != nil {
		t.Fatal(err)
	}
	e.s.OrderChanged(r.evidence)
	e.sync()
	e.caughtUp()
	c := e.copyOf()
	if c == nil || len(c.Rounds) != 2 || c.TaskHash != hex.EncodeToString(r.taskHash) || !bytes.Equal(c.Record, r.record) || !bytes.Equal(c.Accept, r.accept) {
		t.Fatalf("copy of the retry = %+v", c)
	}
	if c.RoundTaskHash(&c.Rounds[0]) != r.f.view.TaskHash || c.RoundTaskHash(&c.Rounds[1]) != c.TaskHash {
		t.Fatalf("round versions = %q, %q", c.RoundTaskHash(&c.Rounds[0]), c.RoundTaskHash(&c.Rounds[1]))
	}
	input, _, err := StoredInputs{Store: e.member.data}.ReadInput(context.Background(), r.f.sessionHex(), r.f.taskHex(), c.TaskHash)
	if err != nil || !bytes.Equal(input, r.input) {
		t.Fatalf("member's input of the retry = %q, %v", input, err)
	}

	r.recordOnChain()
	e.s.Recorded(r.recordedAttempt())
	e.sync()
	e.caughtUp()
	if c = e.copyOf(); !c.Recorded || !bytes.Equal(c.SignedOrder, r.signed) {
		t.Fatalf("copy after the record = %+v", c)
	}
	if a, held := e.member.r.Replica(r.f.sessionHex(), r.f.taskHex()); !held || a.Status != attempt.Recorded || a.TicketHash != r.hash ||
		a.TaskHash != hex.EncodeToString(r.taskHash) {
		t.Fatalf("replica after the record = %+v, %v", a, held)
	}
}

// A sender that never queued the failed version's round (its change was superseded by the
// retry's before the queue ran) still names each round's own version in the round item.
func TestRetryRoundItemsNameTheirVersion(t *testing.T) {
	e := newEnv(t)
	r := newRetried(e)
	e.s.OrderChanged(r.evidence)
	e.sync()
	e.caughtUp()
	var versions []string
	for _, req := range e.peers.requests[e.m.op] {
		for _, item := range req.GetBatch().GetItems() {
			if round := item.GetRound(); round != nil {
				versions = append(versions, hex.EncodeToString(round.GetTaskHash()))
			}
		}
	}
	if len(versions) != 2 || versions[0] != r.f.view.TaskHash || versions[1] != hex.EncodeToString(r.taskHash) {
		t.Fatalf("round items name task_hash %v", versions)
	}
}

// A record must name the version of one of the rounds it lists, and a ticket the version of its
// round.
func TestRecordOrTicketOfAnotherVersionThanItsRoundsIsRefused(t *testing.T) {
	e := newEnv(t)
	r := newRetried(e)
	forged := cloneView(r.failed)
	var rec taskv1.DispatchRecordV1
	if err := proto.Unmarshal(r.failed.Record, &rec); err != nil {
		t.Fatal(err)
	}
	rec.TaskHash = r.taskHash
	forged.Record, _ = signWith(t, e.d.key, recordName, &rec, func(s []byte) { rec.BuilderServiceSignature = s })
	e.s.OrderChanged(forged)
	e.sync()
	if c := e.copyOf(); c == nil || len(c.Rounds) != 1 || len(c.Record) != 0 {
		t.Fatalf("copy took a record naming no round's version: %+v", c)
	}

	e = newEnv(t)
	r = newRetried(e)
	var ticket taskv1.DispatchTicketV1
	if err := proto.Unmarshal(r.ticket, &ticket); err != nil {
		t.Fatal(err)
	}
	ticket.TaskHash, ticket.InputHash = r.f.taskHash, r.f.order.GetInputHash()
	raw, hash := signWith(t, e.d.key, ticketName, &ticket, func(s []byte) { ticket.BuilderServiceSignature = s })
	mixed := cloneView(r.evidence)
	mixed.Rounds[1].Attempts = []dispatchevidence.Attempt{{Ticket: raw, Hash: hash[:], Rank: 1, Operator: e.worker.op, Sent: true, Outcome: outcomeOut}}
	mixed.Accept, mixed.Record = nil, nil
	e.s.OrderChanged(mixed)
	e.sync()
	if c := e.copyOf(); c == nil || len(c.Rounds) != 2 || len(c.Rounds[1].Attempts) != 0 {
		t.Fatalf("copy took a ticket of another version than its round: %+v", c)
	}
}
