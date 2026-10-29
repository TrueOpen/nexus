package buildersync

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	buildersyncv1 "github.com/TrueOpen/nexus/gen/buildersync/v1"
	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/attempt"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatchevidence"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/mmr"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/taskdata"
	"github.com/TrueOpen/nexus/internal/taskgroup"
)

const (
	testChainID = "trueopen-phase1-vector-1"
	prefix      = "trueopen"
	testESH     = 100
	testBound   = 80
	testEpoch   = 7
)

var (
	evidenceParams = dispatchevidence.Params{RecordDeadlineBlocks: 20, ClaimWindowBlocks: 30, RebuttalBlocks: 10,
		ChallengeWindowBlocks: 50, ChallengeResponseBlocks: 6, RetentionBlocks: 100}
	outputConfig = taskdata.OutputStreamConfig{MaxLeaves: 16, MinFrameBytes: 4, MaxFrameBytes: 64}
	storeConfig  = taskdata.Config{InlineMaxBytes: 8, ChunkSizeBytes: 64, MaxRangeBytes: 256, MaxBlobBytes: 4096,
		SpoolReservationBytes: 1 << 20, DiskAcceptWatermarkPercent: 90}
)

func fill(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func newSigner(t testing.TB, seed byte) signer.Signer {
	t.Helper()
	s, err := signer.NewFromBytes(bytes.Repeat([]byte{seed}, 32), prefix)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// party is an operator with its current service key.
type party struct {
	op  string
	key signer.Signer
}

func newParty(t testing.TB, opSeed, keySeed byte) party {
	return party{op: newSigner(t, opSeed).Address(), key: newSigner(t, keySeed)}
}

// fakeKeys answers current service keys.
type fakeKeys struct {
	mu      sync.Mutex
	keys    map[string]signer.Signer // participant|operator
	fails   bool
	lookups []string // participant|operator of every lookup
}

func (k *fakeKeys) set(participant string, p party) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.keys[participant+"|"+p.op] = p.key
}

func (k *fakeKeys) QueryCurrentServiceKey(_ context.Context, participant, operator string) (chaincli.ServiceKeyState, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.lookups = append(k.lookups, participant+"|"+operator)
	if k.fails {
		return chaincli.ServiceKeyState{}, errors.New("chain unreachable")
	}
	s, ok := k.keys[participant+"|"+operator]
	if !ok {
		return chaincli.ServiceKeyState{}, chaincli.ErrNotFound
	}
	return chaincli.ServiceKeyState{
		ParticipantType: participant, OperatorAddress: operator, ServicePubKey: hex.EncodeToString(s.PubKeyCompressed()),
		ServiceAddress: s.Address(), Status: "ACTIVE",
	}, nil
}

type fakeGroups struct {
	mu       sync.Mutex
	snapshot taskgroup.Snapshot
}

func taskgroupSnapshot(id string, hash byte, members ...string) taskgroup.Snapshot {
	return taskgroup.Snapshot{ID: id, Hash: [32]byte(fill(hash)), Members: members}
}

func (g *fakeGroups) CurrentBuilderSet() (taskgroup.Snapshot, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.snapshot, g.snapshot.ID != ""
}

type fakeRecords struct {
	mu      sync.Mutex
	records map[string]*taskv1.DispatchRecordState
	err     error
}

func (f *fakeRecords) QueryDispatchRecordByOrder(_ context.Context, sessionID string, seq uint64) (*taskv1.DispatchRecordState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	rec, ok := f.records[streamKey(sessionID, seq)]
	if !ok {
		return nil, chaincli.ErrNotFound
	}
	return proto.Clone(rec).(*taskv1.DispatchRecordState), nil
}

func (f *fakeRecords) set(sessionID string, seq uint64, rec *taskv1.DispatchRecordState) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[streamKey(sessionID, seq)] = rec
}

type fakeInputs map[string][]byte // task hash -> input

func (f fakeInputs) ReadInput(_ context.Context, _, _, taskHash string) ([]byte, string, error) {
	data, ok := f[taskHash]
	if !ok {
		return nil, "", errors.New("no input")
	}
	return data, "text/plain", nil
}

// loopPeers hands batches straight to the members' receivers; fail makes a member unreachable.
type loopPeers struct {
	mu        sync.Mutex
	receivers map[string]*Receiver
	fail      map[string]error
	requests  map[string][]*buildersyncv1.SyncRequest
}

func (p *loopPeers) Sync(ctx context.Context, operator string, req *buildersyncv1.SyncRequest) (*buildersyncv1.SyncResponse, error) {
	p.mu.Lock()
	p.requests[operator] = append(p.requests[operator], req)
	err := p.fail[operator]
	r := p.receivers[operator]
	p.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return r.Sync(ctx, req)
}

func (p *loopPeers) setFail(operator string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fail[operator] = err
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// member is a group member's receiving side.
type member struct {
	party
	store     kv.Store
	evidence  *dispatchevidence.Store
	data      *taskdata.Store
	r         *Receiver
	published []taskdata.OutputFrame
	pubMu     sync.Mutex
}

func (m *member) frames() []taskdata.OutputFrame {
	m.pubMu.Lock()
	defer m.pubMu.Unlock()
	return append([]taskdata.OutputFrame(nil), m.published...)
}

// env is a dispatching Builder D syncing to member M of a group {D, M, X}.
type env struct {
	t       *testing.T
	d, m, x party
	worker  party
	other   party // a Cortex that is not the winner
	keys    *fakeKeys
	groups  *fakeGroups
	records *fakeRecords
	peers   *loopPeers
	clock   *fakeClock

	dStore    kv.Store
	dEvidence *dispatchevidence.Store
	dData     *taskdata.Store
	inputs    fakeInputs
	roots     map[[32]byte]*taskv1.SignedHandraiseRootV1
	s         *Sender
	member    *member

	fx *fixture
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{
		t: t, d: newParty(t, 0x01, 0x11), m: newParty(t, 0x02, 0x12), x: newParty(t, 0x03, 0x13),
		worker: newParty(t, 0x04, 0x14), other: newParty(t, 0x05, 0x15),
		keys:    &fakeKeys{keys: map[string]signer.Signer{}},
		records: &fakeRecords{records: map[string]*taskv1.DispatchRecordState{}},
		peers:   &loopPeers{receivers: map[string]*Receiver{}, fail: map[string]error{}, requests: map[string][]*buildersyncv1.SyncRequest{}},
		clock:   &fakeClock{now: time.UnixMilli(1_800_000_000_000)},
		dStore:  kv.NewMemStore(), inputs: fakeInputs{}, roots: map[[32]byte]*taskv1.SignedHandraiseRootV1{},
	}
	for _, p := range []party{e.d, e.m, e.x} {
		e.keys.set("BUILDER", p)
	}
	e.keys.set("CORTEX", e.worker)
	e.keys.set("CORTEX", e.other)
	e.groups = &fakeGroups{snapshot: taskgroup.Snapshot{ID: "set-1", Hash: [32]byte(fill(0x5e)), Members: []string{e.d.op, e.m.op, e.x.op}}}
	e.dEvidence = dispatchevidence.New(e.dStore, evidenceParams)
	e.dData = newDataStore(t, e.dStore)
	e.member = e.newMember(e.m)
	e.peers.receivers[e.m.op] = e.member.r
	e.peers.setFail(e.x.op, errors.New("X is down"))
	e.openSender()
	e.fx = newFixture(e)
	return e
}

func newDataStore(t *testing.T, store kv.Store) *taskdata.Store {
	t.Helper()
	data, err := taskdata.NewStore(nil, t.TempDir(), store, storeConfig, taskdata.WithDiskUsage(func(string) (uint64, uint64, error) { return 1 << 40, 0, nil }))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func (e *env) newMember(p party) *member {
	e.t.Helper()
	m := &member{party: p, store: kv.NewMemStore()}
	m.evidence = dispatchevidence.New(m.store, evidenceParams)
	m.data = newDataStore(e.t, m.store)
	var err error
	m.r, err = NewReceiver(ReceiverConfig{
		ChainID: testChainID, Builder: p.op, AddressPrefix: prefix, Keys: e.keys, Groups: e.groups, Store: m.store,
		Evidence: m.evidence, Inputs: StoredInputs{Store: m.data}, Outputs: m.data, OutputConfig: outputConfig,
		Publish: func(_ taskdata.ObjectKey, f taskdata.OutputFrame) {
			m.pubMu.Lock()
			defer m.pubMu.Unlock()
			m.published = append(m.published, f)
		},
		Chain: e.records, Retention: evidenceParams.RetainUntil, MaxInputBytes: 4096,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return m
}

// openSender builds D's sender over its store, as after a start (without the workers).
func (e *env) openSender() {
	e.t.Helper()
	var err error
	e.s, err = NewSender(SenderConfig{
		ChainID: testChainID, Builder: e.d.op, Signer: e.d.key, Store: e.dStore, Groups: e.groups,
		Roots: func(d [32]byte) (*taskv1.SignedHandraiseRootV1, bool, error) {
			r, ok := e.roots[d]
			return r, ok, nil
		},
		Inputs: e.inputs, Outputs: e.dData, Evidence: e.dEvidence, Peers: e.peers, Retention: evidenceParams.RetainUntil,
		InputChunkBytes: 5, AlarmAfter: time.Minute, Clock: e.clock.Now,
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

// sync runs D's queue and one delivery pass to M.
func (e *env) sync() {
	e.t.Helper()
	e.s.drain()
	e.s.deliverPeer(context.Background(), e.m.op)
}

// ---- a dispatched order ----

// fixture is one order of a session dispatched by D: round 0 to op1 (rejected) then the worker
// (accepted).
type fixture struct {
	e          *env
	sessionID  []byte
	sequence   uint64
	taskID     []byte
	taskHash   []byte
	input      []byte
	signed     []byte
	roster     []byte
	rosterHash [32]byte
	root       []byte
	rootDigest [32]byte
	rejecter   party
	tickets    [][]byte
	hashes     [][32]byte
	reject     []byte
	accept     []byte
	acceptDig  [32]byte
	record     []byte
	// view is the evidence as D's dispatcher hands it over.
	view *dispatchevidence.Order
}

func mustMarshal(t testing.TB, m proto.Message) []byte {
	t.Helper()
	raw, err := marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func digestOf(t testing.TB, name string, raw []byte) [32]byte {
	t.Helper()
	d, err := dispatch.SigningDigest(name, raw)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// signWith signs m under name with key, setting the signature through set, and returns the
// signed bytes and the digest.
func signWith(t testing.TB, key signer.Signer, name string, m proto.Message, set func([]byte)) ([]byte, [32]byte) {
	t.Helper()
	set(nil)
	digest := digestOf(t, name, mustMarshal(t, m))
	sig, err := key.SignDigest(digest)
	if err != nil {
		t.Fatal(err)
	}
	set(sig)
	return mustMarshal(t, m), digest
}

func memberRef(op string, slot uint32) *taskv1.CandidateMemberRefV1 {
	return &taskv1.CandidateMemberRefV1{CandidatePoolSnapshotId: fill(0x66), Slot: slot, SlotVersion: 1, OperatorAddress: op}
}

func newFixture(e *env) *fixture {
	t := e.t
	f := &fixture{e: e, sessionID: fill(0xaa), sequence: 3, taskID: fill(0xa1), taskHash: fill(0xb1), input: []byte("hello, group members"),
		rejecter: newParty(t, 0x06, 0x16)}
	e.keys.set("CORTEX", f.rejecter)
	inputHash := sha256.Sum256(f.input)
	e.inputs[hex.EncodeToString(f.taskHash)] = f.input
	f.signed = mustMarshal(t, &taskv1.SignedOrderV2{Order: &taskv1.TaskOrderV3{
		ChainId: testChainID, UserAddress: "trueopen1user", SessionId: f.sessionID, OrderSequence: f.sequence,
		InputHash: inputHash[:], InputSizeBytes: uint64(len(f.input)), EarliestSubmitHeight: testESH,
		BuilderSetId: "set-1", BuilderSetHash: fill(0x5e),
	}})
	members := []dispatch.RosterMember{
		{Slot: 1, SlotVersion: 1, OperatorAddress: f.rejecter.op, CandidateWeight: 1},
		{Slot: 3, SlotVersion: 1, OperatorAddress: e.worker.op, CandidateWeight: 5},
	}
	roster := &taskv1.DispatchRosterV1{TaskId: f.taskID, ReferenceHeight: 90, CandidatePoolSnapshotId: fill(0x66)}
	for _, m := range members {
		roster.Members = append(roster.Members, &taskv1.DispatchRosterMemberV1{Slot: m.Slot, SlotVersion: m.SlotVersion, OperatorAddress: m.OperatorAddress, CandidateWeight: m.CandidateWeight})
	}
	f.roster = mustMarshal(t, roster)
	var err error
	if f.rosterHash, err = dispatch.RosterDigest(testChainID, [32]byte(f.taskID), 90, [32]byte(fill(0x66)), members); err != nil {
		t.Fatal(err)
	}
	root := &taskv1.SignedHandraiseRootV1{ChainId: testChainID, BuilderAddress: e.d.op, RootHeight: 95, LeafCount: 2, Root: fill(0x77)}
	f.root, f.rootDigest = signWith(t, e.d.key, rootName, root, func(s []byte) { root.BuilderServiceSignature = s })
	e.roots[f.rootDigest] = root

	for rank, target := range []party{f.rejecter, e.worker} {
		ticket := &taskv1.DispatchTicketV1{
			SchemaVersion: 1, ChainId: testChainID, TaskId: f.taskID, TaskHash: f.taskHash, SessionId: f.sessionID, OrderSequence: f.sequence,
			BuilderAddress: e.d.op, ReferenceHeight: 90, CandidatePoolSnapshotId: fill(0x66), VrfEpoch: testEpoch, VrfOutput: fill(0x99),
			RosterHash: f.rosterHash[:], HandraiseRootDigest: f.rootDigest[:], Rank: uint32(rank), Target: memberRef(target.op, members[rank].Slot),
			AcceptDeadlineMs: 1, InputHash: inputHash[:], BoundChangeHeight: testBound,
		}
		raw, hash := signWith(t, e.d.key, ticketName, ticket, func(s []byte) { ticket.BuilderServiceSignature = s })
		f.tickets, f.hashes = append(f.tickets, raw), append(f.hashes, hash)
	}
	reject := &taskv1.DispatchRejectV1{
		SchemaVersion: 1, ChainId: testChainID, TaskId: f.taskID, TaskHash: f.taskHash, DispatchTicketHash: f.hashes[0][:],
		Member: memberRef(f.rejecter.op, 1), ServiceAuthorizationNonce: 1,
	}
	f.reject, _ = signWith(t, f.rejecter.key, rejectName, reject, func(s []byte) { reject.ServiceSignature = s })
	accept := &taskv1.DispatchAcceptV1{SchemaVersion: 1, ChainId: testChainID, TaskId: f.taskID, TaskHash: f.taskHash,
		DispatchTicketHash: f.hashes[1][:], Member: memberRef(e.worker.op, 3), ServiceAuthorizationNonce: 1}
	f.accept, f.acceptDig = signWith(t, e.worker.key, acceptName, accept, func(s []byte) { accept.ServiceSignature = s })
	record := &taskv1.DispatchRecordV1{
		SchemaVersion: 1, ChainId: testChainID, TaskId: f.taskID, TaskHash: f.taskHash, SessionId: f.sessionID, OrderSequence: f.sequence,
		BuilderAddress: e.d.op, ReferenceHeight: 90, CandidatePoolSnapshotId: fill(0x66), VrfEpoch: testEpoch, VrfOutput: fill(0x99),
		BoundChangeHeight: testBound, DispatchTicketHash: f.hashes[1][:],
		Rounds: []*taskv1.DispatchRoundV1{{DispatchRound: 0, HandraiseRootDigest: f.rootDigest[:], RosterHash: f.rosterHash[:], Attempts: []*taskv1.DispatchAttemptV1{
			{DispatchTicketHash: f.hashes[0][:], Rank: 0, Member: memberRef(f.rejecter.op, 1), Outcome: outcomeRejected, RejectDigestOrZero32: fill(0xee)},
			{DispatchTicketHash: f.hashes[1][:], Rank: 1, Member: memberRef(e.worker.op, 3), Outcome: outcomeAccepted, RejectDigestOrZero32: make([]byte, 32)},
		}}},
	}
	f.record, _ = signWith(t, e.d.key, recordName, record, func(s []byte) { record.BuilderServiceSignature = s })
	f.view = &dispatchevidence.Order{
		SessionID: hex.EncodeToString(f.sessionID), Sequence: f.sequence, TaskID: hex.EncodeToString(f.taskID), TaskHash: hex.EncodeToString(f.taskHash),
		Epoch: testEpoch, SignedOrder: f.signed, DeadlineBase: testESH,
		Rounds: []dispatchevidence.Round{{Number: 0, RootDigest: f.rootDigest[:], Roster: f.roster, RosterHash: f.rosterHash[:]}},
	}
	return f
}

const (
	outcomeRejected = taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_REJECTED
	outcomeOut      = taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_UNSPECIFIED
)

func (f *fixture) sessionHex() string { return hex.EncodeToString(f.sessionID) }
func (f *fixture) taskHex() string    { return hex.EncodeToString(f.taskID) }

// issued is D's view after the first ticket was issued.
func (f *fixture) issued() *dispatchevidence.Order {
	v := cloneView(f.view)
	v.Rounds[0].Attempts = []dispatchevidence.Attempt{{Ticket: f.tickets[0], Hash: f.hashes[0][:], Rank: 0, Operator: f.rejecter.op, Sent: true, Outcome: outcomeOut}}
	return v
}

// rejectedThenOut is D's view after op1 rejected and the worker's ticket is out.
func (f *fixture) rejectedThenOut() *dispatchevidence.Order {
	v := cloneView(f.view)
	v.Rounds[0].Attempts = []dispatchevidence.Attempt{
		{Ticket: f.tickets[0], Hash: f.hashes[0][:], Rank: 0, Operator: f.rejecter.op, Sent: true, Outcome: outcomeRejected, Reject: f.reject},
		{Ticket: f.tickets[1], Hash: f.hashes[1][:], Rank: 1, Operator: f.e.worker.op, Sent: true, Outcome: outcomeOut},
	}
	return v
}

// accepted is D's evidence once the worker accepted: with the accept and the signed record.
func (f *fixture) accepted() *dispatchevidence.Order {
	v := f.rejectedThenOut()
	v.Rounds[0].Attempts[1].Outcome = outcomeAccepted
	v.Accept, v.Record = f.accept, f.record
	return v
}

func cloneView(o *dispatchevidence.Order) *dispatchevidence.Order {
	v := *o
	v.Rounds = append([]dispatchevidence.Round(nil), o.Rounds...)
	return &v
}

// recordOnChain makes the chain hold the order's record with the worker's ticket.
func (f *fixture) recordOnChain() {
	f.e.records.set(f.sessionHex(), f.sequence, &taskv1.DispatchRecordState{
		TaskId: f.taskID, DispatchTicketHash: f.hashes[1][:], BuilderAddress: f.e.d.op, RecordedHeight: 110, DispatchRecordHash: fill(0x7a),
		Rounds: []*taskv1.DispatchRoundV1{{DispatchRound: 0, HandraiseRootDigest: f.rootDigest[:], RosterHash: f.rosterHash[:]}},
	})
}

// recordedAttempt is D's attempt book entry of the winner once RECORDED.
func (f *fixture) recordedAttempt() attempt.Attempt {
	t := f.e.t
	var ticket taskv1.DispatchTicketV1
	var accept taskv1.DispatchAcceptV1
	if proto.Unmarshal(f.tickets[1], &ticket) != nil || proto.Unmarshal(f.accept, &accept) != nil {
		t.Fatal("fixture messages do not parse")
	}
	header, err := attempt.SignResultHeader(f.e.d.key, &nexusv1.DispatchResultHeaderV1{
		TaskId: f.taskID, WinnerTicket: &ticket, Accept: &accept, RecordStatus: attempt.Recorded,
	})
	if err != nil {
		t.Fatal(err)
	}
	return attempt.Attempt{
		SessionID: f.sessionHex(), Sequence: f.sequence, TaskID: f.taskHex(), TaskHash: hex.EncodeToString(f.taskHash),
		Worker: f.e.worker.op, TicketHash: f.hashes[1], AcceptDigest: f.acceptDig, Status: attempt.Recorded,
		Ticket: f.tickets[1], Accept: f.accept, Header: header, User: "trueopen1user",
	}
}

// putAccepted stores D's evidence of the accepted order, as the dispatcher does.
func (f *fixture) putAccepted() {
	if err := f.e.dEvidence.Put(f.accepted()); err != nil {
		f.e.t.Fatal(err)
	}
}

// writeOutput stores n chunks of the winner (and its Fin when fin) on D, as the Worker uploads
// them; signer signs them.
func (f *fixture) writeOutput(data *taskdata.Store, by party, texts []string, fin bool) {
	t := f.e.t
	key := taskdata.ObjectKey{TaskHash: hex.EncodeToString(f.taskHash), SessionID: f.sessionHex(), TaskID: f.taskHex(), Kind: taskdata.ObjectKindOutput}
	stream, progress, err := data.OpenReplicaStream(context.Background(), key, f.e.worker.op, outputConfig, f.hashes[1][:])
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	acc, _ := mmr.New(nodecontract.DomainOutputMMRV1)
	for i, text := range texts {
		root := acc.Append([]byte(text))
		if progress.Received && uint64(i) <= progress.LastSeq {
			continue
		}
		digest := dispatch.OutputChunkDigest(testChainID, [32]byte(f.taskHash), f.hashes[1], uint64(i), root)
		sig, err := by.key.SignDigest(digest)
		if err != nil {
			t.Fatal(err)
		}
		chunk := taskdata.OutputChunk{Seq: uint64(i), Text: []byte(text), MMRRoot: root[:], WorkerSignature: sig, DispatchTicketHash: f.hashes[1][:],
			CumulativeGeneratedTokens: uint64(i + 1)}
		if _, err := stream.Append(context.Background(), chunk); err != nil {
			t.Fatal(err)
		}
	}
	if !fin {
		return
	}
	root := acc.Root()
	digest, err := dispatch.OutputFinDigest(testChainID, [32]byte(f.taskHash), f.hashes[1], uint64(len(texts)-1), root, 1)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := by.key.SignDigest(digest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Finish(context.Background(), taskdata.OutputFin{FinalSeq: uint64(len(texts) - 1), OutputMMRRoot: root[:], FinishReason: 1,
		WorkerSignature: sig, DispatchTicketHash: f.hashes[1][:]}); err != nil {
		t.Fatal(err)
	}
}

// copyOf returns M's copy of D's evidence of the order.
func (e *env) copyOf() *dispatchevidence.Order {
	e.t.Helper()
	orders, err := e.member.evidence.ByTask(e.fx.taskHex())
	if err != nil {
		e.t.Fatal(err)
	}
	for _, o := range orders {
		if o.Builder == e.d.op {
			return o
		}
	}
	return nil
}
