package buildersync

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatchevidence"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/registeredkey"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/taskdata"
	"github.com/TrueOpen/nexus/internal/taskgroup"
)

const outcomeAccepted = taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_ACCEPTED

// MemberEvidence keeps the copies of the dispatching Builders' evidence (dispatchevidence.Store).
type MemberEvidence interface {
	Put(o *dispatchevidence.Order, extra ...kv.WriteOp) error
	ByTask(taskID string) ([]*dispatchevidence.Order, error)
	ByTicket(hash []byte) (*dispatchevidence.Order, *dispatchevidence.Attempt, bool, error)
}

// InputWriter stores an order version's input with the task data (StoredInputs).
type InputWriter interface {
	PutInput(ctx context.Context, header taskdata.UploadHeader, data []byte) error
}

// ReplicaWriter writes and reads the output replica (taskdata.Store).
type ReplicaWriter interface {
	OpenReplicaStream(ctx context.Context, key taskdata.ObjectKey, worker string, cfg taskdata.OutputStreamConfig, ticket []byte) (*taskdata.OutputStream, taskdata.OutputStreamProgress, error)
	OutputStreamProgressOf(ctx context.Context, key taskdata.ObjectKey) (taskdata.OutputStreamProgress, bool, error)
}

// RecordReader reads the dispatch record the chain admitted for a session order.
type RecordReader interface {
	QueryDispatchRecordByOrder(ctx context.Context, sessionID string, orderSequence uint64) (*taskv1.DispatchRecordState, error)
}

// ReceiverConfig wires a Receiver.
type ReceiverConfig struct {
	ChainID string
	// Builder is this Builder's operator address.
	Builder       string
	AddressPrefix string
	// Keys answers the current service keys: the senders' BUILDER keys and the winners' CORTEX keys.
	Keys     servicekey.Resolver
	Groups   taskgroup.Source
	Store    kv.Store
	Evidence MemberEvidence
	Inputs   InputWriter
	Outputs  ReplicaWriter
	// OutputConfig holds the network's output stream limits the replica is written under; zero
	// when this Builder does not serve streamed output, which then keeps no replicas and says so.
	OutputConfig taskdata.OutputStreamConfig
	// Publish hands a replica frame to the live subscribers of its task (taskdata.OutputDispatcher).
	Publish func(taskdata.ObjectKey, taskdata.OutputFrame)
	Chain   RecordReader
	// Retention is the last height a copy of an order's evidence is kept at
	// (dispatchevidence.Params.RetainUntil); the member's sync stream and stored input follow it.
	Retention func(*dispatchevidence.Order) uint64
	// MaxInputBytes bounds an order version's input.
	MaxInputBytes uint64
	// FeeDenom is the chain's business_denom, the feeDenom of the order signing domain: with it a
	// synced order's user signature is checked. Empty skips that check. An order signed by a key
	// other than the user's wallet is checked against the session's registered key in SessionKeys.
	FeeDenom    string
	SessionKeys SessionKeyReader
	// PreviousSnapshotBlocks is how many blocks after a BuilderSet replacement a new order of the
	// replaced snapshot is still accepted (0 = 600).
	PreviousSnapshotBlocks uint64
	Log                    *slog.Logger
}

// SessionKeyReader reads the registered-key state of a session (registeredkey.Cache).
type SessionKeyReader interface {
	Lookup(ctx context.Context, sessionID string, height uint64) (registeredkey.State, error)
}

// Receiver applies the sync streams the dispatching Builders send this Builder as a member of
// their orders' Task Builders groups.
type Receiver struct {
	cfg ReceiverConfig
	log *slog.Logger

	mu       sync.Mutex
	locks    map[string]*sync.Mutex
	replicas map[string]*taskdata.OutputStream
	// current and previous are the last two BuilderSet snapshots seen current; replacedAt the head
	// when current replaced previous.
	current, previous *taskgroup.Snapshot
	replacedAt        uint64

	head      atomic.Uint64
	lastPrune atomic.Uint64

	watch watchers
}

// NewReceiver builds a Receiver.
func NewReceiver(cfg ReceiverConfig) (*Receiver, error) {
	switch {
	case cfg.ChainID == "" || cfg.Builder == "" || cfg.Keys == nil || cfg.Groups == nil || cfg.Store == nil:
		return nil, fmt.Errorf("builder sync receiver needs the chain id, Builder address, service keys, BuilderSet source and store")
	case cfg.Evidence == nil || cfg.Inputs == nil || cfg.Outputs == nil || cfg.Chain == nil || cfg.Retention == nil:
		return nil, fmt.Errorf("builder sync receiver needs the evidence, inputs, outputs, chain and retention")
	case cfg.MaxInputBytes == 0:
		return nil, fmt.Errorf("builder sync receiver needs the input size bound")
	}
	r := &Receiver{cfg: cfg, log: cfg.Log, locks: map[string]*sync.Mutex{}, replicas: map[string]*taskdata.OutputStream{}}
	if r.log == nil {
		r.log = slog.New(slog.DiscardHandler)
	}
	if r.cfg.Publish == nil {
		r.cfg.Publish = func(taskdata.ObjectKey, taskdata.OutputFrame) {}
	}
	if r.cfg.PreviousSnapshotBlocks == 0 {
		r.cfg.PreviousSnapshotBlocks = defaultPreviousSnapshotBlocks
	}
	return r, nil
}

// lock serializes the work on one member stream.
func (r *Receiver) lock(key string) func() {
	r.mu.Lock()
	l := r.locks[key]
	if l == nil {
		l = &sync.Mutex{}
		r.locks[key] = l
	}
	r.mu.Unlock()
	l.Lock()
	return l.Unlock
}

// HandleChainEvent follows the head and drops the member streams past their retention.
func (r *Receiver) HandleChainEvent(ev chaincli.ChainEvent) {
	if ev.Type != chaincli.EventNewBlock || ev.Height <= 0 {
		return
	}
	head := uint64(ev.Height)
	if head <= r.head.Load() {
		return
	}
	r.head.Store(head)
	r.observeSnapshot()
	if last := r.lastPrune.Load(); head >= last+pruneEveryBlocks {
		r.lastPrune.Store(head)
		r.prune(head)
	}
}

// Close closes the open replica streams; what they received is kept.
func (r *Receiver) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, stream := range r.replicas {
		stream.Close()
		delete(r.replicas, key)
	}
}

// Sync applies a SyncRequest as received. The bytes are validated strictly against the wire
// contract before they are decoded; a request that is not from a group member's dispatching
// Builder for this Builder fails with ErrMalformed, ErrUnauthenticated, ErrNotGroupMember or
// ErrUnavailable. Otherwise its items are applied in order from the one after the last applied,
// each checked first; an item at a sequence already applied must be the item applied there. The
// first that cannot be applied stops the batch and is named in the response, which always carries
// how far the order's items and output are held.
func (r *Receiver) Sync(ctx context.Context, raw []byte) (*nexusv1.SyncResponse, error) {
	if len(raw) > MaxRequestBytes {
		return nil, fmt.Errorf("%w: request of %d bytes", ErrMalformed, len(raw))
	}
	// Strict validation also enforces schema_version 1, a sender other than the receiver, a raw32
	// session_id and builder_set_hash, a non-empty chain_id and builder_set_id, consecutive item
	// sequences, the entry bounds and the identities inside the items; none is checked again here.
	// The chain and receiver can only be read from the decoded request, after it.
	if err := dispatch.ValidateMessage(requestName, raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	var req nexusv1.SyncRequest
	if err := proto.Unmarshal(raw, &req); err != nil {
		return nil, fmt.Errorf("%w: request: %v", ErrMalformed, err)
	}
	batch := req.GetBatch()
	switch {
	case batch.GetChainId() != r.cfg.ChainID:
		return nil, fmt.Errorf("%w: batch is for chain %q", ErrMalformed, batch.GetChainId())
	case batch.GetReceiverOperatorAddress() != r.cfg.Builder:
		return nil, fmt.Errorf("%w: batch is for %s", ErrMalformed, batch.GetReceiverOperatorAddress())
	}
	sender := batch.GetSenderOperatorAddress()
	sessionID := hex.EncodeToString(batch.GetSessionId())
	key := memberKey(sender, sessionID, batch.GetOrderSequence())
	// The group is the allowlist: only a member of the snapshot a new order names, or the sender of
	// a stream already held, is worth reading a service key for. Both are decided locally, so a
	// batch with a made-up sender costs no chain read.
	if err := r.admit(batch, key); err != nil {
		return nil, err
	}
	if err := r.authenticate(ctx, sender, raw); err != nil {
		return nil, err
	}
	unlock := r.lock(key)
	defer unlock()
	m, found, err := r.loadMember(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if !found {
		m = &memberStream{Sender: sender, SessionID: sessionID, Sequence: batch.GetOrderSequence(),
			BuilderSetID: batch.GetBuilderSetId(), BuilderSetHash: batch.GetBuilderSetHash(), Inputs: map[string]*memberInput{}}
	}
	resp := &nexusv1.SyncResponse{}
	applied := m.Applied
	defer func() {
		if m.Applied > applied && m.TaskID != "" {
			r.watch.notify(m.TaskID)
		}
	}()
	for _, item := range batch.GetItems() {
		digest, err := itemDigest(item)
		if err != nil {
			return nil, err
		}
		if item.GetSequence() <= m.Applied {
			if err := r.checkApplied(m, item.GetSequence(), digest); err != nil {
				resp.Refused = fmt.Sprintf("item %d: %v", item.GetSequence(), err)
				r.log.Warn("synced item refused", "order", key, "item", item.GetSequence(), "err", err)
				break
			}
			continue
		}
		if item.GetSequence() != m.Applied+1 {
			resp.Refused = fmt.Sprintf("item %d out of order: item %d is next", item.GetSequence(), m.Applied+1)
			break
		}
		next, err := r.apply(ctx, m, item, digest)
		if err != nil {
			resp.Refused = fmt.Sprintf("item %d: %v", item.GetSequence(), err)
			r.log.Warn("synced item refused", "order", key, "item", item.GetSequence(), "err", err)
			break
		}
		m = next
	}
	resp.OutputNotHeld = !r.holdsOutput()
	if resp.Refused == "" && batch.Output != nil && !resp.OutputNotHeld {
		if err := r.applyOutput(ctx, m, batch.GetOutput()); err != nil {
			resp.Refused = fmt.Sprintf("output: %v", err)
			r.log.Warn("synced output refused", "order", key, "err", err)
		}
	}
	resp.AppliedThrough = m.Applied
	if m.Recorded && m.Winner != nil && !resp.OutputNotHeld {
		progress, found, err := r.cfg.Outputs.OutputStreamProgressOf(ctx, r.replicaKey(m))
		if err == nil && found {
			resp.OutputReceived, resp.OutputLastSeq, resp.OutputSealed = progress.Received, progress.LastSeq, progress.Sealed
		}
	}
	return resp, nil
}

// authenticate checks a request is signed by its sender's current ACTIVE BUILDER service key, for
// this chain and this Builder: sync transport is current-key only. The dispatch proofs inside the
// batch are checked one by one under the generation their own nonce selects. A key the chain
// cannot answer is ErrUnavailable.
func (r *Receiver) authenticate(ctx context.Context, sender string, raw []byte) error {
	opts := dispatch.ProofKeyOptions{LookupProofKey: func(s dispatch.ServiceProofSigner) (dispatch.ProofKeyBinding, error) {
		key, state, err := servicekey.Current(ctx, r.cfg.Keys, r.cfg.AddressPrefix, servicekey.ParticipantBuilder, s.OperatorAddress)
		if err != nil {
			return dispatch.ProofKeyBinding{}, err
		}
		return dispatch.ProofKeyBinding{PublicKey: key, ServiceAuthorizationNonce: state.AuthorizationNonce, Status: dispatch.ProofKeyActive}, nil
	}}
	err := dispatch.VerifyBuilderSyncRequest(r.cfg.ChainID, r.cfg.Builder, raw, opts)
	switch {
	case errors.Is(err, servicekey.ErrAuthority):
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	case errors.Is(err, dispatch.ErrDecode):
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	case err != nil:
		return fmt.Errorf("%w: batch is not signed by the sender's current service key %s: %v", ErrUnauthenticated, sender, err)
	}
	return nil
}

// itemDigest is the local comparison key of an item: SHA-256 of its canonical typed projection, the
// element of the items field the batch signature commits to. Two items at one sequence are the
// same iff those bytes are equal, nested signatures included; the protobuf encoding is never
// compared, so field order or explicit defaults in a resend make no conflict.
func itemDigest(item *nexusv1.BuilderSyncItemV1) ([]byte, error) {
	raw, err := marshal(item)
	if err != nil {
		return nil, fmt.Errorf("%w: item %d: %v", ErrMalformed, item.GetSequence(), err)
	}
	projection, err := dispatch.BuilderSyncItemCanonicalBytes(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: item %d: %v", ErrMalformed, item.GetSequence(), err)
	}
	digest := sum(projection)
	return digest[:], nil
}

// checkApplied requires an item at an applied sequence to be the item applied there.
func (r *Receiver) checkApplied(m *memberStream, sequence uint64, digest []byte) error {
	held, found, err := r.cfg.Store.GetWithError(kv.NSBuilderSyncMember, appliedItemKey(m.key(), sequence))
	switch {
	case err != nil:
		return fmt.Errorf("%w: applied item: %v", ErrUnavailable, err)
	case !found:
		return errors.New("the item applied at this sequence is not held to compare with")
	case !bytes.Equal(held, digest):
		return errors.New("conflicts with the item applied at this sequence")
	}
	return nil
}

// verifyProof verifies a dispatch proof (root, ticket, record, accept or reject) with the wire
// verifier, under the key generation its signed nonce selects: the current one, or the previous
// (explicitly revoked) one only when the larger of the order version's earliest_submit_height and
// the bound_change_height of the held ticket a record, accept or reject belongs to (either nil when
// not known) is below that key's retirement (revoke). Tickets and result headers take the binding
// height from their own ticket, roots compare their root_height. A chain that cannot answer is
// ErrUnavailable.
func (r *Receiver) verifyProof(ctx context.Context, name string, raw []byte, earliestSubmitHeight, ticketBoundChangeHeight *uint64) error {
	err := dispatch.VerifyDispatchProof(r.cfg.ChainID, name, raw, servicekey.ProofOptions(ctx, r.cfg.Keys, r.cfg.AddressPrefix, earliestSubmitHeight, ticketBoundChangeHeight))
	if errors.Is(err, servicekey.ErrAuthority) {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return err
}

// holdsOutput reports whether this Builder keeps output replicas: it serves streamed output.
func (r *Receiver) holdsOutput() bool { return r.cfg.OutputConfig.MaxLeaves != 0 }

// serviceKey is operator's current service key of the participant type.
func (r *Receiver) serviceKey(ctx context.Context, participant, operator string) ([]byte, error) {
	key, _, err := servicekey.Current(ctx, r.cfg.Keys, r.cfg.AddressPrefix, participant, operator)
	switch {
	case errors.Is(err, servicekey.ErrAuthority):
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	case err != nil:
		return nil, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}
	return key, nil
}

// admit decides from local state whether a batch may be looked at: a new order's group is the
// current snapshot (checkGroup); once an order's stream began it keeps the group it began with, as
// the chain keeps the group it locks a recorded task with.
func (r *Receiver) admit(batch *nexusv1.BuilderSyncBatchV1, key string) error {
	m, found, err := r.loadMember(key)
	switch {
	case err != nil:
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	case !found:
		return r.checkGroup(batch)
	case m.BuilderSetID != batch.GetBuilderSetId() || !bytes.Equal(m.BuilderSetHash, batch.GetBuilderSetHash()):
		return fmt.Errorf("%w: the order's sync stream names BuilderSet %q", ErrMalformed, m.BuilderSetID)
	}
	return nil
}

// checkGroup requires the BuilderSet of a new order's batch to be the current snapshot with both
// the sender and this Builder among its members: the order's group.
func (r *Receiver) checkGroup(batch *nexusv1.BuilderSyncBatchV1) error {
	current, previous, ok := r.observeSnapshot()
	if !ok {
		return fmt.Errorf("%w: no current BuilderSet snapshot", ErrUnavailable)
	}
	snapshot := current
	if !names(batch, current) {
		// An order dispatched just before the snapshot was replaced may sync its first batch after.
		if previous == nil || !names(batch, *previous) {
			return fmt.Errorf("%w: batch names BuilderSet %q, current is %q", ErrNotGroupMember, batch.GetBuilderSetId(), current.ID)
		}
		snapshot = *previous
	}
	if !slices.Contains(snapshot.Members, batch.GetSenderOperatorAddress()) || !slices.Contains(snapshot.Members, r.cfg.Builder) {
		return fmt.Errorf("%w: sender or receiver is not a member of BuilderSet %q", ErrNotGroupMember, snapshot.ID)
	}
	return nil
}

func names(batch *nexusv1.BuilderSyncBatchV1, s taskgroup.Snapshot) bool {
	return s.ID == batch.GetBuilderSetId() && bytes.Equal(s.Hash[:], batch.GetBuilderSetHash())
}

// defaultPreviousSnapshotBlocks is ReceiverConfig.PreviousSnapshotBlocks when unset.
const defaultPreviousSnapshotBlocks = 600

// observeSnapshot returns the current snapshot and, within PreviousSnapshotBlocks of its
// replacement, the one current before it, as far as this receiver saw them.
func (r *Receiver) observeSnapshot() (taskgroup.Snapshot, *taskgroup.Snapshot, bool) {
	current, ok := r.cfg.Groups.CurrentBuilderSet()
	if !ok {
		return taskgroup.Snapshot{}, nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	head := r.head.Load()
	if r.current == nil || r.current.ID != current.ID || r.current.Hash != current.Hash {
		r.previous, r.current, r.replacedAt = r.current, &current, head
	}
	if r.previous == nil || head > r.replacedAt+r.cfg.PreviousSnapshotBlocks {
		return current, nil, true
	}
	return current, r.previous, true
}

// apply checks and applies one item on a copy of m and stores it with the item's digest; it returns
// the copy.
func (r *Receiver) apply(ctx context.Context, m *memberStream, item *nexusv1.BuilderSyncItemV1, digest []byte) (*memberStream, error) {
	next := m.clone()
	next.Applied = item.GetSequence()
	next.appliedDigest = digest
	var err error
	switch it := item.GetItem().(type) {
	case *nexusv1.BuilderSyncItemV1_Round:
		err = r.applyRound(ctx, next, it.Round)
	case *nexusv1.BuilderSyncItemV1_InputChunk:
		err = r.applyInput(ctx, next, it.InputChunk)
	case *nexusv1.BuilderSyncItemV1_Attempt:
		err = r.applyAttempt(ctx, next, it.Attempt)
	case *nexusv1.BuilderSyncItemV1_Record:
		err = r.applyRecord(ctx, next, it.Record)
	case *nexusv1.BuilderSyncItemV1_Order:
		err = r.applyOrder(ctx, next, it.Order)
	default:
		err = errors.New("unknown item")
	}
	if err != nil {
		return nil, err
	}
	next.appliedDigest = nil
	return next, nil
}

// copies are the sender's copies of a task in an epoch, one per binding generation.
func (r *Receiver) copies(m *memberStream, taskID string, epoch uint64) ([]*dispatchevidence.Order, error) {
	orders, err := r.cfg.Evidence.ByTask(taskID)
	if err != nil {
		return nil, fmt.Errorf("%w: evidence: %v", ErrUnavailable, err)
	}
	var out []*dispatchevidence.Order
	for _, o := range orders {
		if o.Builder == m.Sender && o.SessionID == m.SessionID && o.Sequence == m.Sequence && o.Epoch == epoch {
			out = append(out, o)
		}
	}
	return out, nil
}

// copyOf is the sender's copy of a task in an epoch and binding generation; nil when not held.
func (r *Receiver) copyOf(m *memberStream, taskID string, epoch, boundChangeHeight uint64) (*dispatchevidence.Order, error) {
	orders, err := r.copies(m, taskID, epoch)
	if err != nil {
		return nil, err
	}
	for _, o := range orders {
		if o.BoundChangeHeight == boundChangeHeight {
			return o, nil
		}
	}
	return nil, nil
}

// latestCopy is the sender's copy of a task in an epoch with the latest binding generation; nil
// when none is held.
func (r *Receiver) latestCopy(m *memberStream, taskID string, epoch uint64) (*dispatchevidence.Order, error) {
	orders, err := r.copies(m, taskID, epoch)
	if err != nil || len(orders) == 0 {
		return nil, err
	}
	return slices.MaxFunc(orders, func(a, b *dispatchevidence.Order) int { return cmp.Compare(a.BoundChangeHeight, b.BoundChangeHeight) }), nil
}

// put stores the copy o with m (and extra) in one write.
func (r *Receiver) put(o *dispatchevidence.Order, m *memberStream, extra ...kv.WriteOp) error {
	m.ExpireHeight = max(m.ExpireHeight, r.cfg.Retention(o))
	ops, err := memberOps(m)
	if err != nil {
		return err
	}
	if err := r.cfg.Evidence.Put(o, append(extra, ops...)...); err != nil {
		return fmt.Errorf("%w: store the copy: %v", ErrUnavailable, err)
	}
	return nil
}

func (r *Receiver) store(m *memberStream, extra ...kv.WriteOp) error {
	ops, err := memberOps(m)
	if err != nil {
		return err
	}
	if err := r.cfg.Store.WriteBatch(append(extra, ops...)...); err != nil {
		return fmt.Errorf("%w: store the sync stream: %v", ErrUnavailable, err)
	}
	return nil
}

// applyRound adds a round to the copy: its roster must hash to its roster_hash and its root must
// be signed by the sender, under the key generation the root's nonce selects for the order
// version's earliest_submit_height.
func (r *Receiver) applyRound(ctx context.Context, m *memberStream, round *nexusv1.BuilderSyncRoundV1) error {
	if len(round.GetTaskId()) != 32 || len(round.GetTaskHash()) != 32 || len(round.GetRosterHash()) != 32 {
		return errors.New("round task_id, task_hash or roster_hash is not 32 bytes")
	}
	taskID := hex.EncodeToString(round.GetTaskId())
	if m.TaskID != "" && m.TaskID != taskID {
		return fmt.Errorf("round names task %s, the order's is %s", taskID, m.TaskID)
	}
	if round.GetUserAddress() == "" || m.User != "" && m.User != round.GetUserAddress() {
		return errors.New("round names no user, or another user than the order's earlier rounds")
	}
	rosterRaw, err := marshal(round.GetRoster())
	if err != nil {
		return err
	}
	candidate := dispatchevidence.Round{Number: round.GetDispatchRound(), Roster: rosterRaw, RosterHash: round.GetRosterHash()}
	check := &dispatchevidence.Order{Rounds: []dispatchevidence.Round{candidate}}
	if _, ok := check.RosterFor(r.cfg.ChainID, candidate.Number, candidate.RosterHash); !ok {
		return errors.New("roster does not hash to roster_hash")
	}
	if !bytes.Equal(round.GetRoster().GetTaskId(), round.GetTaskId()) {
		return errors.New("roster is not the task's")
	}
	taskHash := hex.EncodeToString(round.GetTaskHash())
	esh := round.GetEarliestSubmitHeight()
	if held, ok := m.Submit[taskHash]; ok && held != esh {
		return fmt.Errorf("round names earliest_submit_height %d, the order version's earlier rounds %d", esh, held)
	}
	root := round.GetHandraiseRoot()
	if root.GetChainId() != r.cfg.ChainID || root.GetBuilderAddress() != m.Sender {
		return errors.New("handraise root is not the sender's on this chain")
	}
	rootRaw, err := marshal(root)
	if err != nil {
		return err
	}
	rootDigest, err := signingDigest(rootName, rootRaw)
	if err != nil {
		return err
	}
	if err := r.verifyProof(ctx, rootName, rootRaw, &esh, nil); err != nil {
		return fmt.Errorf("handraise root is not signed by the sender: %w", err)
	}
	if m.Submit == nil {
		m.Submit = map[string]uint64{}
	}
	m.Submit[taskHash] = esh
	candidate.RootDigest, candidate.SignedRoot = rootDigest[:], rootRaw
	// A round names no bound_change_height: it waits in the stream until its first ticket names the
	// binding generation whose copy it joins (takeRound). A round number the latest generation
	// already holds starts a new one (a takeover back to the sender in the same epoch restarts the
	// rounds from 0); any other round continues the latest and carries its task_hash.
	latest, err := r.latestCopy(m, taskID, round.GetVrfEpoch())
	if err != nil {
		return err
	}
	if latest != nil && latest.TaskHash != taskHash {
		if _, held := latest.Round(candidate.Number); !held {
			return fmt.Errorf("round names task_hash %s, the task's earlier rounds %s", taskHash, latest.TaskHash)
		}
	}
	pending := pendingRound{TaskID: taskID, TaskHash: taskHash, Epoch: round.GetVrfEpoch(), Round: candidate}
	if slices.ContainsFunc(m.Rounds, pending.same) {
		return fmt.Errorf("round %d is held already", candidate.Number)
	}
	m.Rounds = append(m.Rounds, pending)
	m.TaskID, m.User = taskID, round.GetUserAddress()
	index := kv.WriteOp{NS: kv.NSBuilderSyncMember, Key: memberTaskPrefix + taskID, Val: []byte(m.key())}
	return r.store(m, index)
}

// takeRound returns the copy and round a ticket binds: the round held in the copy of the ticket's
// binding generation, or the round waiting in the stream with the ticket's number, roster_hash and
// root, which then joins that copy (created for the first ticket of a generation). The copy is not
// stored here.
func (r *Receiver) takeRound(m *memberStream, ticket *taskv1.DispatchTicketV1) (*dispatchevidence.Order, *dispatchevidence.Round, error) {
	taskID, taskHash, number := hex.EncodeToString(ticket.GetTaskId()), hex.EncodeToString(ticket.GetTaskHash()), ticket.GetDispatchRound()
	o, err := r.copyOf(m, taskID, ticket.GetVrfEpoch(), ticket.GetBoundChangeHeight())
	if err != nil {
		return nil, nil, err
	}
	if o != nil {
		if round, held := o.Round(number); held {
			if !bytes.Equal(round.RosterHash, ticket.GetRosterHash()) || !bytes.Equal(round.RootDigest, ticket.GetHandraiseRootDigest()) {
				return nil, nil, fmt.Errorf("ticket's round %d is not held with its roster_hash and root", number)
			}
			if taskHash != o.TaskHash {
				return nil, nil, errors.New("ticket's task_hash is not its round's")
			}
			return o, round, nil
		}
	}
	i := slices.IndexFunc(m.Rounds, func(p pendingRound) bool {
		return p.TaskID == taskID && p.Epoch == ticket.GetVrfEpoch() && p.Round.Number == number &&
			bytes.Equal(p.Round.RosterHash, ticket.GetRosterHash()) && bytes.Equal(p.Round.RootDigest, ticket.GetHandraiseRootDigest())
	})
	switch {
	case i < 0 && o == nil:
		return nil, nil, errors.New("ticket of a round not held")
	case i < 0:
		return nil, nil, fmt.Errorf("ticket's round %d is not held with its roster_hash and root", number)
	case m.Rounds[i].TaskHash != taskHash:
		return nil, nil, errors.New("ticket's task_hash is not its round's")
	}
	if o == nil {
		o = &dispatchevidence.Order{Builder: m.Sender, SessionID: m.SessionID, Sequence: m.Sequence, TaskID: taskID, Epoch: ticket.GetVrfEpoch(),
			BoundChangeHeight: ticket.GetBoundChangeHeight()}
	}
	if o.TaskHash != "" && o.TaskHash != taskHash {
		return nil, nil, fmt.Errorf("round names task_hash %s, the task's earlier rounds %s", taskHash, o.TaskHash)
	}
	o.TaskHash = taskHash
	o.DeadlineBase = max(o.DeadlineBase, m.Submit[taskHash])
	o.Rounds = append(o.Rounds, m.Rounds[i].Round)
	slices.SortFunc(o.Rounds, func(a, b dispatchevidence.Round) int { return int(a.Number) - int(b.Number) })
	m.Rounds = slices.Delete(m.Rounds, i, i+1)
	round, _ := o.Round(number)
	return o, round, nil
}

// applyInput takes a piece of an order version's input; once whole, the input must hash to its
// input_hash and is stored with the task data.
func (r *Receiver) applyInput(ctx context.Context, m *memberStream, c *nexusv1.BuilderSyncInputChunkV1) error {
	if m.TaskID == "" {
		return errors.New("input before the order's first round")
	}
	if len(c.GetTaskHash()) != 32 || len(c.GetInputHash()) != 32 {
		return errors.New("input task_hash or input_hash is not 32 bytes")
	}
	taskHash := hex.EncodeToString(c.GetTaskHash())
	input := m.Inputs[taskHash]
	if input == nil {
		// An input over what this Builder stores is not held; the rest of the order still syncs, since
		// the input copy is only a fallback for the Worker.
		input = &memberInput{InputHash: c.GetInputHash(), Size: c.GetInputSizeBytes(), Skipped: c.GetInputSizeBytes() > r.cfg.MaxInputBytes}
		m.Inputs[taskHash] = input
		if input.Skipped {
			r.log.Warn("synced input is over what this Builder stores; it is not held", "order", m.key(), "task_hash", taskHash,
				"size", input.Size, "max", r.cfg.MaxInputBytes)
		}
	}
	switch {
	case input.Stored:
		return errors.New("input is stored already")
	case !bytes.Equal(input.InputHash, c.GetInputHash()) || input.Size != c.GetInputSizeBytes():
		return errors.New("input piece names another input")
	case c.GetOffset() != input.Received:
		return fmt.Errorf("input piece at %d, %d bytes are held", c.GetOffset(), input.Received)
	case input.Received+uint64(len(c.GetData())) > input.Size:
		return errors.New("input piece runs past the input size")
	case len(c.GetData()) == 0 && input.Size != 0:
		return errors.New("empty input piece")
	}
	input.Received += uint64(len(c.GetData()))
	if input.Skipped {
		return r.store(m)
	}
	if input.Received < input.Size {
		input.Offsets = append(input.Offsets, c.GetOffset())
		piece := kv.WriteOp{NS: kv.NSBuilderSyncMember, Key: inputPieceKey(m.key(), taskHash, c.GetOffset()), Val: c.GetData()}
		return r.store(m, piece)
	}
	data := make([]byte, 0, input.Size)
	var ops []kv.WriteOp
	for _, offset := range input.Offsets {
		key := inputPieceKey(m.key(), taskHash, offset)
		piece, found, err := r.cfg.Store.GetWithError(kv.NSBuilderSyncMember, key)
		if err != nil || !found {
			return fmt.Errorf("%w: input piece at %d not read (%v)", ErrUnavailable, offset, err)
		}
		data = append(data, piece...)
		ops = append(ops, kv.WriteOp{NS: kv.NSBuilderSyncMember, Key: key, Delete: true})
	}
	data = append(data, c.GetData()...)
	if got := sha256.Sum256(data); !bytes.Equal(got[:], input.InputHash) {
		return errors.New("input does not hash to its input_hash")
	}
	if input.Size > 0 {
		inputHash := hex.EncodeToString(input.InputHash)
		header := taskdata.UploadHeader{
			Key: taskdata.ObjectKey{
				TaskHash: taskHash, SessionID: m.SessionID, TaskID: m.TaskID, Kind: taskdata.ObjectKindInput,
				ContentHash: taskdata.InputContentHash(inputHash),
			},
			SizeBytes: input.Size, SemanticHash: inputHash, MediaType: c.GetMediaType(), RetainUntilHeight: max(m.ExpireHeight, 1),
		}
		if err := r.cfg.Inputs.PutInput(ctx, header, data); err != nil {
			return fmt.Errorf("store the input: %w", err)
		}
	}
	input.Stored, input.Offsets = true, nil
	return r.store(m, ops...)
}

// applyAttempt adds or updates a ticket in the copy: signed by the sender for this order, in a
// round held with its roster_hash and root, with the answers its target gave (signed by it).
func (r *Receiver) applyAttempt(ctx context.Context, m *memberStream, a *nexusv1.BuilderSyncAttemptV1) error {
	ticket := a.GetTicket()
	ticketRaw, err := marshal(ticket)
	if err != nil {
		return err
	}
	hash, err := r.checkTicket(ctx, m, ticketRaw, ticket)
	if err != nil {
		return err
	}
	o, round, err := r.takeRound(m, ticket)
	if err != nil {
		return err
	}
	if input := m.Inputs[hex.EncodeToString(ticket.GetTaskHash())]; input != nil && !bytes.Equal(input.InputHash, ticket.GetInputHash()) {
		return errors.New("ticket's input_hash is not the synced input's")
	}
	target := ticket.GetTarget().GetOperatorAddress()
	if target == "" {
		return errors.New("ticket names no target")
	}
	bound := ticket.GetBoundChangeHeight()
	var rejectRaw []byte
	if reject := a.GetReject(); reject != nil {
		if a.GetOutcome() != taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_REJECTED {
			return errors.New("reject of an attempt that is not REJECTED")
		}
		if !bytes.Equal(reject.GetDispatchTicketHash(), hash[:]) || reject.GetMember().GetOperatorAddress() != target {
			return errors.New("reject is not the target's reject of the ticket")
		}
		if rejectRaw, err = marshal(reject); err != nil {
			return err
		}
		// A rebuttal carries the reject: one that does not verify, under the key generation its
		// nonce selects for the order, would only cost a refused tx. The target may have rotated
		// twice since it signed, or have no usable key any more (deregistered), so the reject is
		// dropped rather than the order's sync stopped: the attempt stays REJECTED, without the
		// reject a rebuttal needs. Only a chain that cannot be read leaves the batch to be sent
		// again.
		switch err := r.verifyProof(ctx, rejectName, rejectRaw, m.submitOf(ticket.GetTaskHash()), &bound); {
		case errors.Is(err, ErrUnavailable):
			return fmt.Errorf("reject signer: %w", err)
		case err != nil:
			r.log.Warn("synced reject does not verify under its target's key; kept without it, so this member cannot rebut a claim on the ticket",
				"session_id", m.SessionID, "sequence", m.Sequence, "ticket", hex.EncodeToString(hash[:]), "target", target, "err", err)
			rejectRaw = nil
		}
	}
	var acceptRaw, lateAcceptRaw []byte
	acceptUnverified := false
	for _, x := range []struct {
		accept *taskv1.DispatchAcceptV1
		raw    *[]byte
	}{{a.GetLateAccept(), &lateAcceptRaw}, {a.GetAccept(), &acceptRaw}} {
		if x.accept == nil {
			continue
		}
		if !bytes.Equal(x.accept.GetDispatchTicketHash(), hash[:]) || x.accept.GetMember().GetOperatorAddress() != target ||
			!bytes.Equal(x.accept.GetTaskHash(), ticket.GetTaskHash()) {
			return errors.New("accept is not the target's accept of the ticket")
		}
		if *x.raw, err = marshal(x.accept); err != nil {
			return err
		}
		// The accept is the target's dispatch proof, verified under the key generation its nonce
		// selects for the order. The winner's accept is the order's evidence: a bad signature is
		// refused, while one whose signer has no resolvable key any more (it never will again) is
		// kept marked unverified rather than stop the order's sync for good. A late accept that
		// does not verify is dropped, as a reject is.
		switch err := r.verifyProof(ctx, acceptName, *x.raw, m.submitOf(ticket.GetTaskHash()), &bound); {
		case err == nil:
		case errors.Is(err, ErrUnavailable):
			return fmt.Errorf("accept signer: %w", err)
		case x.raw == &acceptRaw && errors.Is(err, dispatch.ErrProofKeyUnavailable):
			r.log.Warn("synced winner accept cannot be verified: its signer has no resolvable key; kept unverified",
				"session_id", m.SessionID, "sequence", m.Sequence, "ticket", hex.EncodeToString(hash[:]), "target", target, "err", err)
			acceptUnverified = true
		case x.raw == &acceptRaw:
			return fmt.Errorf("accept is not signed by its target: %w", err)
		default:
			r.log.Warn("synced late accept does not verify under its target's key; kept without it",
				"session_id", m.SessionID, "sequence", m.Sequence, "ticket", hex.EncodeToString(hash[:]), "target", target, "err", err)
			*x.raw = nil
		}
	}
	if a.GetOutcome() == outcomeAccepted {
		if acceptRaw == nil {
			return errors.New("ACCEPTED attempt without its accept")
		}
		o.Accept, o.AcceptUnverified = acceptRaw, acceptUnverified
	} else if len(o.Accept) > 0 {
		// A winner voided by a binding change is no winner any more.
		var accept taskv1.DispatchAcceptV1
		if proto.Unmarshal(o.Accept, &accept) == nil && bytes.Equal(accept.GetDispatchTicketHash(), hash[:]) {
			o.Accept, o.AcceptUnverified = nil, false
		}
	}
	attempt := dispatchevidence.Attempt{
		Ticket: ticketRaw, Hash: hash[:], Rank: ticket.GetRank(), Operator: target, Sent: a.GetSent(), Outcome: a.GetOutcome(),
		Reject: rejectRaw, LateAccept: lateAcceptRaw,
	}
	if i := slices.IndexFunc(round.Attempts, func(x dispatchevidence.Attempt) bool { return bytes.Equal(x.Hash, hash[:]) }); i >= 0 {
		round.Attempts[i] = attempt
	} else {
		round.Attempts = append(round.Attempts, attempt)
		slices.SortFunc(round.Attempts, func(x, y dispatchevidence.Attempt) int { return int(x.Rank) - int(y.Rank) })
	}
	o.DeadlineBase = max(o.DeadlineBase, ticket.GetBoundChangeHeight())
	return r.put(o, m)
}

// checkTicket checks a ticket is the sender's, for this order on this chain, and returns its
// dispatch_ticket_hash.
func (r *Receiver) checkTicket(ctx context.Context, m *memberStream, raw []byte, t *taskv1.DispatchTicketV1) ([32]byte, error) {
	if t.GetChainId() != r.cfg.ChainID || t.GetBuilderAddress() != m.Sender ||
		hex.EncodeToString(t.GetSessionId()) != m.SessionID || t.GetOrderSequence() != m.Sequence {
		return [32]byte{}, errors.New("ticket is not the sender's for this order")
	}
	if m.TaskID != "" && hex.EncodeToString(t.GetTaskId()) != m.TaskID {
		return [32]byte{}, errors.New("ticket names another task")
	}
	hash, err := signingDigest(ticketName, raw)
	if err != nil {
		return [32]byte{}, err
	}
	if err := r.verifyProof(ctx, ticketName, raw, m.submitOf(t.GetTaskHash()), nil); err != nil {
		return [32]byte{}, fmt.Errorf("ticket is not signed by the sender: %w", err)
	}
	return hash, nil
}

// applyRecord sets the signed record of an order version in the copy.
func (r *Receiver) applyRecord(ctx context.Context, m *memberStream, rec *nexusv1.BuilderSyncRecordV1) error {
	record := rec.GetRecord()
	recordRaw, err := marshal(record)
	if err != nil {
		return err
	}
	if record.GetChainId() != r.cfg.ChainID || record.GetBuilderAddress() != m.Sender ||
		hex.EncodeToString(record.GetSessionId()) != m.SessionID || record.GetOrderSequence() != m.Sequence {
		return errors.New("record is not the sender's for this order")
	}
	// The record's own bound_change_height only finds the copy of its generation; the tickets it
	// lists must be held there.
	o, err := r.copyOf(m, hex.EncodeToString(record.GetTaskId()), record.GetVrfEpoch(), record.GetBoundChangeHeight())
	if err != nil {
		return err
	}
	if o == nil {
		return errors.New("record of an order version not held")
	}
	// The record proves under the binding of the tickets it lists, as held here, never under its
	// own signed bound_change_height.
	bound, err := recordBinding(o, record)
	if err != nil {
		return err
	}
	if err := r.verifyProof(ctx, recordName, recordRaw, m.submitOf(record.GetTaskHash()), &bound); err != nil {
		return fmt.Errorf("record is not signed by the sender: %w", err)
	}
	if hex.EncodeToString(record.GetTaskHash()) != o.TaskHash {
		return errors.New("record's task_hash is not its rounds'")
	}
	o.Record = recordRaw
	return r.put(o, m)
}

// recordBinding is the largest bound_change_height of the held tickets a record lists; every
// ticket it lists must be held, since the attempts of an order are synced before its record.
func recordBinding(o *dispatchevidence.Order, record *taskv1.DispatchRecordV1) (uint64, error) {
	var bound uint64
	listed := false
	for _, round := range record.GetRounds() {
		for _, a := range round.GetAttempts() {
			held, ok := o.Attempt(a.GetDispatchTicketHash())
			var ticket taskv1.DispatchTicketV1
			if !ok || proto.Unmarshal(held.Ticket, &ticket) != nil {
				return 0, fmt.Errorf("record lists ticket %x, not held", a.GetDispatchTicketHash())
			}
			bound, listed = max(bound, ticket.GetBoundChangeHeight()), true
		}
	}
	if !listed {
		return 0, errors.New("record lists no ticket")
	}
	return bound, nil
}

// applyOrder takes the user's order once the chain recorded it: the chain's record must name the
// winner of the sender's RECORDED header, a ticket held in the copy, the header's accept must be
// the winner's, and the order's earliest_submit_height the one its rounds named.
func (r *Receiver) applyOrder(ctx context.Context, m *memberStream, item *nexusv1.BuilderSyncOrderV1) error {
	signed := item.GetSignedOrder()
	signedRaw, err := marshal(signed)
	if err != nil {
		return err
	}
	order := signed.GetOrder()
	if hex.EncodeToString(order.GetSessionId()) != m.SessionID || order.GetOrderSequence() != m.Sequence ||
		order.GetBuilderSetId() != m.BuilderSetID || !bytes.Equal(order.GetBuilderSetHash(), m.BuilderSetHash) ||
		order.GetUserAddress() != m.User {
		return errors.New("signed order is not this order of the group's BuilderSet and user")
	}
	header := item.GetResultHeader()
	headerRaw, err := marshal(header)
	if err != nil {
		return err
	}
	if header.GetRecordStatus() != taskv1.DispatchRecordStatusV1_DISPATCH_RECORD_STATUS_V1_RECORDED {
		return fmt.Errorf("result header is %s, not RECORDED", header.GetRecordStatus())
	}
	winnerRaw, err := marshal(header.GetWinnerTicket())
	if err != nil {
		return err
	}
	winnerHash, err := signingDigest(ticketName, winnerRaw)
	if err != nil {
		return err
	}
	ev, held, found, err := r.cfg.Evidence.ByTicket(winnerHash[:])
	if err != nil {
		return fmt.Errorf("%w: evidence: %v", ErrUnavailable, err)
	}
	if !found || ev.Builder != m.Sender || ev.SessionID != m.SessionID || ev.Sequence != m.Sequence {
		return errors.New("result header's winner is not a ticket of the order held here")
	}
	if err := r.checkUserOrder(ctx, m, signed, ev.TaskHash); err != nil {
		return err
	}
	// The rounds named the order version's earliest_submit_height, which chose the key generation
	// their material was verified under; the signed order (its task_hash, checked above) is the
	// authority for it.
	esh := order.GetEarliestSubmitHeight()
	named, ok := m.Submit[ev.TaskHash]
	switch {
	case !ok:
		return errors.New("no round of the recorded order version is held here")
	case named != esh:
		return fmt.Errorf("the order's rounds named earliest_submit_height %d, the signed order's is %d", named, esh)
	}
	// The header is the winner ticket's Builder's (the sender's, checked above) dispatch proof,
	// relayed with its original bytes: its signed nonce selects the key generation, the previous
	// one only for an order below that key's retirement.
	if err := r.verifyProof(ctx, resultHeaderName, headerRaw, &esh, nil); err != nil {
		if errors.Is(err, ErrUnavailable) {
			return fmt.Errorf("result header signer: %w", err)
		}
		return fmt.Errorf("result header is not signed by the sender: %w", err)
	}
	acceptRaw, err := marshal(header.GetAccept())
	if err != nil {
		return err
	}
	acceptUnverified := false
	winnerBound := header.GetWinnerTicket().GetBoundChangeHeight()
	switch err := r.verifyProof(ctx, acceptName, acceptRaw, &esh, &winnerBound); {
	case err == nil:
	case errors.Is(err, ErrUnavailable):
		return fmt.Errorf("result header's accept signer: %w", err)
	case errors.Is(err, dispatch.ErrProofKeyUnavailable):
		// As for the attempt's accept: no resolvable key will ever check it again.
		r.log.Warn("synced result header's accept cannot be verified: its signer has no resolvable key; kept unverified",
			"session_id", m.SessionID, "sequence", m.Sequence, "worker", held.Operator, "err", err)
		acceptUnverified = true
	default:
		return fmt.Errorf("result header's accept is not signed by the winner: %w", err)
	}
	acceptDigest, err := signingDigest(acceptName, acceptRaw)
	if err != nil {
		return err
	}
	if !bytes.Equal(header.GetAccept().GetDispatchTicketHash(), winnerHash[:]) || header.GetAccept().GetMember().GetOperatorAddress() != held.Operator ||
		!bytes.Equal(header.GetTaskId(), header.GetWinnerTicket().GetTaskId()) || !bytes.Equal(header.GetWinnerTicket().GetInputHash(), order.GetInputHash()) {
		return errors.New("result header does not hold the winner's accept of this order")
	}
	record, err := r.cfg.Chain.QueryDispatchRecordByOrder(ctx, m.SessionID, m.Sequence)
	switch {
	case errors.Is(err, chaincli.ErrNotFound):
		return errors.New("the chain holds no record of the order yet")
	case err != nil:
		return fmt.Errorf("%w: chain record: %v", ErrUnavailable, err)
	case !bytes.Equal(record.GetDispatchTicketHash(), winnerHash[:]):
		return errors.New("the chain recorded another winner")
	}
	ev.SignedOrder = signedRaw
	ev.AcceptUnverified = ev.AcceptUnverified || acceptUnverified
	ev.Recorded, ev.RecordedHeight = true, record.GetRecordedHeight()
	ev.DeadlineBase = max(ev.DeadlineBase, order.GetEarliestSubmitHeight())
	m.Recorded, m.RecordedHeight = true, record.GetRecordedHeight()
	m.Winner = &memberWinner{
		TaskHash: ev.TaskHash, TicketHash: winnerHash[:], Ticket: held.Ticket, Accept: acceptRaw, AcceptDigest: acceptDigest[:],
		Worker: held.Operator, Header: headerRaw, User: order.GetUserAddress(),
	}
	index := kv.WriteOp{NS: kv.NSBuilderSyncMember, Key: memberTaskPrefix + ev.TaskID, Val: []byte(m.key())}
	return r.put(ev, m, index)
}

// checkUserOrder checks a synced SignedOrderV2 is the order the winner's tickets were issued for
// (its task_hash) and, with FeeDenom set, that its user signed it: the signature recovers to the
// user's wallet, or to the session's registered key. A registered key set after the order's
// session_anchor_height may have replaced the one that signed: the order is then kept (the chain
// judged the key at the order's height) and a warning logged.
func (r *Receiver) checkUserOrder(ctx context.Context, m *memberStream, signed *taskv1.SignedOrderV2, taskHash string) error {
	orderHash, err := nodecontract.TaskOrderHashHexV3(signed.GetOrder())
	if err != nil {
		return fmt.Errorf("signed order: %w", err)
	}
	if orderHash != taskHash {
		return errors.New("signed order's task_hash is not the recorded winner's")
	}
	if r.cfg.FeeDenom == "" {
		return nil
	}
	recovered, wallet, err := registeredkey.OrderSigner(signed, r.cfg.FeeDenom)
	if err != nil {
		return fmt.Errorf("signed order's user signature: %w", err)
	}
	if wallet {
		return nil
	}
	order := signed.GetOrder()
	if r.cfg.SessionKeys == nil {
		return errors.New("signed order is not signed by its user's wallet, and session keys cannot be read here")
	}
	state, err := r.cfg.SessionKeys.Lookup(ctx, m.SessionID, r.head.Load())
	if err != nil {
		return fmt.Errorf("%w: session key: %v", ErrUnavailable, err)
	}
	switch {
	case !state.Found || state.Owner != order.GetUserAddress():
		return errors.New("signed order is not signed by its user's wallet, and the session has no key of its user")
	case state.Key != nil && *state.Key == recovered:
		return nil
	case state.SetHeight > order.GetSessionAnchorHeight():
		r.log.Warn("synced order is signed by a key other than the session's current one, which was set after the order; kept",
			"order", m.key(), "key_set_height", state.SetHeight, "session_anchor_height", order.GetSessionAnchorHeight())
		return nil
	default:
		return errors.New("signed order is signed by neither its user's wallet nor the session's registered key")
	}
}

// replicaKey is the OUTPUT key of the recorded winner's replica.
func (r *Receiver) replicaKey(m *memberStream) taskdata.ObjectKey {
	return taskdata.ObjectKey{TaskHash: m.Winner.TaskHash, SessionID: m.SessionID, TaskID: m.TaskID, Kind: taskdata.ObjectKindOutput}
}

// applyOutput appends the recorded winner's frames to the replica: each must carry the winner's
// ticket and be signed by the winner's current service key; the batch must name the winner ticket
// and accept the order item named.
func (r *Receiver) applyOutput(ctx context.Context, m *memberStream, out *nexusv1.BuilderSyncOutputV1) error {
	if !m.Recorded || m.Winner == nil {
		return errors.New("output before the order was recorded")
	}
	w := m.Winner
	winnerRaw, err := marshal(out.GetWinnerTicket())
	if err != nil {
		return err
	}
	ticketHash, err := signingDigest(ticketName, winnerRaw)
	if err != nil {
		return err
	}
	if !bytes.Equal(out.GetDispatchTicketHash(), w.TicketHash) || !bytes.Equal(ticketHash[:], w.TicketHash) ||
		!bytes.Equal(out.GetDispatchAcceptDigest(), w.AcceptDigest) {
		return errors.New("output is not of the recorded winner's ticket and accept")
	}
	workerKey, err := r.serviceKey(ctx, servicekey.ParticipantCortex, w.Worker)
	if err != nil {
		return err
	}
	taskHash := [32]byte(mustHex(w.TaskHash))
	key := r.replicaKey(m)
	stream, err := r.replica(ctx, key, w)
	if err != nil {
		return err
	}
	progress := stream.Progress()
	if progress.Sealed {
		return nil
	}
	for _, c := range out.GetChunks() {
		if progress.Received && c.GetSeq() <= progress.LastSeq {
			continue
		}
		if !bytes.Equal(c.GetDispatchTicketHash(), w.TicketHash) || len(c.GetMmrRoot()) != 32 {
			return r.dropReplica(key, fmt.Errorf("chunk %d is not the winner ticket's", c.GetSeq()))
		}
		digest := dispatch.OutputChunkDigest(r.cfg.ChainID, taskHash, ticketHash, c.GetSeq(), [32]byte(c.GetMmrRoot()))
		if dispatch.VerifyDigestSignature(workerKey, digest[:], c.GetWorkerSignature()) != nil {
			return r.dropReplica(key, fmt.Errorf("chunk %d is not signed by the winner", c.GetSeq()))
		}
		chunk := taskdata.OutputChunk{
			Seq: c.GetSeq(), Text: c.GetText(), MMRRoot: c.GetMmrRoot(), WorkerSignature: c.GetWorkerSignature(),
			Attachment: c.GetAttachment(), AttachmentSignature: c.GetAttachmentSignature(),
			DispatchTicketHash: c.GetDispatchTicketHash(), CumulativeGeneratedTokens: c.GetCumulativeGeneratedTokens(),
		}
		if _, err := stream.Append(ctx, chunk); err != nil {
			return r.dropReplica(key, fmt.Errorf("chunk %d: %w", c.GetSeq(), err))
		}
		progress = stream.Progress()
		r.cfg.Publish(key, taskdata.OutputFrame{Chunk: &chunk})
	}
	if f := out.GetFin(); f != nil {
		if len(f.GetOutputMmrRoot()) != 32 || !bytes.Equal(f.GetDispatchTicketHash(), w.TicketHash) {
			return r.dropReplica(key, errors.New("fin is not the winner ticket's"))
		}
		digest, err := dispatch.OutputFinDigest(r.cfg.ChainID, taskHash, ticketHash, f.GetFinalSeq(), [32]byte(f.GetOutputMmrRoot()), uint32(f.GetFinishReason()))
		if err != nil || dispatch.VerifyDigestSignature(workerKey, digest[:], f.GetWorkerSignature()) != nil {
			return r.dropReplica(key, errors.New("fin is not signed by the winner"))
		}
		fin := taskdata.OutputFin{
			FinalSeq: f.GetFinalSeq(), OutputMMRRoot: f.GetOutputMmrRoot(), FinishReason: uint32(f.GetFinishReason()),
			WorkerSignature: f.GetWorkerSignature(), DispatchTicketHash: f.GetDispatchTicketHash(),
		}
		if _, err := stream.Finish(ctx, fin); err != nil {
			return r.dropReplica(key, fmt.Errorf("fin: %w", err))
		}
		r.forgetReplica(key)
		r.cfg.Publish(key, taskdata.OutputFrame{Fin: &fin})
	}
	return nil
}

func replicaHandleKey(key taskdata.ObjectKey) string { return key.SessionID + "|" + key.TaskID }

// replica returns the open replica stream of a task, opening (or resuming) it.
func (r *Receiver) replica(ctx context.Context, key taskdata.ObjectKey, w *memberWinner) (*taskdata.OutputStream, error) {
	r.mu.Lock()
	stream := r.replicas[replicaHandleKey(key)]
	r.mu.Unlock()
	if stream != nil {
		return stream, nil
	}
	stream, _, err := r.cfg.Outputs.OpenReplicaStream(ctx, key, w.Worker, r.cfg.OutputConfig, w.TicketHash)
	if err != nil {
		return nil, fmt.Errorf("open the output replica: %w", err)
	}
	r.mu.Lock()
	r.replicas[replicaHandleKey(key)] = stream
	r.mu.Unlock()
	return stream, nil
}

// dropReplica closes the replica stream after a failed frame; it is reopened from its progress.
func (r *Receiver) dropReplica(key taskdata.ObjectKey, err error) error {
	r.mu.Lock()
	stream := r.replicas[replicaHandleKey(key)]
	delete(r.replicas, replicaHandleKey(key))
	r.mu.Unlock()
	if stream != nil {
		stream.Close()
	}
	return err
}

// forgetReplica drops the handle of a sealed replica.
func (r *Receiver) forgetReplica(key taskdata.ObjectKey) {
	r.mu.Lock()
	delete(r.replicas, replicaHandleKey(key))
	r.mu.Unlock()
}
