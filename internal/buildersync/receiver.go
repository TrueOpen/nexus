package buildersync

import (
	"bytes"
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

	buildersyncv1 "github.com/TrueOpen/nexus/gen/buildersync/v1"
	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatchevidence"
	"github.com/TrueOpen/nexus/internal/kv"
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
	// OutputConfig holds the network's output stream limits the replica is written under.
	OutputConfig taskdata.OutputStreamConfig
	// Publish hands a replica frame to the live subscribers of its task (taskdata.OutputDispatcher).
	Publish func(taskdata.ObjectKey, taskdata.OutputFrame)
	Chain   RecordReader
	// Retention is the last height a copy of an order's evidence is kept at
	// (dispatchevidence.Params.RetainUntil); the member's sync stream and stored input follow it.
	Retention func(*dispatchevidence.Order) uint64
	// MaxInputBytes bounds an order version's input.
	MaxInputBytes uint64
	Log           *slog.Logger
}

// Receiver applies the sync streams the dispatching Builders send this Builder as a member of
// their orders' Task Builders groups.
type Receiver struct {
	cfg ReceiverConfig
	log *slog.Logger

	mu       sync.Mutex
	locks    map[string]*sync.Mutex
	replicas map[string]*taskdata.OutputStream

	head      atomic.Uint64
	lastPrune atomic.Uint64
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

// Sync applies a batch. A batch that is not from a group member's dispatching Builder for this
// Builder fails with ErrMalformed, ErrUnauthenticated, ErrNotGroupMember or ErrUnavailable.
// Otherwise its items are applied in order from the one after the last applied, each checked
// first; the first that cannot be applied stops the batch and is named in the response, which
// always carries how far the order's items and output are held.
func (r *Receiver) Sync(ctx context.Context, req *buildersyncv1.SyncRequest) (*buildersyncv1.SyncResponse, error) {
	var batch buildersyncv1.BuilderSyncBatchV1
	if err := proto.Unmarshal(req.GetBatch(), &batch); err != nil {
		return nil, fmt.Errorf("%w: batch: %v", ErrMalformed, err)
	}
	switch {
	case batch.GetSchemaVersion() != schemaVersion:
		return nil, fmt.Errorf("%w: schema_version %d", ErrMalformed, batch.GetSchemaVersion())
	case batch.GetChainId() != r.cfg.ChainID:
		return nil, fmt.Errorf("%w: batch is for chain %q", ErrMalformed, batch.GetChainId())
	case batch.GetReceiverOperatorAddress() != r.cfg.Builder:
		return nil, fmt.Errorf("%w: batch is for %s", ErrMalformed, batch.GetReceiverOperatorAddress())
	case batch.GetSenderOperatorAddress() == "" || batch.GetSenderOperatorAddress() == r.cfg.Builder:
		return nil, fmt.Errorf("%w: sender", ErrMalformed)
	case len(batch.GetSessionId()) != 32:
		return nil, fmt.Errorf("%w: session_id", ErrMalformed)
	}
	sender := batch.GetSenderOperatorAddress()
	senderKey, err := r.serviceKey(ctx, servicekey.ParticipantBuilder, sender)
	if err != nil {
		return nil, err
	}
	digest := BatchDigest(r.cfg.ChainID, sender, req.GetBatch())
	if dispatch.VerifyDigestSignature(senderKey, digest[:], req.GetSenderSignature()) != nil {
		return nil, fmt.Errorf("%w: batch signature is not the sender's current service key", ErrUnauthenticated)
	}
	sessionID := hex.EncodeToString(batch.GetSessionId())
	key := memberKey(sender, sessionID, batch.GetOrderSequence())
	unlock := r.lock(key)
	defer unlock()
	m, found, err := r.loadMember(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	switch {
	case !found:
		// A new order's group is the current snapshot; once its stream began the order keeps the
		// group it began with, as the chain keeps the group it locks a recorded task with.
		if err := r.checkGroup(&batch); err != nil {
			return nil, err
		}
		m = &memberStream{Sender: sender, SessionID: sessionID, Sequence: batch.GetOrderSequence(),
			BuilderSetID: batch.GetBuilderSetId(), BuilderSetHash: batch.GetBuilderSetHash(), Inputs: map[string]*memberInput{}}
	case m.BuilderSetID != batch.GetBuilderSetId() || !bytes.Equal(m.BuilderSetHash, batch.GetBuilderSetHash()):
		return nil, fmt.Errorf("%w: the order's sync stream names BuilderSet %q", ErrMalformed, m.BuilderSetID)
	}
	resp := &buildersyncv1.SyncResponse{}
	in := &incoming{senderKey: senderKey}
	for _, item := range batch.GetItems() {
		if item.GetSequence() <= m.Applied {
			continue
		}
		if item.GetSequence() != m.Applied+1 {
			resp.Refused = fmt.Sprintf("item %d out of order: item %d is next", item.GetSequence(), m.Applied+1)
			break
		}
		next, err := r.apply(ctx, m, in, item)
		if err != nil {
			resp.Refused = fmt.Sprintf("item %d: %v", item.GetSequence(), err)
			r.log.Warn("synced item refused", "order", key, "item", item.GetSequence(), "err", err)
			break
		}
		m = next
	}
	if resp.Refused == "" && batch.Output != nil {
		if err := r.applyOutput(ctx, m, batch.GetOutput()); err != nil {
			resp.Refused = fmt.Sprintf("output: %v", err)
			r.log.Warn("synced output refused", "order", key, "err", err)
		}
	}
	resp.AppliedThrough = m.Applied
	if m.Recorded && m.Winner != nil {
		progress, found, err := r.cfg.Outputs.OutputStreamProgressOf(ctx, r.replicaKey(m))
		if err == nil && found {
			resp.OutputReceived, resp.OutputLastSeq, resp.OutputSealed = progress.Received, progress.LastSeq, progress.Sealed
		}
	}
	return resp, nil
}

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

// checkGroup requires the BuilderSet of a new order's batch to be the current snapshot with both
// the sender and this Builder among its members: the order's group.
func (r *Receiver) checkGroup(batch *buildersyncv1.BuilderSyncBatchV1) error {
	snapshot, ok := r.cfg.Groups.CurrentBuilderSet()
	if !ok {
		return fmt.Errorf("%w: no current BuilderSet snapshot", ErrUnavailable)
	}
	if snapshot.ID != batch.GetBuilderSetId() || !bytes.Equal(snapshot.Hash[:], batch.GetBuilderSetHash()) {
		return fmt.Errorf("%w: batch names BuilderSet %q, current is %q", ErrNotGroupMember, batch.GetBuilderSetId(), snapshot.ID)
	}
	if !slices.Contains(snapshot.Members, batch.GetSenderOperatorAddress()) || !slices.Contains(snapshot.Members, r.cfg.Builder) {
		return fmt.Errorf("%w: sender or receiver is not a member of BuilderSet %q", ErrNotGroupMember, snapshot.ID)
	}
	return nil
}

// incoming is what one batch's items share.
type incoming struct {
	senderKey []byte
}

// apply checks and applies one item on a copy of m and stores it; it returns the copy.
func (r *Receiver) apply(ctx context.Context, m *memberStream, in *incoming, item *buildersyncv1.BuilderSyncItemV1) (*memberStream, error) {
	next := m.clone()
	next.Applied = item.GetSequence()
	var err error
	switch it := item.GetItem().(type) {
	case *buildersyncv1.BuilderSyncItemV1_Round:
		err = r.applyRound(next, in, it.Round)
	case *buildersyncv1.BuilderSyncItemV1_InputChunk:
		err = r.applyInput(ctx, next, it.InputChunk)
	case *buildersyncv1.BuilderSyncItemV1_Attempt:
		err = r.applyAttempt(next, in, it.Attempt)
	case *buildersyncv1.BuilderSyncItemV1_Record:
		err = r.applyRecord(next, in, it.Record)
	case *buildersyncv1.BuilderSyncItemV1_Order:
		err = r.applyOrder(ctx, next, in, it.Order)
	default:
		err = errors.New("unknown item")
	}
	if err != nil {
		return nil, err
	}
	return next, nil
}

// copyOf finds this Builder's copy of the sender's evidence of an order version in an epoch.
func (r *Receiver) copyOf(m *memberStream, taskID string, epoch uint64) (*dispatchevidence.Order, error) {
	orders, err := r.cfg.Evidence.ByTask(taskID)
	if err != nil {
		return nil, fmt.Errorf("%w: evidence: %v", ErrUnavailable, err)
	}
	for _, o := range orders {
		if o.Builder == m.Sender && o.SessionID == m.SessionID && o.Sequence == m.Sequence && o.Epoch == epoch {
			return o, nil
		}
	}
	return nil, nil
}

// put stores the copy o with m (and extra) in one write.
func (r *Receiver) put(o *dispatchevidence.Order, m *memberStream, extra ...kv.WriteOp) error {
	m.ExpireHeight = max(m.ExpireHeight, r.cfg.Retention(o))
	op, err := memberOp(m)
	if err != nil {
		return err
	}
	if err := r.cfg.Evidence.Put(o, append(extra, op)...); err != nil {
		return fmt.Errorf("%w: store the copy: %v", ErrUnavailable, err)
	}
	return nil
}

func (r *Receiver) store(m *memberStream, extra ...kv.WriteOp) error {
	op, err := memberOp(m)
	if err != nil {
		return err
	}
	if err := r.cfg.Store.WriteBatch(append(extra, op)...); err != nil {
		return fmt.Errorf("%w: store the sync stream: %v", ErrUnavailable, err)
	}
	return nil
}

// applyRound adds a round to the copy: its roster must hash to its roster_hash and its root must
// be signed by the sender.
func (r *Receiver) applyRound(m *memberStream, in *incoming, round *buildersyncv1.BuilderSyncRoundV1) error {
	if len(round.GetTaskId()) != 32 || len(round.GetTaskHash()) != 32 || len(round.GetRosterHash()) != 32 {
		return errors.New("round task_id, task_hash or roster_hash is not 32 bytes")
	}
	taskID := hex.EncodeToString(round.GetTaskId())
	if m.TaskID != "" && m.TaskID != taskID {
		return fmt.Errorf("round names task %s, the order's is %s", taskID, m.TaskID)
	}
	candidate := dispatchevidence.Round{Number: round.GetDispatchRound(), Roster: round.GetRoster(), RosterHash: round.GetRosterHash()}
	check := &dispatchevidence.Order{Rounds: []dispatchevidence.Round{candidate}}
	if _, ok := check.RosterFor(r.cfg.ChainID, candidate.Number, candidate.RosterHash); !ok {
		return errors.New("roster does not hash to roster_hash")
	}
	var roster taskv1.DispatchRosterV1
	if err := proto.Unmarshal(round.GetRoster(), &roster); err != nil || !bytes.Equal(roster.GetTaskId(), round.GetTaskId()) {
		return errors.New("roster is not the task's")
	}
	var root taskv1.SignedHandraiseRootV1
	if err := proto.Unmarshal(round.GetHandraiseRoot(), &root); err != nil {
		return fmt.Errorf("handraise root: %w", err)
	}
	if root.GetChainId() != r.cfg.ChainID || root.GetBuilderAddress() != m.Sender {
		return errors.New("handraise root is not the sender's on this chain")
	}
	rootDigest, err := signingDigest(rootName, round.GetHandraiseRoot())
	if err != nil {
		return err
	}
	if dispatch.VerifyDigestSignature(in.senderKey, rootDigest[:], root.GetBuilderServiceSignature()) != nil {
		return errors.New("handraise root is not signed by the sender")
	}
	candidate.RootDigest, candidate.SignedRoot = rootDigest[:], round.GetHandraiseRoot()
	o, err := r.copyOf(m, taskID, round.GetVrfEpoch())
	if err != nil {
		return err
	}
	if o == nil {
		o = &dispatchevidence.Order{Builder: m.Sender, SessionID: m.SessionID, Sequence: m.Sequence, TaskID: taskID, Epoch: round.GetVrfEpoch()}
	}
	if _, held := o.Round(candidate.Number); held {
		return fmt.Errorf("round %d is held already", candidate.Number)
	}
	o.TaskHash = hex.EncodeToString(round.GetTaskHash())
	o.DeadlineBase = max(o.DeadlineBase, round.GetEarliestSubmitHeight())
	o.Rounds = append(o.Rounds, candidate)
	slices.SortFunc(o.Rounds, func(a, b dispatchevidence.Round) int { return int(a.Number) - int(b.Number) })
	m.TaskID = taskID
	index := kv.WriteOp{NS: kv.NSBuilderSyncMember, Key: memberTaskPrefix + taskID, Val: []byte(m.key())}
	return r.put(o, m, index)
}

// applyInput takes a piece of an order version's input; once whole, the input must hash to its
// input_hash and is stored with the task data.
func (r *Receiver) applyInput(ctx context.Context, m *memberStream, c *buildersyncv1.BuilderSyncInputChunkV1) error {
	if m.TaskID == "" {
		return errors.New("input before the order's first round")
	}
	if len(c.GetTaskHash()) != 32 || len(c.GetInputHash()) != 32 {
		return errors.New("input task_hash or input_hash is not 32 bytes")
	}
	if c.GetInputSizeBytes() > r.cfg.MaxInputBytes {
		return fmt.Errorf("input of %d bytes is over the %d byte bound", c.GetInputSizeBytes(), r.cfg.MaxInputBytes)
	}
	taskHash := hex.EncodeToString(c.GetTaskHash())
	input := m.Inputs[taskHash]
	if input == nil {
		input = &memberInput{InputHash: c.GetInputHash(), Size: c.GetInputSizeBytes()}
		m.Inputs[taskHash] = input
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
// round held with its roster_hash and root, with the answers its target gave.
func (r *Receiver) applyAttempt(m *memberStream, in *incoming, a *buildersyncv1.BuilderSyncAttemptV1) error {
	var ticket taskv1.DispatchTicketV1
	if err := proto.Unmarshal(a.GetTicket(), &ticket); err != nil {
		return fmt.Errorf("ticket: %w", err)
	}
	hash, err := r.checkTicket(m, in, a.GetTicket(), &ticket)
	if err != nil {
		return err
	}
	o, err := r.copyOf(m, hex.EncodeToString(ticket.GetTaskId()), ticket.GetVrfEpoch())
	if err != nil {
		return err
	}
	if o == nil {
		return errors.New("ticket of a round not held")
	}
	round, held := o.Round(ticket.GetDispatchRound())
	if !held || !bytes.Equal(round.RosterHash, ticket.GetRosterHash()) || !bytes.Equal(round.RootDigest, ticket.GetHandraiseRootDigest()) {
		return fmt.Errorf("ticket's round %d is not held with its roster_hash and root", ticket.GetDispatchRound())
	}
	if input := m.Inputs[hex.EncodeToString(ticket.GetTaskHash())]; input != nil && !bytes.Equal(input.InputHash, ticket.GetInputHash()) {
		return errors.New("ticket's input_hash is not the synced input's")
	}
	target := ticket.GetTarget().GetOperatorAddress()
	if target == "" {
		return errors.New("ticket names no target")
	}
	if len(a.GetReject()) > 0 {
		if a.GetOutcome() != taskv1.DispatchAttemptOutcomeV1_DISPATCH_ATTEMPT_OUTCOME_V1_REJECTED {
			return errors.New("reject of an attempt that is not REJECTED")
		}
		var reject taskv1.DispatchRejectV1
		if err := proto.Unmarshal(a.GetReject(), &reject); err != nil || !bytes.Equal(reject.GetDispatchTicketHash(), hash[:]) ||
			reject.GetMember().GetOperatorAddress() != target {
			return errors.New("reject is not the target's reject of the ticket")
		}
	}
	for _, raw := range [][]byte{a.GetLateAccept(), a.GetAccept()} {
		if len(raw) == 0 {
			continue
		}
		var accept taskv1.DispatchAcceptV1
		if err := proto.Unmarshal(raw, &accept); err != nil || !bytes.Equal(accept.GetDispatchTicketHash(), hash[:]) ||
			accept.GetMember().GetOperatorAddress() != target || !bytes.Equal(accept.GetTaskHash(), ticket.GetTaskHash()) {
			return errors.New("accept is not the target's accept of the ticket")
		}
	}
	if a.GetOutcome() == outcomeAccepted {
		if len(a.GetAccept()) == 0 {
			return errors.New("ACCEPTED attempt without its accept")
		}
		o.Accept = a.GetAccept()
	}
	attempt := dispatchevidence.Attempt{
		Ticket: a.GetTicket(), Hash: hash[:], Rank: ticket.GetRank(), Operator: target, Sent: a.GetSent(), Outcome: a.GetOutcome(),
		Reject: a.GetReject(), LateAccept: a.GetLateAccept(),
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
func (r *Receiver) checkTicket(m *memberStream, in *incoming, raw []byte, t *taskv1.DispatchTicketV1) ([32]byte, error) {
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
	if dispatch.VerifyDigestSignature(in.senderKey, hash[:], t.GetBuilderServiceSignature()) != nil {
		return [32]byte{}, errors.New("ticket is not signed by the sender")
	}
	return hash, nil
}

// applyRecord sets the signed record of an order version in the copy.
func (r *Receiver) applyRecord(m *memberStream, in *incoming, rec *buildersyncv1.BuilderSyncRecordV1) error {
	var record taskv1.DispatchRecordV1
	if err := proto.Unmarshal(rec.GetRecord(), &record); err != nil {
		return fmt.Errorf("record: %w", err)
	}
	if record.GetChainId() != r.cfg.ChainID || record.GetBuilderAddress() != m.Sender ||
		hex.EncodeToString(record.GetSessionId()) != m.SessionID || record.GetOrderSequence() != m.Sequence {
		return errors.New("record is not the sender's for this order")
	}
	digest, err := signingDigest(recordName, rec.GetRecord())
	if err != nil {
		return err
	}
	if dispatch.VerifyDigestSignature(in.senderKey, digest[:], record.GetBuilderServiceSignature()) != nil {
		return errors.New("record is not signed by the sender")
	}
	o, err := r.copyOf(m, hex.EncodeToString(record.GetTaskId()), record.GetVrfEpoch())
	if err != nil {
		return err
	}
	if o == nil {
		return errors.New("record of an order version not held")
	}
	o.Record = rec.GetRecord()
	return r.put(o, m)
}

// applyOrder takes the user's order once the chain recorded it: the chain's record must name the
// winner of the sender's RECORDED header, a ticket held in the copy.
func (r *Receiver) applyOrder(ctx context.Context, m *memberStream, in *incoming, item *buildersyncv1.BuilderSyncOrderV1) error {
	var signed taskv1.SignedOrderV2
	if err := proto.Unmarshal(item.GetSignedOrder(), &signed); err != nil {
		return fmt.Errorf("signed order: %w", err)
	}
	order := signed.GetOrder()
	if hex.EncodeToString(order.GetSessionId()) != m.SessionID || order.GetOrderSequence() != m.Sequence ||
		order.GetBuilderSetId() != m.BuilderSetID || !bytes.Equal(order.GetBuilderSetHash(), m.BuilderSetHash) {
		return errors.New("signed order is not this order of the group's BuilderSet")
	}
	var header nexusv1.DispatchResultHeaderV1
	if err := proto.Unmarshal(item.GetResultHeader(), &header); err != nil {
		return fmt.Errorf("result header: %w", err)
	}
	if header.GetRecordStatus() != taskv1.DispatchRecordStatusV1_DISPATCH_RECORD_STATUS_V1_RECORDED {
		return fmt.Errorf("result header is %s, not RECORDED", header.GetRecordStatus())
	}
	headerDigest, err := signingDigest(resultHeaderName, item.GetResultHeader())
	if err != nil {
		return err
	}
	if dispatch.VerifyDigestSignature(in.senderKey, headerDigest[:], header.GetBuilderServiceSignature()) != nil {
		return errors.New("result header is not signed by the sender")
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
	acceptRaw, err := marshal(header.GetAccept())
	if err != nil {
		return err
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
	ev.SignedOrder = item.GetSignedOrder()
	ev.Recorded, ev.RecordedHeight = true, record.GetRecordedHeight()
	ev.DeadlineBase = max(ev.DeadlineBase, order.GetEarliestSubmitHeight())
	m.Recorded, m.RecordedHeight = true, record.GetRecordedHeight()
	m.Winner = &memberWinner{
		TaskHash: ev.TaskHash, TicketHash: winnerHash[:], Ticket: held.Ticket, Accept: acceptRaw, AcceptDigest: acceptDigest[:],
		Worker: held.Operator, Header: item.GetResultHeader(), User: order.GetUserAddress(),
	}
	index := kv.WriteOp{NS: kv.NSBuilderSyncMember, Key: memberTaskPrefix + ev.TaskID, Val: []byte(m.key())}
	return r.put(ev, m, index)
}

// replicaKey is the OUTPUT key of the recorded winner's replica.
func (r *Receiver) replicaKey(m *memberStream) taskdata.ObjectKey {
	return taskdata.ObjectKey{TaskHash: m.Winner.TaskHash, SessionID: m.SessionID, TaskID: m.TaskID, Kind: taskdata.ObjectKindOutput}
}

// applyOutput appends the recorded winner's frames to the replica: each must carry the winner's
// ticket and be signed by the winner's current service key; the batch must name the winner ticket
// and accept the order item named.
func (r *Receiver) applyOutput(ctx context.Context, m *memberStream, out *buildersyncv1.BuilderSyncOutputV1) error {
	if !m.Recorded || m.Winner == nil {
		return errors.New("output before the order was recorded")
	}
	w := m.Winner
	ticketHash, err := signingDigest(ticketName, out.GetWinnerTicket())
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
