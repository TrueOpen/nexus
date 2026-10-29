// Package recorder records the dispatch entries of a Builder's accepted orders on chain.
//
// At every new block the Recorder packs every entry accepted since the previous block into
// MsgRecordDispatch transactions signed by the Builder service key, entries sorted by (session_id,
// order_sequence) and split by max_dispatch_entries_per_record and max_dispatch_record_bytes.
// Each entry is stored in the record outbox as the exact bytes handed over, and each signed
// transaction before it is broadcast; after a restart a stored transaction is broadcast again as
// stored. An entry that has to go out again (its transaction was refused as a whole or can no
// longer land) is sent with the same entry bytes in a new transaction; the chain answers an entry
// it already admitted with its first result.
//
// An entry is resolved only by its result in an executed transaction, a dispatch_recorded event of
// its winner ticket, or its record deadline passing (then the dispatch record query decides).
// Admitted, the order leaves the in-flight ledger and the dispatcher, its task is reconciled and
// the winner gets a RECORDED notice. Refused or late, the order and every later entry of its
// session fail as RECORD_REJECTED with REJECTED notices, the session is suspended from its
// sequence and the dispatcher fails its later orders: none of them can be recorded before it. The
// Workers of those orders claim compensation themselves.
//
// Rebutting those claims is not done here yet. When it is, it may only use an attempt that
// reached its Worker and ended REJECTED, TIMEOUT or REVOKED (the dispatcher's
// attemptState.rebuttable): an unsent ticket, a VOIDED one and the winner are owed the claim.
package recorder

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"sync/atomic"

	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatcher"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/signer"
)

// Params are the task params dispatch values the Recorder applies.
type Params struct {
	// MaxEntries is max_dispatch_entries_per_record.
	MaxEntries uint32
	// MaxBytes is max_dispatch_record_bytes, the encoded size of one MsgRecordDispatch.
	MaxBytes uint64
	// MinCompensation is builder_compensation_account_min_balance.
	MinCompensation *big.Int
}

// ParamsFromChain takes the Recorder's params from task params dispatch.
func ParamsFromChain(d *taskv1.DispatchParamsV1) (Params, error) {
	p := Params{MaxEntries: d.GetMaxDispatchEntriesPerRecord(), MaxBytes: d.GetMaxDispatchRecordBytes(), MinCompensation: new(big.Int)}
	if p.MaxEntries == 0 || p.MaxBytes == 0 {
		return Params{}, fmt.Errorf("dispatch params: max_dispatch_entries_per_record %d and max_dispatch_record_bytes %d must be set", p.MaxEntries, p.MaxBytes)
	}
	if units := d.GetBuilderCompensationAccountMinBalance().GetAtomicUnits(); units != "" {
		if _, ok := p.MinCompensation.SetString(units, 10); !ok || p.MinCompensation.Sign() < 0 {
			return Params{}, fmt.Errorf("dispatch params: builder_compensation_account_min_balance %q is not an amount", units)
		}
	}
	return p, nil
}

// Chain is what the Recorder reads from the task chain.
type Chain interface {
	QueryTx(ctx context.Context, txHash []byte) (chaincli.TxResult, error)
	QueryDispatchRecordByOrder(ctx context.Context, sessionID string, orderSequence uint64) (*taskv1.DispatchRecordState, error)
}

// Submitter sends record transactions from the Builder service account
// (coordinator.RecordSubmitter).
type Submitter interface {
	SubmitRecordDispatch(ctx context.Context, msg *taskv1.MsgRecordDispatch, gasLimit uint64, persist func(raw []byte) error) (chaincli.TxResult, error)
	BroadcastTx(ctx context.Context, raw []byte) (chaincli.TxResult, error)
}

// Ledger is the in-flight ledger (inflight.Ledger).
type Ledger interface {
	MarkRecorded(sessionID string, seq uint64) error
	Suspend(sessionID string, from uint64) error
}

// Orders is the dispatcher.
type Orders interface {
	// Recorded forgets an order whose dispatch entry the chain admitted.
	Recorded(sessionID string, sequence uint64) error
	// Suspend fails the session's orders from sequence from on.
	Suspend(ctx context.Context, sessionID string, from uint64, reason error)
}

// Tasks is told the outcome of each entry; the coordinator implements it.
type Tasks interface {
	DispatchRecorded(sessionID, taskID string, height uint64)
	RecordRejected(sessionID, taskID string, code taskv1.DispatchRejectCodeV1)
}

// Streams sends the record notices to the winners' dispatch streams.
type Streams interface {
	Send(ctx context.Context, operator string, frame *nexusv1.DispatchStreamFrameV1) error
}

// Config wires a Recorder.
type Config struct {
	ChainID string
	// Builder is this Builder's operator address; an event of its service key resumes records a
	// fatal refusal stopped.
	Builder string
	// Signer is the Builder service key: it signs the record transactions as their
	// submitter_address and the record notices.
	Signer  signer.Signer
	Store   kv.Store
	Ledger  Ledger
	Chain   Chain
	Tx      Submitter
	Tasks   Tasks
	Streams Streams
	// Gate holds the compensation account: no record is sent while it is below the minimum.
	Gate *Gate
	// GasBase and GasPerEntry give a record transaction its gas limit: GasBase plus GasPerEntry
	// for each entry.
	GasBase, GasPerEntry uint64
	Log                  *slog.Logger
}

// Recorder records accepted dispatch entries; it implements dispatcher.Recorder.
type Recorder struct {
	cfg    Config
	log    *slog.Logger
	params atomic.Pointer[Params]
	orders Orders

	mu       sync.Mutex
	entries  map[string]*entry    // object id -> unresolved entry
	txs      map[string]*txRecord // tx hash -> transaction
	tooLarge map[string]bool      // entries already reported as too large to send
	// withdrawn holds the winner tickets withdrawn before their Record, with the head then.
	withdrawn map[string]uint64
	// sizing is what deterministic transaction failures did to the batch size and gas.
	sizing sizing

	latest atomic.Uint64
	wake   chan struct{}
	stop   chan struct{}
	wg     sync.WaitGroup
}

var _ dispatcher.Recorder = (*Recorder)(nil)

// New builds a Recorder over the stored outbox. SetOrders must be called before Start.
func New(cfg Config, params Params) (*Recorder, error) {
	switch {
	case cfg.ChainID == "" || cfg.Builder == "" || cfg.Signer == nil || cfg.Store == nil || cfg.Ledger == nil:
		return nil, fmt.Errorf("recorder needs the chain id, Builder address, service signer, store and ledger")
	case cfg.GasBase == 0 || cfg.GasPerEntry == 0:
		return nil, fmt.Errorf("recorder needs the record gas base and per-entry gas")
	case cfg.Chain == nil || cfg.Tx == nil || cfg.Tasks == nil || cfg.Streams == nil || cfg.Gate == nil:
		return nil, fmt.Errorf("recorder needs the chain, submitter, tasks, streams and gate")
	}
	entries, txs, err := loadOutbox(cfg.Store)
	if err != nil {
		return nil, err
	}
	r := &Recorder{
		cfg: cfg, log: cfg.Log, entries: entries, txs: txs, tooLarge: map[string]bool{}, withdrawn: map[string]uint64{},
		wake: make(chan struct{}, 1), stop: make(chan struct{}),
	}
	if r.log == nil {
		r.log = slog.New(slog.DiscardHandler)
	}
	r.SetParams(params)
	return r, nil
}

// SetOrders wires the dispatcher, which is built with the Recorder.
func (r *Recorder) SetOrders(o Orders) { r.orders = o }

// SetParams replaces the params after a params change on chain.
func (r *Recorder) SetParams(p Params) {
	if p.MinCompensation == nil {
		p.MinCompensation = new(big.Int)
	}
	r.params.Store(&p)
	r.cfg.Gate.SetMinBalance(p.MinCompensation)
}

// Start follows the blocks HandleChainEvent reports.
func (r *Recorder) Start(context.Context) error {
	if r.orders == nil {
		return fmt.Errorf("recorder started without the dispatcher")
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.wg.Add(2)
	go func() {
		defer r.wg.Done()
		<-r.stop
		cancel()
	}()
	go func() {
		defer r.wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-r.wake:
				r.onBlock(ctx, r.latest.Load())
			}
		}
	}()
	return nil
}

// Stop ends the block work. Stored entries and transactions stay.
func (r *Recorder) Stop(context.Context) error {
	select {
	case <-r.stop:
	default:
		close(r.stop)
	}
	r.wg.Wait()
	return nil
}

// Record implements dispatcher.Recorder: the entry is stored and goes out at the next block. The
// same entry bytes again are the same entry.
func (r *Recorder) Record(_ context.Context, b *dispatcher.Bundle) error {
	id, err := chaincli.DispatchEntryObjectID(r.cfg.ChainID, b.Entry)
	if err != nil {
		return fmt.Errorf("dispatch entry key: %w", err)
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(&taskv1.DispatchRecordEntryV1{
		Entry: &taskv1.DispatchRecordEntryV1_Dispatch{Dispatch: b.Entry},
	})
	if err != nil {
		return fmt.Errorf("encode dispatch entry: %w", err)
	}
	e := &entry{
		ObjectID: hex.EncodeToString(id[:]), SessionID: b.SessionID, Sequence: b.Sequence, TaskID: b.TaskID,
		TicketHash: append([]byte(nil), b.Entry.GetRecord().GetDispatchTicketHash()...),
		Worker:     b.Entry.GetAccept().GetMember().GetOperatorAddress(), Deadline: b.Deadline, Entry: raw,
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.withdrawn[string(e.TicketHash)]; ok {
		delete(r.withdrawn, string(e.TicketHash))
		r.log.Info("dispatch entry of a withdrawn ticket dropped", "session_id", e.SessionID, "order_sequence", e.Sequence)
		return nil
	}
	if _, ok := r.entries[e.ObjectID]; ok {
		return nil
	}
	op, err := putOp(entryKey(e.ObjectID), e)
	if err == nil {
		err = r.cfg.Store.WriteBatch(op)
	}
	if err != nil {
		return fmt.Errorf("store dispatch entry: %w", err)
	}
	r.entries[e.ObjectID] = e
	return nil
}

// Withdraw implements dispatcher.Recorder: an entry not sent yet is dropped; a sent one is marked
// so that its refusal changes nothing. A Withdraw that comes before the Record of its ticket
// drops that Record.
func (r *Recorder) Withdraw(_ context.Context, _ string, _ uint64, ticketHash [32]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.entries {
		if string(e.TicketHash) != string(ticketHash[:]) {
			continue
		}
		var ops []kv.WriteOp
		if e.Tx == "" {
			r.removeLocked(e, &ops)
		} else {
			e.Withdrawn = true
			ops = append(ops, r.entryOp(e))
		}
		r.writeLocked(ops)
		return
	}
	r.withdrawn[string(ticketHash[:])] = r.latest.Load()
}

// HandleChainEvent follows the head, the dispatch_recorded events of the sessions this Builder
// dispatches for and the events that move its compensation account. The caller feeds it every
// task chain event.
func (r *Recorder) HandleChainEvent(ev chaincli.ChainEvent) {
	r.cfg.Gate.HandleChainEvent(ev)
	r.resumeOnKeyEvent(ev)
	if ev.Type == chaincli.EventNewBlock && ev.Height > 0 {
		for {
			latest := r.latest.Load()
			if uint64(ev.Height) <= latest || r.latest.CompareAndSwap(latest, uint64(ev.Height)) {
				break
			}
		}
		select {
		case r.wake <- struct{}{}:
		default:
		}
		return
	}
	t, ok := ev.Typed.(chaincli.DispatchRecorded)
	if !ok {
		return
	}
	var fx effects
	r.mu.Lock()
	var ops []kv.WriteOp
	for _, e := range r.entries {
		if e.SessionID == t.SessionID && e.Sequence == t.OrderSequence && string(e.TicketHash) == string(t.TicketHash) {
			r.recordLocked(e, uint64(ev.Height), &ops, &fx)
		}
	}
	r.writeLocked(ops)
	r.mu.Unlock()
	fx.run(context.Background())
}

// onBlock checks the transactions out, resolves the entries past their deadline, reads the
// compensation account when due and sends the waiting entries.
func (r *Recorder) onBlock(ctx context.Context, height uint64) {
	r.pruneWithdrawn(height)
	r.checkTxs(ctx, height)
	r.expire(ctx, height)
	r.cfg.Gate.onBlock(ctx, height)
	r.pack(ctx, height)
}

// withdrawnKeepBlocks is how long a ticket withdrawn before its Record is remembered; the Record
// follows the accept at once, so this only bounds the memory of tickets never handed over.
const withdrawnKeepBlocks = 100

func (r *Recorder) pruneWithdrawn(height uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for ticket, at := range r.withdrawn {
		if at+withdrawnKeepBlocks < height {
			delete(r.withdrawn, ticket)
		}
	}
}

func (r *Recorder) entryOp(e *entry) kv.WriteOp {
	op, err := putOp(entryKey(e.ObjectID), e)
	if err != nil {
		r.log.Error("record outbox entry not encoded", "session_id", e.SessionID, "order_sequence", e.Sequence, "err", err)
	}
	return op
}

func (r *Recorder) removeLocked(e *entry, ops *[]kv.WriteOp) {
	delete(r.entries, e.ObjectID)
	*ops = append(*ops, deleteOp(entryKey(e.ObjectID)))
}

// writeLocked applies outbox writes whose memory change is already made. A failed write is
// logged: the entry comes back after a restart and the chain answers it again.
func (r *Recorder) writeLocked(ops []kv.WriteOp) {
	var valid []kv.WriteOp
	for _, op := range ops {
		if op.Key != "" {
			valid = append(valid, op)
		}
	}
	if len(valid) == 0 {
		return
	}
	if err := r.cfg.Store.WriteBatch(valid...); err != nil {
		r.log.Error("record outbox not written", "err", err)
	}
}

// effects are what resolving entries sets off; they run with no Recorder lock held.
type effects []func(context.Context)

func (fx *effects) add(f func(context.Context)) { *fx = append(*fx, f) }

func (fx effects) run(ctx context.Context) {
	for _, f := range fx {
		f(ctx)
	}
}

// notify sends the winner of e its record notice. The notice is a hint: the Worker checks the
// chain after the deadline, so a winner without a stream misses nothing it relies on.
func (r *Recorder) notify(ctx context.Context, e *entry, status taskv1.DispatchRecordStatusV1, code taskv1.DispatchRejectCodeV1, height uint64) {
	n := &nexusv1.RecordResultNoticeV1{DispatchTicketHash: e.TicketHash, Status: status, RejectCode: code, RecordedHeight: height}
	if _, _, err := dispatcher.SignRecordResultNotice(r.cfg.Signer, n); err != nil {
		r.log.Error("record notice not signed", "session_id", e.SessionID, "order_sequence", e.Sequence, "err", err)
		return
	}
	frame := &nexusv1.DispatchStreamFrameV1{Message: &nexusv1.DispatchStreamFrameV1_RecordResult{RecordResult: n}}
	if err := r.cfg.Streams.Send(ctx, e.Worker, frame); err != nil {
		r.log.Info("record notice not sent", "worker", e.Worker, "session_id", e.SessionID, "order_sequence", e.Sequence, "status", status, "err", err)
	}
}

func isNotFound(err error) bool { return errors.Is(err, chaincli.ErrNotFound) }
