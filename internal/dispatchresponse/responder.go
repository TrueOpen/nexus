// Package dispatchresponse answers, from a Builder's dispatch evidence, what the chain asks of the
// Builder about its dispatches.
//
// A Worker that claims compensation on one of this Builder's tickets is rebutted within the
// rebuttal window when the evidence shows the ticket reached it and it rejected (the Worker's own
// reject goes with the record), timed out or was revoked; every other claim is owed and left to be
// paid. A SKIP challenge on this Builder's record is answered with the Worker's reject stored for
// the challenged ticket, a ROSTER_UNAVAILABLE challenge with the stored roster of the challenged
// round whose roster_hash the chain's record holds. OMISSION, DRAW and DOUBLE_DISPATCH challenges
// have no answer; they are logged and counted.
//
// Claims and challenges come from the Builder role event stream. Open ones are stored, so a
// restart goes on with them. After a gap in the stream every ticket the evidence could rebut is
// looked up on chain again; challenges opened during a gap cannot be found, since the chain has no
// query listing the challenges against a Builder.
package dispatchresponse

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatchevidence"
	"github.com/TrueOpen/nexus/internal/kv"
)

const (
	// resubmitBlocks is how long a rebuttal or response sent waits to land before it is sent again
	// while the claim or challenge is still open.
	resubmitBlocks = 3
	// maxSends bounds how often one rebuttal or response is sent: one the chain keeps refusing
	// when executing only spends gas.
	maxSends = 3
	// maxGasFactor bounds how far out-of-gas results raise the gas of one answer.
	maxGasFactor = 8
	// pruneEveryBlocks is how often expired evidence and unbound handraise roots are pruned.
	pruneEveryBlocks = 10
	// rootKeepMarginBlocks keeps, on top of record_deadline_blocks, every handraise root an order
	// still dispatching may bind before its evidence is written.
	rootKeepMarginBlocks = 10
)

// Chain is what the responder reads from the task chain.
type Chain interface {
	QueryDispatchCompensationClaim(ctx context.Context, ticketHash []byte) (*taskv1.DispatchCompensationClaimState, error)
	QueryDispatchChallenge(ctx context.Context, challengeID []byte) (*taskv1.DispatchChallengeState, error)
	QueryDispatchRecordByOrder(ctx context.Context, sessionID string, orderSequence uint64) (*taskv1.DispatchRecordState, error)
	// QueryTx reads the executed result of a transaction sent.
	QueryTx(ctx context.Context, txHash []byte) (chaincli.TxResult, error)
}

// Submitter sends rebuttals and challenge responses from the Builder service account
// (coordinator.RecordSubmitter).
type Submitter interface {
	SubmitRebutDispatchCompensation(ctx context.Context, msg *taskv1.MsgRebutDispatchCompensation, gasLimit uint64) (chaincli.TxResult, error)
	SubmitRespondDispatchChallenge(ctx context.Context, msg *taskv1.MsgRespondDispatchChallenge, gasLimit uint64) (chaincli.TxResult, error)
}

// Roots prunes issued handraise roots (handraise.Registry).
type Roots interface {
	PruneRootsBelow(height uint64, keep func(digest [32]byte) bool) (int, error)
}

// Config wires a Responder.
type Config struct {
	ChainID string
	// Builder is this Builder's operator address; Responder its service account, the
	// responder_address of what it sends.
	Builder   string
	Responder string
	Store     kv.Store
	Evidence  *dispatchevidence.Store
	Chain     Chain
	Tx        Submitter
	// Roots, when set, has its unbound roots pruned along with the evidence; LiveRoots, when set,
	// returns the roots orders still dispatching bind (dispatcher.BoundRoots), kept as well.
	Roots     Roots
	LiveRoots func() map[[32]byte]bool
	// GasBase and GasPerByte give an answer its gas limit: GasBase plus GasPerByte for each
	// encoded byte of the Msg (dispatch.answer_gas_base, answer_gas_per_byte).
	GasBase, GasPerByte uint64
	Log                 *slog.Logger
}

// Counts are what the responder saw since it started.
type Counts struct {
	ClaimsSeen, ClaimsRebutted, ClaimsOwed     uint64
	ChallengesAnswered, UnanswerableChallenges uint64
}

// Responder rebuts claims and answers challenges.
type Responder struct {
	cfg Config
	log *slog.Logger

	mu         sync.Mutex
	claims     map[string]*item // ticket hash -> open claim
	challenges map[string]*item // challenge id -> open challenge
	resync     bool
	lastPrune  uint64

	claimsSeen, claimsRebutted, claimsOwed atomic.Uint64
	answered, unanswerable                 atomic.Uint64
	latest                                 atomic.Uint64
	wake, stop                             chan struct{}
	wg                                     sync.WaitGroup
	stopOnce                               sync.Once
}

// item is an open claim or challenge.
type item struct {
	ID []byte `json:"id"`
	// Deadline is the last height an answer can land at, as the event announced it.
	Deadline uint64 `json:"deadline"`
	// SentAt is the head when an answer was last broadcast, zero when none was; Sends counts them.
	SentAt uint64 `json:"sent_at,omitempty"`
	Sends  int    `json:"sends,omitempty"`
	// TxHash is the last answer's transaction until its result was read; GasFactor multiplies the
	// gas of the next one (0 counts as 1).
	TxHash    []byte `json:"tx_hash,omitempty"`
	GasFactor uint64 `json:"gas_factor,omitempty"`
	// Missing is set once the evidence was looked for and not found (logged once).
	Missing bool `json:"missing,omitempty"`
}

// Keys of the open items in kv.NSDispatchEvidence.
const (
	claimPrefix     = "claim/"
	challengePrefix = "challenge/"
)

// New builds a Responder over the stored open items.
func New(cfg Config) (*Responder, error) {
	switch {
	case cfg.ChainID == "" || cfg.Builder == "" || cfg.Responder == "" || cfg.Store == nil || cfg.Evidence == nil:
		return nil, fmt.Errorf("dispatch responder needs the chain id, Builder and service addresses, store and evidence")
	case cfg.Chain == nil || cfg.Tx == nil:
		return nil, fmt.Errorf("dispatch responder needs the chain and a submitter")
	case cfg.GasBase == 0 || cfg.GasPerByte == 0:
		return nil, fmt.Errorf("dispatch responder needs the answer gas base and per-byte gas")
	}
	r := &Responder{
		cfg: cfg, log: cfg.Log, claims: map[string]*item{}, challenges: map[string]*item{},
		wake: make(chan struct{}, 1), stop: make(chan struct{}),
	}
	if r.log == nil {
		r.log = slog.New(slog.DiscardHandler)
	}
	var decodeErr error
	err := cfg.Store.Scan(kv.NSDispatchEvidence, func(key string, val []byte) bool {
		var into map[string]*item
		switch {
		case strings.HasPrefix(key, claimPrefix):
			into = r.claims
		case strings.HasPrefix(key, challengePrefix):
			into = r.challenges
		default:
			return key < challengePrefix
		}
		var it item
		if err := json.Unmarshal(val, &it); err != nil {
			decodeErr = fmt.Errorf("open dispatch item %q is malformed: %w", key, err)
			return false
		}
		into[string(it.ID)] = &it
		return true
	})
	if err == nil {
		err = decodeErr
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Start answers on the blocks HandleChainEvent reports.
func (r *Responder) Start(context.Context) error {
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

// Stop ends the block work; open items stay stored.
func (r *Responder) Stop(context.Context) error {
	r.stopOnce.Do(func() { close(r.stop) })
	r.wg.Wait()
	return nil
}

// Counts returns what the responder saw since it started.
func (r *Responder) Counts() Counts {
	return Counts{
		ClaimsSeen: r.claimsSeen.Load(), ClaimsRebutted: r.claimsRebutted.Load(), ClaimsOwed: r.claimsOwed.Load(),
		ChallengesAnswered: r.answered.Load(), UnanswerableChallenges: r.unanswerable.Load(),
	}
}

// HandleChainEvent follows the head and the Builder role events. The caller feeds it every task
// chain event; nothing here reads the chain.
func (r *Responder) HandleChainEvent(ev chaincli.ChainEvent) {
	switch ev.Type {
	case chaincli.EventNewBlock:
		if ev.Height > 0 {
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
		}
		return
	case chaincli.EventBuilderRoleResync:
		r.log.Warn("builder role stream (re)connected: claims of the gap are looked up again from the evidence; " +
			"challenges opened during the gap cannot be found (the chain lists no challenges by Builder) and go unanswered")
		r.mu.Lock()
		r.resync = true
		r.mu.Unlock()
		return
	}
	switch t := ev.Typed.(type) {
	case chaincli.DispatchCompensationClaimed:
		if t.Builder != r.cfg.Builder {
			return
		}
		r.claimsSeen.Add(1)
		r.log.Info("compensation claimed on a ticket of this Builder", "ticket", hex.EncodeToString(t.TicketHash), "task_id", t.TaskID,
			"worker", t.Worker, "amount", t.Amount, "rebuttal_deadline", t.RebuttalDeadlineHeight)
		r.open(claimPrefix, r.claims, &item{ID: t.TicketHash, Deadline: t.RebuttalDeadlineHeight})
	case chaincli.DispatchCompensationPaid:
		if t.Builder == r.cfg.Builder {
			r.log.Info("compensation paid on a ticket of this Builder", "ticket", hex.EncodeToString(t.TicketHash), "task_id", t.TaskID,
				"worker", t.Worker, "paid", t.PaidAmount, "unfilled", t.UnfilledAmount)
			r.close(claimPrefix, r.claims, t.TicketHash)
		}
	case chaincli.DispatchCompensationRebutted:
		if t.Builder == r.cfg.Builder {
			r.log.Info("compensation claim rebutted", "ticket", hex.EncodeToString(t.TicketHash), "task_id", t.TaskID,
				"responder", t.Responder, "outcome", t.AttemptOutcome, "worker_fault", t.WorkerFaultRecorded)
			r.close(claimPrefix, r.claims, t.TicketHash)
		}
	case chaincli.DispatchChallengeOpened:
		if !answerable(t.Kind) {
			r.unanswerable.Add(1)
			r.log.Warn("dispatch challenge opened; it has no answer", "challenge_id", hex.EncodeToString(t.ChallengeID), "task_id", t.TaskID,
				"kind", t.Kind, "challenger", t.Challenger)
			return
		}
		r.log.Info("dispatch challenge opened", "challenge_id", hex.EncodeToString(t.ChallengeID), "task_id", t.TaskID, "kind", t.Kind,
			"challenger", t.Challenger, "proof_deadline", t.ProofDeadlineHeight)
		r.open(challengePrefix, r.challenges, &item{ID: t.ChallengeID, Deadline: t.ProofDeadlineHeight})
	case chaincli.DispatchChallengeResolved:
		r.log.Info("dispatch challenge resolved", "challenge_id", hex.EncodeToString(t.ChallengeID), "task_id", t.TaskID, "kind", t.Kind, "outcome", t.Outcome)
		r.close(challengePrefix, r.challenges, t.ChallengeID)
	case chaincli.BuilderDispatchFaultRecorded:
		if t.Builder == r.cfg.Builder {
			r.log.Warn("dispatch fault recorded against this Builder", "fault_id", hex.EncodeToString(t.FaultID), "kind", t.Kind, "task_id", t.TaskID,
				"penalty", t.PenaltyAmount, "unfilled", t.UnfilledAmount, "compensated_worker", t.CompensatedWorker)
		}
	}
}

// onBlock answers the open claims and challenges at head, looks the claims of a role stream gap
// up again, and prunes expired evidence.
func (r *Responder) onBlock(ctx context.Context, head uint64) {
	r.mu.Lock()
	resync := r.resync
	r.resync = false
	r.mu.Unlock()
	if resync {
		r.recheckClaims(ctx, head)
	}
	for _, it := range r.snapshot(r.claims) {
		r.handleClaim(ctx, head, it)
	}
	for _, it := range r.snapshot(r.challenges) {
		r.handleChallenge(ctx, head, it)
	}
	r.prune(head)
}

func (r *Responder) prune(head uint64) {
	r.mu.Lock()
	due := head >= r.lastPrune+pruneEveryBlocks
	if due {
		r.lastPrune = head
	}
	r.mu.Unlock()
	if !due {
		return
	}
	if n, err := r.cfg.Evidence.Prune(head); err != nil {
		r.log.Warn("dispatch evidence not pruned", "err", err)
	} else if n > 0 {
		r.log.Debug("dispatch evidence pruned", "orders", n)
	}
	margin := r.cfg.Evidence.Params().RecordDeadlineBlocks + rootKeepMarginBlocks
	if r.cfg.Roots == nil || head <= margin {
		return
	}
	var live map[[32]byte]bool
	if r.cfg.LiveRoots != nil {
		live = r.cfg.LiveRoots()
	}
	keep := func(digest [32]byte) bool { return live[digest] || r.cfg.Evidence.ReferencesRoot(digest) }
	if _, err := r.cfg.Roots.PruneRootsBelow(head-margin, keep); err != nil {
		r.log.Warn("handraise roots not pruned", "err", err)
	}
}

// open stores an open item; one already open keeps what it has.
func (r *Responder) open(prefix string, into map[string]*item, it *item) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := into[string(it.ID)]; ok {
		return
	}
	into[string(it.ID)] = it
	r.writeLocked(prefix, it)
}

// close drops an open item.
func (r *Responder) close(prefix string, from map[string]*item, id []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := from[string(id)]; !ok {
		return
	}
	delete(from, string(id))
	if err := r.cfg.Store.Delete(kv.NSDispatchEvidence, prefix+hex.EncodeToString(id)); err != nil {
		r.log.Warn("closed dispatch item not deleted", "id", hex.EncodeToString(id), "err", err)
	}
}

// update stores the item's progress if it is still open.
func (r *Responder) update(prefix string, in map[string]*item, it *item) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur, ok := in[string(it.ID)]; ok {
		*cur = *it
		r.writeLocked(prefix, cur)
	}
}

func (r *Responder) writeLocked(prefix string, it *item) {
	raw, err := json.Marshal(it)
	if err == nil {
		err = r.cfg.Store.Set(kv.NSDispatchEvidence, prefix+hex.EncodeToString(it.ID), raw)
	}
	if err != nil {
		r.log.Warn("open dispatch item not stored; it is lost on a restart", "id", hex.EncodeToString(it.ID), "err", err)
	}
}

func (r *Responder) snapshot(from map[string]*item) []item {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]item, 0, len(from))
	for _, it := range from {
		out = append(out, *it)
	}
	return out
}

func (r *Responder) openClaims() []item     { return r.snapshot(r.claims) }
func (r *Responder) openChallenges() []item { return r.snapshot(r.challenges) }

// ready reports whether an answer may be sent at head as far as time goes: none was sent, or the
// last one had time to land.
func (it *item) ready(head uint64) bool { return it.SentAt == 0 || head >= it.SentAt+resubmitBlocks }

// spent reports whether the item may not be answered again: maxSends answers were sent.
func (it *item) spent() bool { return it.Sends >= maxSends }

// gas is the gas limit of msg for the item's next answer.
func (r *Responder) gas(msg proto.Message, it *item) uint64 {
	return (r.cfg.GasBase + r.cfg.GasPerByte*uint64(proto.Size(msg))) * max(it.GasFactor, 1)
}

// settleLastSend reads the result of the item's last answer once it had time to land. One that
// ran out of gas below maxGasFactor goes again with twice the gas and does not count as a send.
func (r *Responder) settleLastSend(ctx context.Context, it *item) {
	if len(it.TxHash) == 0 {
		return
	}
	res, err := r.cfg.Chain.QueryTx(ctx, it.TxHash)
	it.TxHash = nil
	if err != nil || res.Codespace != "sdk" || res.Code != 11 {
		return
	}
	factor := max(it.GasFactor, 1)
	if factor >= maxGasFactor {
		r.log.Error("dispatch answer out of gas at the highest gas; raise dispatch.answer_gas_base or answer_gas_per_byte", "id", hex.EncodeToString(it.ID))
		return
	}
	it.GasFactor, it.Sends = factor*2, it.Sends-1
	r.log.Warn("dispatch answer out of gas; it goes again with more gas", "id", hex.EncodeToString(it.ID), "gas_factor", it.GasFactor)
}

// sent records an answer broadcast at head.
func (it *item) sent(head uint64, res chaincli.TxResult) {
	it.SentAt, it.Sends, it.TxHash = head, it.Sends+1, res.TxHash
}

func isNotFound(err error) bool { return errors.Is(err, chaincli.ErrNotFound) }
