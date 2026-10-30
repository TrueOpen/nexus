package buildersync

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/attempt"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatchevidence"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/opsmetrics"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/taskdata"
	"github.com/TrueOpen/nexus/internal/taskgroup"
)

const (
	defaultInputChunkBytes = 256 << 10
	defaultMaxBatchBytes   = MaxRequestBytes
	defaultRetryMin        = 500 * time.Millisecond
	defaultRetryMax        = 30 * time.Second
	defaultAlarmAfter      = 5 * time.Minute
	defaultPollInterval    = 250 * time.Millisecond
	defaultRequestTimeout  = 10 * time.Second
	// maxBatchesPerPass bounds how many batches in a row one order sends to one member before the
	// member's other orders get their turn.
	maxBatchesPerPass = 8
	// pruneEveryBlocks is how often the sync streams past their retention are dropped.
	pruneEveryBlocks = 10
	// maxChangeRetries is how many prune ticks a change that failed is applied again before it is
	// dropped (the dispatcher hands the order over again on its next change or a restart).
	maxChangeRetries = 30
	// lostProbeEvery is how often a member marked lost on an order is sent the items still held, to
	// find out whether its store was restored.
	lostProbeEvery = 10 * time.Minute
)

// Peers sends a signed batch to a member of a Task Builders group (ChainPeers).
type Peers interface {
	Sync(ctx context.Context, operator string, req *nexusv1.SyncRequest) (*nexusv1.SyncResponse, error)
}

// InputReader reads the input of an order version as OpenTask stored it, with its media type
// (StoredInputs).
type InputReader interface {
	ReadInput(ctx context.Context, sessionID, taskID, taskHash string) ([]byte, string, error)
}

// OutputReader reads a task's OUTPUT stream (taskdata.Store).
type OutputReader interface {
	// OutputFramesUpTo reads the frames after afterSeq, at most maxBytes of chunk text (at least
	// one chunk); the Fin only when every chunk fits.
	OutputFramesUpTo(ctx context.Context, key taskdata.ObjectKey, afterSeq *uint64, maxBytes int) ([]taskdata.OutputFrame, error)
	OutputStreamProgressOf(ctx context.Context, key taskdata.ObjectKey) (taskdata.OutputStreamProgress, bool, error)
}

// AttemptReader reads the current attempt of a task (attempt.Book).
type AttemptReader interface {
	Current(taskID string) (attempt.Attempt, bool)
}

// EvidenceReader finds the evidence of a ticket (dispatchevidence.Store).
type EvidenceReader interface {
	ByTicket(hash []byte) (*dispatchevidence.Order, *dispatchevidence.Attempt, bool, error)
}

// SenderConfig wires a Sender.
type SenderConfig struct {
	ChainID string
	// Builder is this Builder's operator address; Signer its service key, which signs the batches.
	Builder string
	Signer  servicekey.Signer
	Store   kv.Store
	// Groups answers the current BuilderSet snapshot: an order's group is its members.
	Groups taskgroup.Source
	// Roots finds a handraise root this Builder issued by its digest (handraise.Registry).
	Roots    func(digest [32]byte) (*taskv1.SignedHandraiseRootV1, bool, error)
	Inputs   InputReader
	Outputs  OutputReader
	Evidence EvidenceReader
	Peers    Peers
	// Retention is the last height the sync stream of an order is kept at: the retention of its
	// evidence (dispatchevidence.Params.RetainUntil).
	Retention func(*dispatchevidence.Order) uint64
	// SnapshotAt, when set, reads the BuilderSet snapshot in effect at a height from the chain: an
	// order whose snapshot was replaced before its first sync gets the group the order names.
	SnapshotAt func(ctx context.Context, height uint64) (taskgroup.Snapshot, error)
	// Attempts, when set, is looked at on a start and every few blocks for recorded orders whose
	// order item was never queued.
	Attempts AttemptReader
	// InputChunkBytes bounds the input bytes of one item; MaxBatchBytes a complete signed request
	// (at most MaxRequestBytes), which always carries at least one item or frame.
	InputChunkBytes int
	MaxBatchBytes   int
	// RetryMin and RetryMax bound the backoff after a member failed; AlarmAfter is how long a member
	// may stay failing before it is logged as an error.
	RetryMin, RetryMax time.Duration
	AlarmAfter         time.Duration
	// PollInterval is how often members are looked at for retries and new output frames;
	// RequestTimeout bounds one batch.
	PollInterval   time.Duration
	RequestTimeout time.Duration
	// Clock is nil for the system clock.
	Clock func() time.Time
	// Metrics, when set, counts the batches members rate-limited (CounterSyncRateLimited).
	Metrics *opsmetrics.Registry
	Log     *slog.Logger
}

// SenderCounts are what the sender saw since it started.
type SenderCounts struct {
	// Batches counts batches a member applied in full; Failures every failed or refused batch;
	// RateLimited every batch a member rate-limited; Alarms the times a member stayed failing past
	// AlarmAfter.
	Batches, Failures, RateLimited, Alarms uint64
}

// Sender syncs the orders this Builder dispatches to the other members of their groups.
type Sender struct {
	cfg SenderConfig
	log *slog.Logger

	mu      sync.Mutex
	streams map[string]*outStream // streamKey -> stream
	retries map[string]*retry     // streamKey|peer -> backoff
	probes  map[string]time.Time  // streamKey|peer -> next probe of a member marked lost
	workers map[string]chan struct{}
	// qmu guards queue alone, so a caller handing over a change never waits on s.mu (held while
	// a change is turned into items, which may read the chain).
	qmu    sync.Mutex
	queue  []event
	redo   map[string]event // changes that failed, applied again on the next prune ticks; under qmu
	ctx    context.Context
	cancel context.CancelFunc
	wake   chan struct{}
	wg     sync.WaitGroup

	head                                   atomic.Uint64
	lastPrune                              atomic.Uint64
	batches, failures, rateLimited, alarms atomic.Uint64
}

// event is one change handed to the sender: an order's evidence, or its winner recorded.
type event struct {
	view     *dispatchevidence.Order
	recorded *attempt.Attempt
	tries    int
}

// key names the order and kind of the change: a later change of the same kind supersedes it.
func (ev event) key() string {
	if ev.view != nil {
		return "view|" + streamKey(ev.view.SessionID, ev.view.Sequence)
	}
	return "recorded|" + streamKey(ev.recorded.SessionID, ev.recorded.Sequence)
}

// outStream is the sync stream of one order, with each member's progress and what of the order
// was turned into items already.
type outStream struct {
	SessionID      string   `json:"session_id"`
	Sequence       uint64   `json:"sequence"`
	TaskID         string   `json:"task_id"`
	BuilderSetID   string   `json:"builder_set_id"`
	BuilderSetHash []byte   `json:"builder_set_hash"`
	Peers          []string `json:"peers"`
	// Last is the last item sequence assigned; items up to Pruned were acknowledged by every
	// member and deleted.
	Last   uint64               `json:"last"`
	Pruned uint64               `json:"pruned,omitempty"`
	Acked  map[string]uint64    `json:"acked"`
	Output map[string]outputAck `json:"output,omitempty"`
	// Lost marks the members that hold fewer items than every member acknowledged (they lost
	// their store): the outbox cannot catch them up, and nothing more is sent to them.
	Lost map[string]bool `json:"lost,omitempty"`
	// Rounds (task/epoch/round), Inputs (task_hash), Attempts (ticket hash -> item digest) and
	// Record (record digest) are what was turned into items.
	Rounds   map[string]bool   `json:"rounds,omitempty"`
	Inputs   map[string]bool   `json:"inputs,omitempty"`
	Attempts map[string]string `json:"attempts,omitempty"`
	Record   string            `json:"record,omitempty"`
	// Winner is set once the order item was queued: the chain recorded it.
	Winner       *winnerRef `json:"winner,omitempty"`
	ExpireHeight uint64     `json:"expire_height"`
}

// winnerRef is the recorded winner whose output follows the order item.
type winnerRef struct {
	TaskHash     string `json:"task_hash"`
	TicketHash   []byte `json:"ticket_hash"`
	Ticket       []byte `json:"ticket"`
	AcceptDigest []byte `json:"accept_digest"`
}

// outputAck is a member's output progress as it last answered.
type outputAck struct {
	Received bool   `json:"received,omitempty"`
	LastSeq  uint64 `json:"last_seq,omitempty"`
	Sealed   bool   `json:"sealed,omitempty"`
	// NotHeld is set once the member said it keeps no output replicas.
	NotHeld bool `json:"not_held,omitempty"`
}

func (st *outStream) key() string { return streamKey(st.SessionID, st.Sequence) }

func (st *outStream) clone() *outStream {
	next := *st
	next.BuilderSetHash = append([]byte(nil), st.BuilderSetHash...)
	next.Peers = append([]string(nil), st.Peers...)
	next.Acked = cloneMap(st.Acked)
	next.Output = cloneMap(st.Output)
	next.Lost = cloneMap(st.Lost)
	next.Rounds = cloneMap(st.Rounds)
	next.Inputs = cloneMap(st.Inputs)
	next.Attempts = cloneMap(st.Attempts)
	if st.Winner != nil {
		w := *st.Winner
		next.Winner = &w
	}
	return &next
}

func cloneMap[K comparable, V any](m map[K]V) map[K]V {
	out := make(map[K]V, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// Keys of kv.NSBuilderSyncOutbox: "stream/<stream key>" holds the stream as JSON and
// "item/<stream key>/<zero-padded sequence>" each item not every member acknowledged.
const (
	outStreamPrefix = "stream/"
	outItemPrefix   = "item/"
)

func outItemKey(stream string, n uint64) string {
	return fmt.Sprintf("%s%s/%020d", outItemPrefix, stream, n)
}

// NewSender loads the stored sync streams.
func NewSender(cfg SenderConfig) (*Sender, error) {
	switch {
	case cfg.ChainID == "" || cfg.Builder == "" || cfg.Signer == nil || cfg.Store == nil || cfg.Groups == nil:
		return nil, fmt.Errorf("builder sync sender needs the chain id, Builder address, service signer, store and BuilderSet source")
	case cfg.Roots == nil || cfg.Inputs == nil || cfg.Outputs == nil || cfg.Evidence == nil || cfg.Peers == nil || cfg.Retention == nil:
		return nil, fmt.Errorf("builder sync sender needs the roots, inputs, outputs, evidence, peers and retention")
	}
	setDefault(&cfg.InputChunkBytes, defaultInputChunkBytes)
	setDefault(&cfg.MaxBatchBytes, defaultMaxBatchBytes)
	cfg.MaxBatchBytes = min(cfg.MaxBatchBytes, MaxRequestBytes)
	setDefault(&cfg.RetryMin, defaultRetryMin)
	setDefault(&cfg.RetryMax, defaultRetryMax)
	setDefault(&cfg.AlarmAfter, defaultAlarmAfter)
	setDefault(&cfg.PollInterval, defaultPollInterval)
	setDefault(&cfg.RequestTimeout, defaultRequestTimeout)
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	s := &Sender{
		cfg: cfg, log: cfg.Log, streams: map[string]*outStream{}, retries: map[string]*retry{}, probes: map[string]time.Time{},
		workers: map[string]chan struct{}{}, wake: make(chan struct{}, 1), redo: map[string]event{},
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	var decodeErr error
	err := cfg.Store.Scan(kv.NSBuilderSyncOutbox, func(key string, val []byte) bool {
		if !strings.HasPrefix(key, outStreamPrefix) {
			return key < outStreamPrefix
		}
		var st outStream
		if err := json.Unmarshal(val, &st); err != nil || outStreamPrefix+st.key() != key {
			decodeErr = fmt.Errorf("builder sync stream %q is malformed", key)
			return false
		}
		s.streams[st.key()] = &st
		return true
	})
	if err == nil {
		err = decodeErr
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}

func setDefault[T comparable](v *T, def T) {
	var zero T
	if *v == zero {
		*v = def
	}
}

// Start runs the queue and one delivery worker per member.
func (s *Sender) Start(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-s.wake:
				s.drain()
			}
		}
	}()
	for _, st := range s.streams {
		for _, peer := range st.Peers {
			s.ensureWorkerLocked(peer)
		}
	}
	s.qmu.Lock()
	queued := len(s.queue) > 0
	s.qmu.Unlock()
	if queued {
		s.signal()
	}
	go s.recheckRecorded()
	return nil
}

// recheckRecorded queues the order item of every stream the attempt book shows recorded while
// the stream has no winner: the Recorded call was lost to a crash, or failed.
func (s *Sender) recheckRecorded() {
	if s.cfg.Attempts == nil {
		return
	}
	s.mu.Lock()
	var pending []*outStream
	for _, st := range s.streams {
		if st.Winner == nil && st.TaskID != "" {
			pending = append(pending, st)
		}
	}
	s.mu.Unlock()
	for _, st := range pending {
		a, ok := s.cfg.Attempts.Current(st.TaskID)
		if ok && a.Status == attempt.Recorded && a.SessionID == st.SessionID && a.Sequence == st.Sequence {
			s.Recorded(a)
		}
	}
}

// Stop ends the queue and the workers; what is queued but not stored is lost, and the dispatcher
// hands its live orders over again after a restart.
func (s *Sender) Stop(context.Context) error {
	s.mu.Lock()
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	s.wg.Wait()
	return nil
}

// Counts returns what the sender saw since it started.
func (s *Sender) Counts() SenderCounts {
	return SenderCounts{Batches: s.batches.Load(), Failures: s.failures.Load(), RateLimited: s.rateLimited.Load(), Alarms: s.alarms.Load()}
}

// Outstanding is what one member has not acknowledged of one order's sync stream: Items sync items,
// and Output while the recorded winner's output is not sealed at the member. Peer is empty for a
// change still queued, not turned into items yet.
type Outstanding struct {
	SessionID string
	Sequence  uint64
	TaskID    string
	Peer      string
	Items     uint64
	Output    bool
}

// Outstanding lists what members have not acknowledged and the changes still queued, by order and
// member. A batch and its result headers are signed again with the current key whenever it is
// sent; the tickets, roots and records in it keep the generation that signed them, which members
// accept for orders below that generation's retirement.
func (s *Sender) Outstanding() []Outstanding {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Outstanding
	for _, ev := range s.queue {
		switch {
		case ev.view != nil:
			out = append(out, Outstanding{SessionID: ev.view.SessionID, Sequence: ev.view.Sequence, TaskID: ev.view.TaskID})
		case ev.recorded != nil:
			out = append(out, Outstanding{SessionID: ev.recorded.SessionID, Sequence: ev.recorded.Sequence, TaskID: ev.recorded.TaskID})
		}
	}
	for _, st := range s.streams {
		for _, peer := range st.Peers {
			o := Outstanding{SessionID: st.SessionID, Sequence: st.Sequence, TaskID: st.TaskID, Peer: peer}
			if acked := st.Acked[peer]; acked < st.Last {
				o.Items = st.Last - acked
			}
			o.Output = st.Winner != nil && !st.Output[peer].Sealed
			if o.Items > 0 || o.Output {
				out = append(out, o)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SessionID != out[j].SessionID {
			return out[i].SessionID < out[j].SessionID
		}
		if out[i].Sequence != out[j].Sequence {
			return out[i].Sequence < out[j].Sequence
		}
		return out[i].Peer < out[j].Peer
	})
	return out
}

// OrderChanged implements dispatcher.OrderSync: the change is queued, never sent from the caller.
func (s *Sender) OrderChanged(o *dispatchevidence.Order) { s.enqueue(event{view: o}) }

// Recorded queues the order item of an attempt the chain recorded: the user's signed order with
// the attempt's RECORDED header. It is called once the attempt book holds the attempt as
// RECORDED.
func (s *Sender) Recorded(a attempt.Attempt) {
	if a.Status != attempt.Recorded {
		return
	}
	s.enqueue(event{recorded: &a})
}

func (s *Sender) enqueue(ev event) {
	s.qmu.Lock()
	s.queue = append(s.queue, ev)
	s.qmu.Unlock()
	s.signal()
}

func (s *Sender) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// HandleChainEvent follows the head and drops the sync streams past their retention.
func (s *Sender) HandleChainEvent(ev chaincli.ChainEvent) {
	if ev.Type != chaincli.EventNewBlock || ev.Height <= 0 {
		return
	}
	head := uint64(ev.Height)
	if head <= s.head.Load() {
		return
	}
	s.head.Store(head)
	if last := s.lastPrune.Load(); head >= last+pruneEveryBlocks {
		s.lastPrune.Store(head)
		s.prune(head)
		s.recheckRecorded()
		s.retryFailed()
	}
}

// drain turns the queued changes into items.
func (s *Sender) drain() {
	for {
		s.qmu.Lock()
		if len(s.queue) == 0 {
			s.qmu.Unlock()
			return
		}
		ev := s.queue[0]
		s.queue[0] = event{}
		s.queue = s.queue[1:]
		s.qmu.Unlock()
		ctx := context.Background()
		var err error
		if ev.view != nil {
			err = s.applyView(ctx, ev.view)
		} else {
			err = s.applyRecorded(ctx, *ev.recorded)
		}
		s.settled(ev, err)
	}
}

// settled forgets a change that applied, and keeps one that failed to be applied again on the
// next prune ticks, up to maxChangeRetries times.
func (s *Sender) settled(ev event, err error) {
	key := ev.key()
	s.qmu.Lock()
	defer s.qmu.Unlock()
	if err == nil {
		delete(s.redo, key)
		return
	}
	s.failures.Add(1)
	if ev.tries >= maxChangeRetries {
		delete(s.redo, key)
		s.log.Error("order change not queued for the Task Builders group; given up after retries", "change", key, "err", err)
		return
	}
	s.redo[key] = ev
	s.log.Warn("order change not queued for the Task Builders group; applied again in a few blocks", "change", key, "err", err)
}

// retryFailed queues again the changes that failed.
func (s *Sender) retryFailed() {
	s.qmu.Lock()
	for key, ev := range s.redo {
		ev.tries++
		s.queue = append(s.queue, ev)
		delete(s.redo, key)
	}
	queued := len(s.queue) > 0
	s.qmu.Unlock()
	if queued {
		s.signal()
	}
}

// applyView turns what is new in an order's evidence into items. A new order's group is resolved
// before the stream lock is taken: it may read the chain.
func (s *Sender) applyView(ctx context.Context, view *dispatchevidence.Order) error {
	key := streamKey(view.SessionID, view.Sequence)
	s.mu.Lock()
	_, held := s.streams[key]
	s.mu.Unlock()
	var fresh *outStream
	if !held {
		var err error
		if fresh, err = s.newStream(ctx, view); err != nil || fresh == nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.streams[key]
	if st == nil {
		st = fresh
	}
	if st == nil {
		return nil // dropped past its retention meanwhile
	}
	next := st.clone()
	items, err := s.diff(ctx, next, view)
	if err != nil {
		return fmt.Errorf("order %s/%d: %w", view.SessionID, view.Sequence, err)
	}
	next.ExpireHeight = max(next.ExpireHeight, s.cfg.Retention(view))
	return s.commitLocked(next, items)
}

// applyRecorded queues the order item of a recorded winner after anything still missing of its
// evidence.
func (s *Sender) applyRecorded(ctx context.Context, a attempt.Attempt) error {
	ev, _, found, err := s.cfg.Evidence.ByTicket(a.TicketHash[:])
	if err != nil {
		return fmt.Errorf("evidence of recorded ticket %x: %w", a.TicketHash[:4], err)
	}
	if !found {
		return fmt.Errorf("no evidence of recorded ticket %x: the group cannot get the order", a.TicketHash[:4])
	}
	if err := s.applyView(ctx, ev); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.streams[streamKey(ev.SessionID, ev.Sequence)]
	if st == nil || st.Winner != nil {
		return nil
	}
	next := st.clone()
	next.Winner = &winnerRef{TaskHash: a.TaskHash, TicketHash: append([]byte(nil), a.TicketHash[:]...), Ticket: a.Ticket, AcceptDigest: append([]byte(nil), a.AcceptDigest[:]...)}
	var signed taskv1.SignedOrderV2
	if err := proto.Unmarshal(ev.SignedOrder, &signed); err != nil {
		return fmt.Errorf("signed order of recorded ticket %x: %w", a.TicketHash[:4], err)
	}
	var header nexusv1.DispatchResultHeaderV1
	if err := proto.Unmarshal(a.Header, &header); err != nil {
		return fmt.Errorf("result header of recorded ticket %x: %w", a.TicketHash[:4], err)
	}
	item := &nexusv1.BuilderSyncItemV1{Item: &nexusv1.BuilderSyncItemV1_Order{Order: &nexusv1.BuilderSyncOrderV1{
		SignedOrder: &signed, ResultHeader: &header,
	}}}
	return s.commitLocked(next, []*nexusv1.BuilderSyncItemV1{item})
}

// newStream builds a new order's stream with the other members of the order's group; nil when
// the order has no other member. It does not need s.mu.
func (s *Sender) newStream(ctx context.Context, view *dispatchevidence.Order) (*outStream, error) {
	key := streamKey(view.SessionID, view.Sequence)
	var signed taskv1.SignedOrderV2
	if err := proto.Unmarshal(view.SignedOrder, &signed); err != nil {
		return nil, fmt.Errorf("order %s: signed order: %w", key, err)
	}
	snapshot, err := taskgroup.CheckOrder(s.cfg.Groups, signed.GetOrder())
	if errors.Is(err, taskgroup.ErrBuilderSetStale) && s.cfg.SnapshotAt != nil {
		snapshot, err = s.orderSnapshot(ctx, signed.GetOrder())
	}
	if err != nil {
		return nil, fmt.Errorf("order %s: Task Builders group: %w", key, err)
	}
	group, err := taskgroup.New(snapshot, s.cfg.Builder)
	if err != nil {
		return nil, fmt.Errorf("order %s: Task Builders group: %w", key, err)
	}
	peers := group.Others(s.cfg.Builder)
	if len(peers) == 0 {
		return nil, nil
	}
	st := &outStream{
		SessionID: view.SessionID, Sequence: view.Sequence, TaskID: view.TaskID,
		BuilderSetID: group.BuilderSetID, BuilderSetHash: append([]byte(nil), group.BuilderSetHash[:]...), Peers: peers,
		Acked: map[string]uint64{}, Output: map[string]outputAck{}, Lost: map[string]bool{},
		Rounds: map[string]bool{}, Inputs: map[string]bool{}, Attempts: map[string]string{},
	}
	return st, nil
}

// orderSnapshot reads from the chain the snapshot an order names, as in effect at its
// earliest_submit_height.
func (s *Sender) orderSnapshot(ctx context.Context, order *taskv1.TaskOrderV3) (taskgroup.Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.RequestTimeout)
	defer cancel()
	snapshot, err := s.cfg.SnapshotAt(ctx, order.GetEarliestSubmitHeight())
	if err != nil {
		return taskgroup.Snapshot{}, fmt.Errorf("BuilderSet at height %d: %w", order.GetEarliestSubmitHeight(), err)
	}
	if snapshot.ID != order.GetBuilderSetId() || !bytes.Equal(snapshot.Hash[:], order.GetBuilderSetHash()) {
		return taskgroup.Snapshot{}, fmt.Errorf("%w: the chain's BuilderSet at the order's height is %q", taskgroup.ErrBuilderSetStale, snapshot.ID)
	}
	return snapshot, nil
}

// diff returns the items of what view shows that st has not turned into items yet, and marks it
// in st: a round (with the version's input the first time) before its attempts, an attempt
// whenever it changed, the record whenever it changed.
func (s *Sender) diff(ctx context.Context, st *outStream, view *dispatchevidence.Order) ([]*nexusv1.BuilderSyncItemV1, error) {
	var signed taskv1.SignedOrderV2
	if err := proto.Unmarshal(view.SignedOrder, &signed); err != nil {
		return nil, fmt.Errorf("signed order: %w", err)
	}
	order := signed.GetOrder()
	taskID, err := hex.DecodeString(view.TaskID)
	if err != nil {
		return nil, fmt.Errorf("task id: %w", err)
	}
	taskHash, err := hex.DecodeString(view.TaskHash)
	if err != nil {
		return nil, fmt.Errorf("task hash: %w", err)
	}
	var items []*nexusv1.BuilderSyncItemV1
	for _, r := range view.Rounds {
		roundKey := fmt.Sprintf("%s/%d/%d", view.TaskID, view.Epoch, r.Number)
		if !st.Rounds[roundKey] {
			if len(r.RootDigest) != 32 {
				return nil, fmt.Errorf("round %d binds no handraise root", r.Number)
			}
			root, found, err := s.cfg.Roots([32]byte(r.RootDigest))
			if err != nil || !found {
				return nil, fmt.Errorf("handraise root %x of round %d: found %v, %v", r.RootDigest[:4], r.Number, found, err)
			}
			var roster taskv1.DispatchRosterV1
			if err := proto.Unmarshal(r.Roster, &roster); err != nil {
				return nil, fmt.Errorf("roster of round %d: %w", r.Number, err)
			}
			items = append(items, &nexusv1.BuilderSyncItemV1{Item: &nexusv1.BuilderSyncItemV1_Round{Round: &nexusv1.BuilderSyncRoundV1{
				TaskId: taskID, TaskHash: taskHash, VrfEpoch: view.Epoch, DispatchRound: r.Number,
				Roster: &roster, RosterHash: r.RosterHash, HandraiseRoot: root, EarliestSubmitHeight: order.GetEarliestSubmitHeight(),
				UserAddress: order.GetUserAddress(),
			}}})
			st.Rounds[roundKey] = true
			if !st.Inputs[view.TaskHash] {
				chunks, err := s.inputItems(ctx, view, order)
				if err != nil {
					return nil, err
				}
				items = append(items, chunks...)
				st.Inputs[view.TaskHash] = true
			}
		}
		for _, a := range r.Attempts {
			item, err := attemptItem(a, view.Accept)
			if err != nil {
				return nil, fmt.Errorf("attempt of rank %d: %w", a.Rank, err)
			}
			raw, err := marshal(item)
			if err != nil {
				return nil, err
			}
			digest := sum(raw)
			fingerprint := hex.EncodeToString(digest[:])
			hash := hex.EncodeToString(a.Hash)
			if st.Attempts[hash] == fingerprint {
				continue
			}
			items = append(items, &nexusv1.BuilderSyncItemV1{Item: &nexusv1.BuilderSyncItemV1_Attempt{Attempt: item}})
			st.Attempts[hash] = fingerprint
		}
	}
	if len(view.Record) > 0 {
		digest := sum(view.Record)
		if record := hex.EncodeToString(digest[:]); st.Record != record {
			var signedRecord taskv1.DispatchRecordV1
			if err := proto.Unmarshal(view.Record, &signedRecord); err != nil {
				return nil, fmt.Errorf("signed record: %w", err)
			}
			items = append(items, &nexusv1.BuilderSyncItemV1{Item: &nexusv1.BuilderSyncItemV1_Record{Record: &nexusv1.BuilderSyncRecordV1{Record: &signedRecord}}})
			st.Record = record
		}
	}
	return items, nil
}

// attemptItem is the sync item of an attempt with the signed answers it has: the target's reject,
// a late accept, and for the winner the order's accept.
func attemptItem(a dispatchevidence.Attempt, accept []byte) (*nexusv1.BuilderSyncAttemptV1, error) {
	item := &nexusv1.BuilderSyncAttemptV1{Ticket: &taskv1.DispatchTicketV1{}, Sent: a.Sent, Outcome: a.Outcome}
	if err := proto.Unmarshal(a.Ticket, item.Ticket); err != nil {
		return nil, fmt.Errorf("ticket: %w", err)
	}
	if len(a.Reject) > 0 {
		item.Reject = &taskv1.DispatchRejectV1{}
		if err := proto.Unmarshal(a.Reject, item.Reject); err != nil {
			return nil, fmt.Errorf("reject: %w", err)
		}
	}
	if len(a.LateAccept) > 0 {
		item.LateAccept = &taskv1.DispatchAcceptV1{}
		if err := proto.Unmarshal(a.LateAccept, item.LateAccept); err != nil {
			return nil, fmt.Errorf("late accept: %w", err)
		}
	}
	if a.Outcome == outcomeAccepted && len(accept) > 0 {
		item.Accept = &taskv1.DispatchAcceptV1{}
		if err := proto.Unmarshal(accept, item.Accept); err != nil {
			return nil, fmt.Errorf("accept: %w", err)
		}
	}
	return item, nil
}

// inputItems are the input of the order version cut into pieces.
func (s *Sender) inputItems(ctx context.Context, view *dispatchevidence.Order, order *taskv1.TaskOrderV3) ([]*nexusv1.BuilderSyncItemV1, error) {
	data, mediaType, err := s.cfg.Inputs.ReadInput(ctx, view.SessionID, view.TaskID, view.TaskHash)
	if err != nil {
		return nil, fmt.Errorf("input of the order: %w", err)
	}
	inputHash := sum(data)
	if !bytes.Equal(inputHash[:], order.GetInputHash()) {
		return nil, fmt.Errorf("stored input does not hash to the order's input_hash")
	}
	var items []*nexusv1.BuilderSyncItemV1
	for offset := 0; offset < len(data) || offset == 0; offset += s.cfg.InputChunkBytes {
		end := min(offset+s.cfg.InputChunkBytes, len(data))
		items = append(items, &nexusv1.BuilderSyncItemV1{Item: &nexusv1.BuilderSyncItemV1_InputChunk{InputChunk: &nexusv1.BuilderSyncInputChunkV1{
			TaskHash: mustHex(view.TaskHash), InputHash: inputHash[:], InputSizeBytes: uint64(len(data)), MediaType: mediaType,
			Offset: uint64(offset), Data: data[offset:end],
		}}})
		if end == len(data) {
			break
		}
	}
	return items, nil
}

func mustHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

// commitLocked numbers items after next.Last and stores them with next in one write, then makes
// next the stream and wakes its members' workers. Caller holds s.mu.
func (s *Sender) commitLocked(next *outStream, items []*nexusv1.BuilderSyncItemV1) error {
	cur := s.streams[next.key()]
	if len(items) == 0 && cur != nil && cur.ExpireHeight == next.ExpireHeight {
		return nil
	}
	ops := make([]kv.WriteOp, 0, len(items)+1)
	for _, item := range items {
		next.Last++
		item.Sequence = next.Last
		raw, err := marshal(item)
		if err != nil {
			return err
		}
		ops = append(ops, kv.WriteOp{NS: kv.NSBuilderSyncOutbox, Key: outItemKey(next.key(), next.Last), Val: raw})
	}
	op, err := streamOp(next)
	if err != nil {
		return err
	}
	if err := s.cfg.Store.WriteBatch(append(ops, op)...); err != nil {
		return fmt.Errorf("store sync items: %w", err)
	}
	s.streams[next.key()] = next
	for _, peer := range next.Peers {
		s.ensureWorkerLocked(peer)
		s.wakeWorkerLocked(peer)
	}
	return nil
}

func streamOp(st *outStream) (kv.WriteOp, error) {
	raw, err := json.Marshal(st)
	if err != nil {
		return kv.WriteOp{}, fmt.Errorf("encode sync stream: %w", err)
	}
	return kv.WriteOp{NS: kv.NSBuilderSyncOutbox, Key: outStreamPrefix + st.key(), Val: raw}, nil
}

// prune drops the sync streams whose retention ended before head, with their items.
func (s *Sender) prune(head uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, st := range s.streams {
		if st.ExpireHeight == 0 || st.ExpireHeight >= head {
			continue
		}
		ops := []kv.WriteOp{{NS: kv.NSBuilderSyncOutbox, Key: outStreamPrefix + key, Delete: true}}
		for n := st.Pruned + 1; n <= st.Last; n++ {
			ops = append(ops, kv.WriteOp{NS: kv.NSBuilderSyncOutbox, Key: outItemKey(key, n), Delete: true})
		}
		if err := s.cfg.Store.WriteBatch(ops...); err != nil {
			s.log.Warn("expired sync stream not deleted", "order", key, "err", err)
			continue
		}
		delete(s.streams, key)
		for _, peer := range st.Peers {
			delete(s.retries, key+"|"+peer)
			delete(s.probes, key+"|"+peer)
		}
	}
}
