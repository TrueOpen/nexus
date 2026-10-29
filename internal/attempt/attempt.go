// Package attempt keeps the winning dispatch attempt of every order this Builder dispatched: the
// winner ticket, the Worker's accept and how the chain took the order's dispatch entry.
//
// The attempt is what the output data plane trusts before the chain knows the task: a Worker may
// stream output and read the input only for the ticket it accepted, subscribers get the
// Builder-signed DispatchResultHeaderV1 of the attempt first, and output beyond
// max_prerecord_output_tokens waits for the record. A task has one current attempt. It is PENDING
// from the accept, RECORDED once the chain admitted the entry and REJECTED once it refused it; a
// retry of the sequence replaces a REJECTED attempt, a binding change that voids the winner
// removes it, and a RECORDED attempt is final.
//
// Every attempt is stored with its Builder-signed header at its status, so a restart serves the
// same bytes; the header is signed again only when the status changes.
package attempt

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/signer"
)

// Status is the record status of an attempt.
type Status = taskv1.DispatchRecordStatusV1

const (
	Pending  = taskv1.DispatchRecordStatusV1_DISPATCH_RECORD_STATUS_V1_PENDING
	Recorded = taskv1.DispatchRecordStatusV1_DISPATCH_RECORD_STATUS_V1_RECORDED
	Rejected = taskv1.DispatchRecordStatusV1_DISPATCH_RECORD_STATUS_V1_REJECTED
)

// Winner is an accepted ticket as the dispatcher hands it over: the signed winner ticket and the
// Worker's signed accept of it.
type Winner struct {
	SessionID string
	Sequence  uint64
	Ticket    *taskv1.DispatchTicketV1
	Accept    *taskv1.DispatchAcceptV1
}

// Attempt is the current dispatch attempt of a task. Hashes are lowercase hex.
type Attempt struct {
	SessionID string `json:"session_id"`
	Sequence  uint64 `json:"sequence"`
	TaskID    string `json:"task_id"`
	TaskHash  string `json:"task_hash"`
	InputHash string `json:"input_hash"`
	// Worker is the operator address of the ticket's target.
	Worker       string   `json:"worker"`
	TicketHash   [32]byte `json:"ticket_hash"`
	AcceptDigest [32]byte `json:"accept_digest"`
	Status       Status   `json:"status"`
	// Ticket and Accept are the winner ticket and the accept as handed over.
	Ticket []byte `json:"ticket"`
	Accept []byte `json:"accept"`
	// Header is the Builder-signed DispatchResultHeaderV1 at Status, as signed.
	Header []byte `json:"header"`
}

// Live reports whether output of the attempt may still be taken and delivered: its record is
// pending or admitted.
func (a Attempt) Live() bool { return a.Status == Pending || a.Status == Recorded }

// ResultHeader decodes the signed header.
func (a Attempt) ResultHeader() (*nexusv1.DispatchResultHeaderV1, error) {
	var h nexusv1.DispatchResultHeaderV1
	if err := proto.Unmarshal(a.Header, &h); err != nil {
		return nil, fmt.Errorf("decode stored result header: %w", err)
	}
	return &h, nil
}

// Book holds the current attempt of every task. It is safe for concurrent use.
type Book struct {
	store  kv.Store
	signer signer.Signer
	log    *slog.Logger

	maxPrerecord atomic.Uint64

	mu       sync.Mutex
	byTask   map[string]*Attempt
	voided   map[[32]byte]bool
	watchers map[string]map[uint64]chan struct{}
	nextID   uint64
}

// New loads the stored attempts. s is the Builder service key that signs the result headers.
func New(store kv.Store, s signer.Signer, log *slog.Logger) (*Book, error) {
	if store == nil || s == nil {
		return nil, fmt.Errorf("attempt book needs a store and the service signer")
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	b := &Book{
		store: store, signer: s, log: log,
		byTask: map[string]*Attempt{}, voided: map[[32]byte]bool{}, watchers: map[string]map[uint64]chan struct{}{},
	}
	var loadErr error
	err := store.Scan(kv.NSDispatchAttempt, func(key string, val []byte) bool {
		var a Attempt
		if err := json.Unmarshal(val, &a); err != nil || a.TaskID != key {
			loadErr = fmt.Errorf("dispatch attempt %q is malformed", key)
			return false
		}
		b.byTask[key] = &a
		return true
	})
	if err != nil {
		return nil, fmt.Errorf("scan dispatch attempts: %w", err)
	}
	return b, loadErr
}

// SetMaxPrerecordTokens sets max_prerecord_output_tokens: before an attempt is recorded, output is
// forwarded to subscribers only up to this many cumulative generated tokens.
func (b *Book) SetMaxPrerecordTokens(n uint64) { b.maxPrerecord.Store(n) }

// MaxPrerecordTokens returns max_prerecord_output_tokens.
func (b *Book) MaxPrerecordTokens() uint64 { return b.maxPrerecord.Load() }

// Accepted makes an accepted ticket its task's PENDING attempt. The same ticket again changes
// nothing; a ticket voided before its accept arrived is dropped; a RECORDED attempt is never
// replaced.
func (b *Book) Accepted(w Winner) error {
	ticketHash, err := digestOf(ticketName, w.Ticket)
	if err != nil {
		return err
	}
	acceptDigest, err := digestOf(acceptName, w.Accept)
	if err != nil {
		return err
	}
	if !bytes.Equal(w.Accept.GetDispatchTicketHash(), ticketHash[:]) || !bytes.Equal(w.Accept.GetTaskId(), w.Ticket.GetTaskId()) {
		return fmt.Errorf("accept does not name ticket %x", ticketHash)
	}
	ticket, err := marshal(w.Ticket)
	if err != nil {
		return err
	}
	accept, err := marshal(w.Accept)
	if err != nil {
		return err
	}
	a := &Attempt{
		SessionID: w.SessionID, Sequence: w.Sequence,
		TaskID: hex.EncodeToString(w.Ticket.GetTaskId()), TaskHash: hex.EncodeToString(w.Ticket.GetTaskHash()),
		InputHash: hex.EncodeToString(w.Ticket.GetInputHash()), Worker: w.Ticket.GetTarget().GetOperatorAddress(),
		TicketHash: ticketHash, AcceptDigest: acceptDigest, Ticket: ticket, Accept: accept,
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.voided[ticketHash] {
		delete(b.voided, ticketHash)
		return nil
	}
	if cur := b.byTask[a.TaskID]; cur != nil {
		switch {
		case cur.TicketHash == ticketHash:
			return nil
		case cur.Status == Recorded:
			return fmt.Errorf("task %s is recorded with ticket %x", a.TaskID, cur.TicketHash)
		}
	}
	return b.setLocked(a, Pending)
}

// Voided removes a PENDING attempt whose winner ticket a binding change voided. A void that comes
// before its accept keeps that accept out.
func (b *Book) Voided(taskID string, ticketHash [32]byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	cur := b.byTask[taskID]
	if cur == nil || cur.TicketHash != ticketHash {
		b.voided[ticketHash] = true
		return
	}
	if cur.Status != Pending {
		return
	}
	if err := b.store.Delete(kv.NSDispatchAttempt, taskID); err != nil {
		b.log.Error("voided dispatch attempt not deleted", "task_id", taskID, "err", err)
	}
	delete(b.byTask, taskID)
	b.notifyLocked(taskID)
}

// Recorded marks the attempt of ticketHash RECORDED: the chain admitted its dispatch entry.
func (b *Book) Recorded(taskID string, ticketHash [32]byte) { b.settle(taskID, ticketHash, Recorded) }

// Rejected marks the attempt of ticketHash REJECTED: the chain refused its dispatch entry or did
// not record it in time.
func (b *Book) Rejected(taskID string, ticketHash [32]byte) { b.settle(taskID, ticketHash, Rejected) }

func (b *Book) settle(taskID string, ticketHash [32]byte, status Status) {
	b.mu.Lock()
	defer b.mu.Unlock()
	cur := b.byTask[taskID]
	if cur == nil || cur.TicketHash != ticketHash || cur.Status != Pending {
		return
	}
	next := *cur
	if err := b.setLocked(&next, status); err != nil {
		b.log.Error("dispatch attempt status not stored", "task_id", taskID, "status", status, "err", err)
	}
}

// setLocked signs a's header at status, stores a as its task's attempt and tells the watchers.
// Caller holds b.mu.
func (b *Book) setLocked(a *Attempt, status Status) error {
	h := &nexusv1.DispatchResultHeaderV1{
		WinnerTicket: &taskv1.DispatchTicketV1{}, Accept: &taskv1.DispatchAcceptV1{}, RecordStatus: status,
	}
	if err := proto.Unmarshal(a.Ticket, h.WinnerTicket); err != nil {
		return fmt.Errorf("decode winner ticket: %w", err)
	}
	if err := proto.Unmarshal(a.Accept, h.Accept); err != nil {
		return fmt.Errorf("decode accept: %w", err)
	}
	h.TaskId = h.WinnerTicket.GetTaskId()
	header, err := SignResultHeader(b.signer, h)
	if err != nil {
		return err
	}
	a.Status, a.Header = status, header
	raw, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("encode dispatch attempt: %w", err)
	}
	if err := b.store.Set(kv.NSDispatchAttempt, a.TaskID, raw); err != nil {
		return fmt.Errorf("write dispatch attempt: %w", err)
	}
	b.byTask[a.TaskID] = a
	b.notifyLocked(a.TaskID)
	return nil
}

// Current returns the task's current attempt.
func (b *Book) Current(taskID string) (Attempt, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	a := b.byTask[taskID]
	if a == nil {
		return Attempt{}, false
	}
	return *a, true
}

// Watch returns a channel that receives a value whenever the task's attempt changes, and the
// function that stops the watch. Changes in a row may arrive as one value; read Current after.
func (b *Book) Watch(taskID string) (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	b.mu.Lock()
	b.nextID++
	id := b.nextID
	if b.watchers[taskID] == nil {
		b.watchers[taskID] = map[uint64]chan struct{}{}
	}
	b.watchers[taskID][id] = ch
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if w := b.watchers[taskID]; w != nil {
			delete(w, id)
			if len(w) == 0 {
				delete(b.watchers, taskID)
			}
		}
	}
}

func (b *Book) notifyLocked(taskID string) {
	for _, ch := range b.watchers[taskID] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
