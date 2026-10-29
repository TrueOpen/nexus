// Package attempt keeps the winning dispatch attempt of every order this Builder dispatched: the
// winner ticket, the Worker's accept and how the chain took the order's dispatch entry.
//
// The attempt is what the output data plane trusts before the chain knows the task: a Worker may
// stream output and read the input only for the ticket it accepted, subscribers get the
// Builder-signed DispatchResultHeaderV1 of the attempt first, and output beyond
// max_prerecord_output_tokens waits for the record. A task has one current attempt. It is PENDING
// from the accept, RECORDED once the chain admitted the entry and REJECTED once it refused it; a
// retry of the sequence replaces a REJECTED attempt, a binding change that voids the winner
// removes it, and a RECORDED attempt is final. A voided winner is kept aside: if the chain admits
// its entry after all (the withdrawal came too late), it becomes the task's RECORDED attempt and
// replaces a later round's PENDING one.
//
// Every attempt is stored with its Builder-signed header at its status, so a restart serves the
// same bytes; the header is signed again only when the status changes.
package attempt

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
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

// ErrRecordedWithAnotherTicket refuses an accept for a task the chain recorded with another
// ticket: it never becomes the task's attempt, and trying again does not change that.
var ErrRecordedWithAnotherTicket = errors.New("task is recorded with another ticket")

// Winner is an accepted ticket as the dispatcher hands it over: the signed winner ticket and the
// Worker's signed accept of it.
type Winner struct {
	SessionID string
	Sequence  uint64
	// User is the order's user_address: the one subscriber of the task's output.
	User   string
	Ticket *taskv1.DispatchTicketV1
	Accept *taskv1.DispatchAcceptV1
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
	// User is the order's user_address, the task's one output subscriber; it outlives the task
	// so a subscriber after a refused record still gets the REJECTED header.
	User string `json:"user,omitempty"`
	// UploadUntil is the last height output may be uploaded at (the task's infer deadline once
	// recorded); 0 sets no height. UploadsClosed is set once the task is terminal.
	UploadUntil   uint64 `json:"upload_until,omitempty"`
	UploadsClosed bool   `json:"uploads_closed,omitempty"`
	// ExpireHeight, once set, is the height from which the attempt is forgotten (Sweep).
	ExpireHeight uint64 `json:"expire_height,omitempty"`
}

// Live reports whether output of the attempt may still be taken and delivered: its record is
// pending or admitted.
func (a Attempt) Live() bool { return a.Status == Pending || a.Status == Recorded }

// AcceptsUploads reports whether the Worker may still upload output for the attempt with the
// chain head at head: it is live, the task is not terminal and head is not past UploadUntil. A
// head of 0 (not known) skips the height check.
func (a Attempt) AcceptsUploads(head uint64) bool {
	return a.Live() && !a.UploadsClosed && (a.UploadUntil == 0 || head == 0 || head <= a.UploadUntil)
}

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

	mu     sync.Mutex
	byTask map[string]*Attempt
	voided map[[32]byte]bool
	// aside holds the PENDING attempts a binding change voided, by task and ticket.
	aside    map[string]map[[32]byte]*Attempt
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
		byTask: map[string]*Attempt{}, voided: map[[32]byte]bool{}, aside: map[string]map[[32]byte]*Attempt{},
		watchers: map[string]map[uint64]chan struct{}{},
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
	if loadErr != nil {
		return nil, loadErr
	}
	err = store.Scan(kv.NSDispatchAttemptVoided, func(key string, val []byte) bool {
		var a Attempt
		if err := json.Unmarshal(val, &a); err != nil || asideKey(a.TaskID, a.TicketHash) != key {
			loadErr = fmt.Errorf("voided dispatch attempt %q is malformed", key)
			return false
		}
		b.putAsideMemLocked(&a)
		return true
	})
	if err != nil {
		return nil, fmt.Errorf("scan voided dispatch attempts: %w", err)
	}
	return b, loadErr
}

func asideKey(taskID string, ticketHash [32]byte) string {
	return taskID + "|" + hex.EncodeToString(ticketHash[:])
}

func (b *Book) putAsideMemLocked(a *Attempt) {
	if b.aside[a.TaskID] == nil {
		b.aside[a.TaskID] = map[[32]byte]*Attempt{}
	}
	b.aside[a.TaskID][a.TicketHash] = a
}

// dropAsideLocked forgets the task's voided attempts. Caller holds b.mu.
func (b *Book) dropAsideLocked(taskID string) {
	for ticketHash := range b.aside[taskID] {
		if err := b.store.Delete(kv.NSDispatchAttemptVoided, asideKey(taskID, ticketHash)); err != nil {
			b.log.Error("voided dispatch attempt not deleted", "task_id", taskID, "err", err)
		}
	}
	delete(b.aside, taskID)
}

// SetMaxPrerecordTokens sets max_prerecord_output_tokens: before an attempt is recorded, output is
// forwarded to subscribers only up to this many cumulative generated tokens. 0 forwards nothing
// before the record, and a chunk with text that reports 0 tokens is not forwarded either.
func (b *Book) SetMaxPrerecordTokens(n uint64) { b.maxPrerecord.Store(n) }

// MaxPrerecordTokens returns max_prerecord_output_tokens.
func (b *Book) MaxPrerecordTokens() uint64 { return b.maxPrerecord.Load() }

// Accepted makes an accepted ticket its task's PENDING attempt. The same ticket again changes
// nothing; a ticket voided before its accept arrived is dropped; a RECORDED attempt is never
// replaced (ErrRecordedWithAnotherTicket). A PENDING attempt of another ticket should have been
// voided first: it is replaced, and that is logged as an error.
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
		SessionID: w.SessionID, Sequence: w.Sequence, User: w.User,
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
			return fmt.Errorf("%w: task %s, ticket %x", ErrRecordedWithAnotherTicket, a.TaskID, cur.TicketHash)
		case cur.Status == Pending:
			b.log.Error("pending dispatch attempt replaced by another accepted ticket without a void",
				"task_id", a.TaskID, "replaced_ticket", hex.EncodeToString(cur.TicketHash[:]), "ticket", hex.EncodeToString(ticketHash[:]))
		}
	}
	return b.setLocked(a, Pending)
}

// Voided removes a PENDING attempt whose winner ticket a binding change voided and keeps it aside
// in case the chain admitted its entry anyway. A void that comes before its accept keeps that
// accept out.
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
	raw, err := json.Marshal(cur)
	if err == nil {
		err = b.store.WriteBatch(
			kv.WriteOp{NS: kv.NSDispatchAttemptVoided, Key: asideKey(taskID, ticketHash), Val: raw},
			kv.WriteOp{NS: kv.NSDispatchAttempt, Key: taskID, Delete: true},
		)
	}
	if err != nil {
		b.log.Error("voided dispatch attempt not stored", "task_id", taskID, "err", err)
	}
	b.putAsideMemLocked(cur)
	delete(b.byTask, taskID)
	b.notifyLocked(taskID)
}

// Recorded marks the attempt of ticketHash RECORDED: the chain admitted its dispatch entry. A
// voided attempt of that ticket becomes the task's attempt again, RECORDED, in place of a later
// round's PENDING or REJECTED one.
func (b *Book) Recorded(taskID string, ticketHash [32]byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	cur := b.byTask[taskID]
	if cur != nil && cur.TicketHash == ticketHash {
		b.settleLocked(cur, Recorded)
		return
	}
	if cur != nil && cur.Status == Recorded {
		b.log.Error("dispatch record of another ticket for a recorded task ignored", "task_id", taskID,
			"recorded_ticket", hex.EncodeToString(cur.TicketHash[:]), "ticket", hex.EncodeToString(ticketHash[:]))
		return
	}
	aside := b.aside[taskID][ticketHash]
	if aside == nil {
		return
	}
	if cur != nil {
		b.log.Warn("the chain recorded a voided winner: it replaces the task's attempt", "task_id", taskID,
			"replaced_ticket", hex.EncodeToString(cur.TicketHash[:]), "ticket", hex.EncodeToString(ticketHash[:]))
	}
	next := *aside
	if err := b.setLocked(&next, Recorded); err != nil {
		b.log.Error("recorded voided dispatch attempt not stored", "task_id", taskID, "err", err)
	}
}

// Rejected marks the attempt of ticketHash REJECTED: the chain refused its dispatch entry or did
// not record it in time.
func (b *Book) Rejected(taskID string, ticketHash [32]byte) { b.settle(taskID, ticketHash, Rejected) }

func (b *Book) settle(taskID string, ticketHash [32]byte, status Status) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if cur := b.byTask[taskID]; cur != nil && cur.TicketHash == ticketHash {
		b.settleLocked(cur, status)
	}
}

// settleLocked moves the PENDING attempt cur to status. Caller holds b.mu.
func (b *Book) settleLocked(cur *Attempt, status Status) {
	if cur.Status != Pending {
		return
	}
	next := *cur
	if err := b.setLocked(&next, status); err != nil {
		b.log.Error("dispatch attempt status not stored", "task_id", cur.TaskID, "status", status, "err", err)
	}
}

// LimitUploads sets the last height output of the task's attempt of ticketHash may be uploaded
// at (its infer deadline). Another ticket's attempt is left alone.
func (b *Book) LimitUploads(taskID string, ticketHash [32]byte, until uint64) {
	b.update(taskID, func(a *Attempt) bool {
		if a.TicketHash != ticketHash || a.UploadUntil == until {
			return false
		}
		a.UploadUntil = until
		return true
	})
}

// CloseUploads stops output uploads for the task's attempt: the task is terminal.
func (b *Book) CloseUploads(taskID string) {
	b.update(taskID, func(a *Attempt) bool {
		if a.UploadsClosed {
			return false
		}
		a.UploadsClosed = true
		return true
	})
}

// ExpireAt has the task forgotten by the first Sweep at or after height; the attempt and its
// header are served until then. An earlier expiry already set is kept.
func (b *Book) ExpireAt(taskID string, height uint64) {
	b.update(taskID, func(a *Attempt) bool {
		if a.ExpireHeight != 0 && a.ExpireHeight <= height {
			return false
		}
		a.ExpireHeight = height
		return true
	})
}

// Sweep forgets the tasks whose expiry height is at or below head.
func (b *Book) Sweep(head uint64) {
	b.mu.Lock()
	var expired []string
	for taskID, a := range b.byTask {
		if a.ExpireHeight != 0 && a.ExpireHeight <= head {
			expired = append(expired, taskID)
		}
	}
	b.mu.Unlock()
	for _, taskID := range expired {
		b.Forget(taskID)
	}
}

// update applies change to a copy of the task's attempt and stores it when change reports a
// change. The signed header is not touched.
func (b *Book) update(taskID string, change func(*Attempt) bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	cur := b.byTask[taskID]
	if cur == nil {
		return
	}
	next := *cur
	if !change(&next) {
		return
	}
	raw, err := json.Marshal(&next)
	if err == nil {
		err = b.store.Set(kv.NSDispatchAttempt, taskID, raw)
	}
	if err != nil {
		b.log.Error("dispatch attempt not stored", "task_id", taskID, "err", err)
		return
	}
	b.byTask[taskID] = &next
	b.notifyLocked(taskID)
}

// Forget drops everything held for the task: its attempt and its voided ones. It is called once
// the task is terminal, and the task's watchers hear of it.
func (b *Book) Forget(taskID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.dropAsideLocked(taskID)
	if _, ok := b.byTask[taskID]; !ok {
		return
	}
	if err := b.store.Delete(kv.NSDispatchAttempt, taskID); err != nil {
		b.log.Error("dispatch attempt not deleted", "task_id", taskID, "err", err)
	}
	delete(b.byTask, taskID)
	b.notifyLocked(taskID)
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
	if status == Recorded {
		// The record is final: no voided attempt of the task can be admitted any more.
		b.dropAsideLocked(a.TaskID)
	}
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
