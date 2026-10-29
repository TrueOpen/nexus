package dispatchevidence

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/kv"
)

// Keys of kv.NSDispatchEvidence:
//
//	order/<evidence key>    the Order as JSON
//	ticket/<hash hex>       evidence key of the order whose task the ticket names
//	task/<task id hex>      JSON list of the evidence keys of a task
//	root/<digest hex>       how many retained orders bind the handraise root
//
// kv.NSDispatchEvidencePrune holds "<zero-padded RetainUntil>/<evidence key>".
const (
	orderPrefix  = "order/"
	ticketPrefix = "ticket/"
	taskPrefix   = "task/"
	rootPrefix   = "root/"
)

func pruneKey(height uint64, key string) string { return fmt.Sprintf("%020d/%s", height, key) }

// Store is the evidence store. Its writes are serialized; reads go to the KV store directly.
type Store struct {
	kv     kv.Store
	params atomic.Pointer[Params]
	mu     sync.Mutex
}

// New builds a Store over kv with the current windows.
func New(store kv.Store, p Params) *Store {
	s := &Store{kv: store}
	s.SetParams(p)
	return s
}

// SetParams replaces the windows after a params change; evidence already stored keeps its
// RetainUntil.
func (s *Store) SetParams(p Params) { s.params.Store(&p) }

// Params returns the windows in use.
func (s *Store) Params() Params { return *s.params.Load() }

// Put stores o, replacing the evidence of the same key, with extra written in the same batch.
// RetainUntil never moves earlier than what was stored or extended before.
func (s *Store) Put(o *Order, extra ...kv.WriteOp) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	o.RetainUntil = s.params.Load().RetainUntil(o)
	old, found, err := s.load(o.Key())
	if err != nil {
		return err
	}
	if found {
		o.RetainUntil = max(o.RetainUntil, old.RetainUntil)
	}
	ops, err := s.indexOps(old, o)
	if err != nil {
		return err
	}
	return s.kv.WriteBatch(append(ops, extra...)...)
}

// Extend keeps the evidence of key at least until height: a claim or challenge on it is open.
func (s *Store) Extend(key string, height uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, found, err := s.load(key)
	if err != nil || !found || o.RetainUntil >= height {
		return err
	}
	next := *o
	next.RetainUntil = height
	ops, err := s.indexOps(o, &next)
	if err != nil {
		return err
	}
	return s.kv.WriteBatch(ops...)
}

// MarkRecorded marks the evidence holding a ticket as recorded at height, for an order the chain
// recorded after the dispatcher let it go; its retention only grows. An unknown ticket is no
// error: there is nothing to mark.
func (s *Store) MarkRecorded(ticketHash []byte, height uint64) error {
	o, _, found, err := s.ByTicket(ticketHash)
	if err != nil || !found || o.Recorded && o.RecordedHeight >= height {
		return err
	}
	o.Recorded, o.RecordedHeight = true, height
	return s.Put(o)
}

// Prune deletes the evidence whose RetainUntil is below height and returns how many it deleted.
func (s *Store) Prune(height uint64) (int, error) {
	var keys []string
	var scanErr error
	err := s.kv.Scan(kv.NSDispatchEvidencePrune, func(key string, _ []byte) bool {
		at, evidence, ok := strings.Cut(key, "/")
		until, err := strconv.ParseUint(at, 10, 64)
		if !ok || err != nil {
			scanErr = fmt.Errorf("malformed evidence prune key %q", key)
			return false
		}
		if until >= height {
			return false
		}
		keys = append(keys, evidence)
		return true
	})
	if err == nil {
		err = scanErr
	}
	if err != nil {
		return 0, fmt.Errorf("scan evidence prune index: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pruned := 0
	for _, key := range keys {
		o, found, err := s.load(key)
		if err != nil {
			return pruned, err
		}
		if !found || o.RetainUntil >= height {
			continue
		}
		ops, err := s.indexOps(o, nil)
		if err != nil {
			return pruned, err
		}
		if err := s.kv.WriteBatch(ops...); err != nil {
			return pruned, fmt.Errorf("prune evidence: %w", err)
		}
		pruned++
	}
	return pruned, nil
}

// ByTicket returns the evidence and attempt of a ticket hash.
func (s *Store) ByTicket(hash []byte) (*Order, *Attempt, bool, error) {
	key, found, err := s.kv.GetWithError(kv.NSDispatchEvidence, ticketPrefix+hex.EncodeToString(hash))
	if err != nil || !found {
		return nil, nil, false, err
	}
	o, found, err := s.load(string(key))
	if err != nil || !found {
		return nil, nil, false, err
	}
	a, ok := o.Attempt(hash)
	if !ok {
		return nil, nil, false, fmt.Errorf("evidence %s does not hold the ticket indexed to it", key)
	}
	return o, a, true, nil
}

// ByTask returns every retained evidence of a task_id (hex).
func (s *Store) ByTask(taskID string) ([]*Order, error) {
	keys, err := s.taskKeys(taskID)
	if err != nil {
		return nil, err
	}
	var out []*Order
	for _, key := range keys {
		o, found, err := s.load(key)
		if err != nil {
			return nil, err
		}
		if found {
			out = append(out, o)
		}
	}
	return out, nil
}

// Scan calls fn with every retained evidence until it returns false.
func (s *Store) Scan(fn func(*Order) bool) error {
	var decodeErr error
	err := s.kv.Scan(kv.NSDispatchEvidence, func(key string, val []byte) bool {
		if !strings.HasPrefix(key, orderPrefix) {
			return key < orderPrefix
		}
		var o Order
		if err := json.Unmarshal(val, &o); err != nil {
			decodeErr = fmt.Errorf("evidence %q is malformed: %w", key, err)
			return false
		}
		return fn(&o)
	})
	if err == nil {
		err = decodeErr
	}
	return err
}

// ReferencesRoot reports whether retained evidence binds the handraise root: such a root must not
// be pruned. A failed read counts as referenced.
func (s *Store) ReferencesRoot(digest [32]byte) bool {
	n, err := s.rootCount(hex.EncodeToString(digest[:]))
	return err != nil || n > 0
}

func (s *Store) load(key string) (*Order, bool, error) {
	val, found, err := s.kv.GetWithError(kv.NSDispatchEvidence, orderPrefix+key)
	if err != nil || !found {
		return nil, false, err
	}
	var o Order
	if err := json.Unmarshal(val, &o); err != nil {
		return nil, false, fmt.Errorf("evidence %q is malformed: %w", key, err)
	}
	return &o, true, nil
}

func (s *Store) taskKeys(taskID string) ([]string, error) {
	val, found, err := s.kv.GetWithError(kv.NSDispatchEvidence, taskPrefix+taskID)
	if err != nil || !found {
		return nil, err
	}
	var keys []string
	if err := json.Unmarshal(val, &keys); err != nil {
		return nil, fmt.Errorf("evidence task index %q is malformed: %w", taskID, err)
	}
	return keys, nil
}

func (s *Store) rootCount(digest string) (uint64, error) {
	val, found, err := s.kv.GetWithError(kv.NSDispatchEvidence, rootPrefix+digest)
	if err != nil || !found {
		return 0, err
	}
	return strconv.ParseUint(string(val), 10, 64)
}

// indexOps are the writes that replace old with next (either may be nil): the record, its prune
// index entry, the ticket and task indexes and the root reference counts. Caller holds s.mu.
func (s *Store) indexOps(old, next *Order) ([]kv.WriteOp, error) {
	var ops []kv.WriteOp
	key := ""
	if next != nil {
		key = next.Key()
	} else {
		key = old.Key()
	}
	if old != nil && (next == nil || old.RetainUntil != next.RetainUntil) {
		ops = append(ops, kv.WriteOp{NS: kv.NSDispatchEvidencePrune, Key: pruneKey(old.RetainUntil, key), Delete: true})
	}
	if next != nil {
		raw, err := json.Marshal(next)
		if err != nil {
			return nil, fmt.Errorf("encode evidence: %w", err)
		}
		ops = append(ops,
			kv.WriteOp{NS: kv.NSDispatchEvidence, Key: orderPrefix + key, Val: raw},
			kv.WriteOp{NS: kv.NSDispatchEvidencePrune, Key: pruneKey(next.RetainUntil, key), Val: []byte{}})
	} else {
		ops = append(ops, kv.WriteOp{NS: kv.NSDispatchEvidence, Key: orderPrefix + key, Delete: true})
	}

	oldTickets, nextTickets := ownTickets(old), ownTickets(next)
	for hash := range oldTickets {
		if !nextTickets[hash] {
			if current, found, _ := s.kv.GetWithError(kv.NSDispatchEvidence, ticketPrefix+hash); found && string(current) == key {
				ops = append(ops, kv.WriteOp{NS: kv.NSDispatchEvidence, Key: ticketPrefix + hash, Delete: true})
			}
		}
	}
	for hash := range nextTickets {
		ops = append(ops, kv.WriteOp{NS: kv.NSDispatchEvidence, Key: ticketPrefix + hash, Val: []byte(key)})
	}

	taskOp, err := s.taskOp(old, next, key)
	if err != nil {
		return nil, err
	}
	if taskOp != nil {
		ops = append(ops, *taskOp)
	}

	oldRoots, nextRoots := roots(old), roots(next)
	for digest := range unionKeys(oldRoots, nextRoots) {
		if oldRoots[digest] == nextRoots[digest] {
			continue
		}
		n, err := s.rootCount(digest)
		if err != nil {
			return nil, fmt.Errorf("evidence root reference %s: %w", digest, err)
		}
		if oldRoots[digest] {
			n = max(n, 1) - 1
		} else {
			n++
		}
		if n == 0 {
			ops = append(ops, kv.WriteOp{NS: kv.NSDispatchEvidence, Key: rootPrefix + digest, Delete: true})
		} else {
			ops = append(ops, kv.WriteOp{NS: kv.NSDispatchEvidence, Key: rootPrefix + digest, Val: []byte(strconv.FormatUint(n, 10))})
		}
	}
	return ops, nil
}

// taskOp adds or removes key in the task index. Caller holds s.mu.
func (s *Store) taskOp(old, next *Order, key string) (*kv.WriteOp, error) {
	if old != nil && next != nil {
		return nil, nil // the same key always names the same task
	}
	taskID := ""
	if next != nil {
		taskID = next.TaskID
	} else {
		taskID = old.TaskID
	}
	keys, err := s.taskKeys(taskID)
	if err != nil {
		return nil, err
	}
	i := slices.Index(keys, key)
	switch {
	case next != nil && i < 0:
		keys = append(keys, key)
	case next == nil && i >= 0:
		keys = slices.Delete(keys, i, i+1)
	default:
		return nil, nil
	}
	if len(keys) == 0 {
		return &kv.WriteOp{NS: kv.NSDispatchEvidence, Key: taskPrefix + taskID, Delete: true}, nil
	}
	raw, err := json.Marshal(keys)
	if err != nil {
		return nil, err
	}
	return &kv.WriteOp{NS: kv.NSDispatchEvidence, Key: taskPrefix + taskID, Val: raw}, nil
}

// ownTickets are the hashes (hex) of the tickets of o that name o's task: a ticket of another
// version of the order is answered from that version's evidence.
func ownTickets(o *Order) map[string]bool {
	out := map[string]bool{}
	if o == nil {
		return out
	}
	for _, r := range o.Rounds {
		for _, a := range r.Attempts {
			var ticket taskv1.DispatchTicketV1
			if proto.Unmarshal(a.Ticket, &ticket) != nil || hex.EncodeToString(ticket.GetTaskId()) != o.TaskID {
				continue
			}
			out[hex.EncodeToString(a.Hash)] = true
		}
	}
	return out
}

func roots(o *Order) map[string]bool {
	out := map[string]bool{}
	if o == nil {
		return out
	}
	for _, r := range o.Rounds {
		out[hex.EncodeToString(r.RootDigest)] = true
	}
	return out
}

func unionKeys(a, b map[string]bool) map[string]bool {
	out := make(map[string]bool, len(a)+len(b))
	for k := range a {
		out[k] = true
	}
	for k := range b {
		out[k] = true
	}
	return out
}
