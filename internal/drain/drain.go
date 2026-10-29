// Package drain is the drain a dispatching Builder runs before it rotates its service key.
//
// The chain admits a dispatch record only under the Builder's current service key, and its
// rotation guard does not count orders accepted but not recorded yet: a key switched while orders
// are in flight makes their records fail, and the failures are charged to this Builder. Group
// members also verify what this Builder syncs to them under its current key, so sync items signed
// before a rotation are refused after it. The drain therefore stops new work first: while it lasts
// no new order is taken, no ticket issued and no takeover admitted (the dispatcher and the
// takeover manager ask Draining). The orders in flight are accepted, recorded or fail as usual and
// the group sync finishes. A held takeover whose entry has not gone out yet cannot be on chain: it
// is ended as NO_CAPACITY when the drain begins (OnDraining), so its user goes elsewhere at once.
// A takeover that went out is work from before the drain: it takes effect and its order is walked
// with tickets as usual. Once nothing remains (no in-flight order, no record outbox entry, no
// takeover, no sync item a member has not acknowledged) the operator submits the rotation; the drain ends by itself once the chain shows the new key current and
// this process signs with it (after a restart with the new key), or when the operator ends it.
//
// The drain state is stored, so it survives a restart.
package drain

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/kv"
)

// stateKey is the key of the drain state in kv.NSOps.
const stateKey = "drain"

// Phase is where the Builder stands in a rotation.
type Phase string

const (
	// PhaseServing: no drain; new work is taken.
	PhaseServing Phase = "SERVING"
	// PhaseDraining: no new work is taken and some remains.
	PhaseDraining Phase = "DRAINING"
	// PhaseDrained: nothing remains; the rotation may be submitted now.
	PhaseDrained Phase = "DRAINED"
	// PhaseRotationPending: the chain registered the replacement key; it waits for its
	// activation height.
	PhaseRotationPending Phase = "ROTATION_PENDING"
	// PhaseRestartRequired: the replacement key is current but this process signs with the old
	// one; restart it with the new service key.
	PhaseRestartRequired Phase = "RESTART_REQUIRED"
)

// SyncPending is what one group member has not acknowledged of one order's sync stream: Items
// sync items, and Output when the recorded winner's output is not sealed at the member yet.
type SyncPending struct {
	SessionID string `json:"session_id"`
	Sequence  uint64 `json:"sequence"`
	TaskID    string `json:"task_id"`
	Peer      string `json:"peer"`
	Items     uint64 `json:"items"`
	Output    bool   `json:"output"`
}

// Remaining is the work a drain waits for.
type Remaining struct {
	// InFlightOrders are the orders still dispatching or accepted and not recorded, with the sum
	// of their max_fee in atomic units.
	InFlightOrders int    `json:"in_flight_orders"`
	InFlightMaxFee string `json:"in_flight_max_fee"`
	// RecordEntries are the record outbox entries the chain has not resolved yet.
	RecordEntries int `json:"record_entries"`
	// Takeovers are the takeovers held as candidate.
	Takeovers int `json:"takeovers"`
	// SyncPending lists the sync items group members have not acknowledged: they would be refused
	// once the key rotated.
	SyncPending []SyncPending `json:"sync_pending,omitempty"`
}

// Empty reports whether nothing remains.
func (r Remaining) Empty() bool {
	return r.InFlightOrders == 0 && r.RecordEntries == 0 && r.Takeovers == 0 && len(r.SyncPending) == 0
}

// Sources read the work that remains.
type Sources struct {
	InFlight  func() (orders int, maxFee *big.Int)
	Records   func() int
	Takeovers func() int
	Sync      func() []SyncPending
}

// Key is this Builder's BUILDER service binding as the chain shows it.
type Key struct {
	PubKey string `json:"service_pubkey"`
	Nonce  uint64 `json:"service_authorization_nonce"`
	// PendingNonce and PendingEffectiveHeight describe a registered replacement, 0 without one.
	PendingNonce           uint64 `json:"pending_authorization_nonce,omitempty"`
	PendingEffectiveHeight uint64 `json:"pending_effective_height,omitempty"`
}

// Status is the drain as Check found it.
type Status struct {
	Phase     Phase     `json:"phase"`
	Since     time.Time `json:"since,omitzero"`
	Complete  bool      `json:"complete"`
	Remaining Remaining `json:"remaining"`
	// Key is the binding read from the chain; nil when it could not be read.
	Key     *Key   `json:"key,omitempty"`
	Warning string `json:"warning,omitempty"`
}

// Config wires a Controller.
type Config struct {
	Store   kv.Store
	Sources Sources
	// Key reads this Builder's current BUILDER service binding from the chain.
	Key func(ctx context.Context) (chaincli.ServiceKeyState, error)
	// LocalPubKey is the compressed public key, lowercase hex, of the service key this process
	// signs with.
	LocalPubKey string
	// OnDraining, when set, runs when the drain begins and on every Check while it lasts: it ends
	// the held takeovers whose entry has not gone out.
	OnDraining func()
	// Now is nil for the system clock.
	Now func() time.Time
	Log *slog.Logger
}

// state is the stored drain.
type state struct {
	Draining    bool  `json:"draining"`
	SinceUnixMs int64 `json:"since_unix_ms,omitempty"`
	// KeyNonce and KeyPubKey are the binding current when the drain began; a current binding with
	// another nonce is the rotation. A zero nonce is taken at the first read showing this
	// process's key current.
	KeyNonce  uint64 `json:"key_nonce,omitempty"`
	KeyPubKey string `json:"key_pubkey,omitempty"`
}

// Controller holds the drain state.
type Controller struct {
	cfg      Config
	log      *slog.Logger
	draining atomic.Bool

	mu sync.Mutex
	st state
}

// New loads the stored drain state.
func New(cfg Config) (*Controller, error) {
	if cfg.Store == nil || cfg.Key == nil || cfg.Sources.InFlight == nil || cfg.Sources.Records == nil ||
		cfg.Sources.Takeovers == nil || cfg.Sources.Sync == nil {
		return nil, fmt.Errorf("drain needs a store, the key reader and every work source")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	c := &Controller{cfg: cfg, log: cfg.Log}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	raw, found, err := cfg.Store.GetWithError(kv.NSOps, stateKey)
	if err != nil {
		return nil, fmt.Errorf("read drain state: %w", err)
	}
	if found {
		if err := json.Unmarshal(raw, &c.st); err != nil {
			return nil, fmt.Errorf("drain state is malformed: %w", err)
		}
	}
	c.draining.Store(c.st.Draining)
	return c, nil
}

// Draining reports whether new work must be refused.
func (c *Controller) Draining() bool { return c.draining.Load() }

// Begin starts a drain, noting the current key binding; a drain under way is kept as it is.
func (c *Controller) Begin(ctx context.Context) error {
	c.mu.Lock()
	draining := c.st.Draining
	c.mu.Unlock()
	if draining {
		return nil
	}
	next := state{Draining: true, SinceUnixMs: c.cfg.Now().UnixMilli()}
	if key, err := c.cfg.Key(ctx); err == nil && key.PendingRotation == nil {
		next.KeyNonce, next.KeyPubKey = key.AuthorizationNonce, key.ServicePubKey
	}
	c.mu.Lock()
	if c.st.Draining {
		c.mu.Unlock()
		return nil
	}
	if err := c.storeLocked(next); err != nil {
		c.mu.Unlock()
		return err
	}
	c.mu.Unlock()
	c.log.Info("drain begun: no new order, ticket or takeover until it ends", "key_nonce", next.KeyNonce)
	c.onDraining()
	return nil
}

func (c *Controller) onDraining() {
	if c.cfg.OnDraining != nil {
		c.cfg.OnDraining()
	}
}

// End ends the drain; without one it does nothing.
func (c *Controller) End() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.st.Draining {
		return nil
	}
	if err := c.storeLocked(state{}); err != nil {
		return err
	}
	c.log.Info("drain ended: new work is taken again")
	return nil
}

func (c *Controller) storeLocked(next state) error {
	raw, err := json.Marshal(next)
	if err == nil {
		err = c.cfg.Store.Set(kv.NSOps, stateKey, raw)
	}
	if err != nil {
		return fmt.Errorf("store drain state: %w", err)
	}
	c.st = next
	c.draining.Store(next.Draining)
	return nil
}

// Check reads the remaining work and the key binding and returns the status. A drain whose key
// rotated to the key this process signs with ends here.
func (c *Controller) Check(ctx context.Context) Status {
	if c.Draining() {
		c.onDraining()
	}
	s := Status{Phase: PhaseServing, Remaining: c.remaining()}
	s.Complete = s.Remaining.Empty()
	chainKey, keyErr := c.cfg.Key(ctx)
	if keyErr == nil {
		k := &Key{PubKey: chainKey.ServicePubKey, Nonce: chainKey.AuthorizationNonce}
		if p := chainKey.PendingRotation; p != nil {
			k.PendingNonce, k.PendingEffectiveHeight = p.NextAuthorizationNonce, p.EffectiveHeight
		}
		s.Key = k
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.st.Draining {
		return s
	}
	s.Since = time.UnixMilli(c.st.SinceUnixMs)
	if keyErr != nil {
		return c.workPhase(s)
	}
	local := chainKey.ServicePubKey == c.cfg.LocalPubKey
	switch {
	case chainKey.PendingRotation != nil:
		s.Phase = PhaseRotationPending
		if !s.Complete {
			s.Warning = "the key rotation was registered before the drain completed: the remaining items will fail under the new key"
		}
		return s
	case c.st.KeyNonce == 0:
		if local {
			if err := c.storeLocked(state{Draining: true, SinceUnixMs: c.st.SinceUnixMs, KeyNonce: chainKey.AuthorizationNonce, KeyPubKey: chainKey.ServicePubKey}); err != nil {
				c.log.Warn("key binding of the drain not stored", "err", err)
			}
		}
		return c.workPhase(s)
	case chainKey.AuthorizationNonce == c.st.KeyNonce:
		return c.workPhase(s)
	case !local:
		s.Phase = PhaseRestartRequired
		return s
	}
	if err := c.storeLocked(state{}); err != nil {
		c.log.Warn("drain end not stored", "err", err)
		return c.workPhase(s)
	}
	c.log.Info("drain ended: the new service key is current", "key_nonce", chainKey.AuthorizationNonce)
	s.Since = time.Time{}
	return s
}

func (c *Controller) workPhase(s Status) Status {
	s.Phase = PhaseDraining
	if s.Complete {
		s.Phase = PhaseDrained
	}
	return s
}

func (c *Controller) remaining() Remaining {
	orders, maxFee := c.cfg.Sources.InFlight()
	if maxFee == nil {
		maxFee = new(big.Int)
	}
	return Remaining{
		InFlightOrders: orders, InFlightMaxFee: maxFee.String(), RecordEntries: c.cfg.Sources.Records(),
		Takeovers: c.cfg.Sources.Takeovers(), SyncPending: c.cfg.Sources.Sync(),
	}
}
