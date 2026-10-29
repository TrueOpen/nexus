package recorder

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sync"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatcher"
)

// compensationRefreshBlocks is how often the compensation account is read again without an event
// that moves it.
const compensationRefreshBlocks = 20

// GateConfig wires a Gate.
type GateConfig struct {
	// Keys is the service key check the gate extends.
	Keys dispatcher.Keys
	// Builder is this Builder's operator address.
	Builder string
	// Account reads this Builder's compensation account (QueryBuilderCompensationAccount).
	Account func(ctx context.Context) (*hubv1.BuilderCompensationAccountState, error)
	// MinBalance is builder_compensation_account_min_balance.
	MinBalance *big.Int
	Log        *slog.Logger
}

// Gate is the dispatcher's Keys: the service key check, then this Builder's compensation
// account. Below builder_compensation_account_min_balance the chain refuses every record of the
// Builder whole, so the dispatcher takes no new order and issues no ticket, and the Recorder sends
// no record, until the account is funded.
type Gate struct {
	cfg GateConfig
	log *slog.Logger

	mu      sync.Mutex
	min     *big.Int
	balance *big.Int // nil until the account was read once
	readAt  uint64   // block height of the last read
	head    uint64
	stale   bool
}

// NewGate builds a Gate; Refresh reads the account for the first time.
func NewGate(cfg GateConfig) *Gate {
	g := &Gate{cfg: cfg, log: cfg.Log, min: new(big.Int)}
	if g.log == nil {
		g.log = slog.New(slog.DiscardHandler)
	}
	if cfg.MinBalance != nil {
		g.min = new(big.Int).Set(cfg.MinBalance)
	}
	return g
}

// SetMinBalance replaces builder_compensation_account_min_balance after a params change.
func (g *Gate) SetMinBalance(min *big.Int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.min = new(big.Int).Set(min)
}

// CheckBuilderKey implements dispatcher.Keys: the key check first, then
// dispatcher.ErrCompensationBelowMin below the minimum. An account never read is unconfirmed.
func (g *Gate) CheckBuilderKey(ctx context.Context) error {
	if err := g.cfg.Keys.CheckBuilderKey(ctx); err != nil {
		return err
	}
	return g.compensationErr()
}

// CortexRotationPending implements dispatcher.Keys.
func (g *Gate) CortexRotationPending(ctx context.Context, operator string) (bool, error) {
	return g.cfg.Keys.CortexRotationPending(ctx, operator)
}

func (g *Gate) compensationErr() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch {
	case g.min.Sign() == 0:
		return nil
	case g.balance == nil:
		return errors.New("builder compensation account not read yet")
	case g.balance.Cmp(g.min) < 0:
		return fmt.Errorf("%w: balance %s, minimum %s", dispatcher.ErrCompensationBelowMin, g.balance, g.min)
	}
	return nil
}

// Refresh reads the compensation account. No account is a zero balance; a failed read keeps the
// last balance read.
func (g *Gate) Refresh(ctx context.Context) error {
	account, err := g.cfg.Account(ctx)
	balance := new(big.Int)
	switch {
	case errors.Is(err, chaincli.ErrNotFound):
	case err != nil:
		return fmt.Errorf("read builder compensation account: %w", err)
	default:
		if _, ok := balance.SetString(account.GetBalance().GetAtomicUnits(), 10); !ok || balance.Sign() < 0 {
			return fmt.Errorf("builder compensation account balance %q is not an amount", account.GetBalance().GetAtomicUnits())
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.balance == nil || g.balance.Cmp(balance) != 0 {
		g.log.Info("builder compensation account read", "balance", balance, "minimum", g.min)
	}
	g.balance, g.readAt, g.stale = balance, g.head, false
	return nil
}

// HandleChainEvent marks the account for a read at the next block when an event moved it: a
// funding, a paid compensation or a recorded dispatch fault of this Builder.
func (g *Gate) HandleChainEvent(ev chaincli.ChainEvent) {
	var builder string
	switch t := ev.Typed.(type) {
	case chaincli.BuilderCompensationFunded:
		builder = t.Builder
	case chaincli.DispatchCompensationPaid:
		builder = t.Builder
	case chaincli.BuilderDispatchFaultRecorded:
		builder = t.Builder
	default:
		return
	}
	if builder == g.cfg.Builder {
		g.markStale()
	}
}

func (g *Gate) markStale() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.stale = true
}

// onBlock reads the account when an event or a failed record asked for it, and every
// compensationRefreshBlocks blocks.
func (g *Gate) onBlock(ctx context.Context, height uint64) {
	g.mu.Lock()
	g.head = height
	due := g.stale || g.balance == nil || height >= g.readAt+compensationRefreshBlocks
	g.mu.Unlock()
	if !due {
		return
	}
	if err := g.Refresh(ctx); err != nil {
		g.log.Warn("builder compensation account not read", "err", err)
	}
}

// open reports whether records may be sent.
func (g *Gate) open() bool { return g.compensationErr() == nil }
