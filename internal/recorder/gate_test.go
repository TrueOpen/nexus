package recorder

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatcher"
	"github.com/TrueOpen/nexus/internal/handraise"
)

// Below builder_compensation_account_min_balance the gate refuses tickets and the recorder sends
// no record (the chain would refuse it whole); a funding event of this Builder reads the account
// again at the next block.
func TestCompensationGate(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	if err := e.gate.CheckBuilderKey(ctx); err != nil {
		t.Fatalf("funded gate = %v", err)
	}
	e.account.set("99", nil)
	if err := e.gate.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.gate.CheckBuilderKey(ctx); !errors.Is(err, dispatcher.ErrCompensationBelowMin) {
		t.Fatalf("gate below the minimum = %v", err)
	}
	e.record(bundle(0xaa, 0, 1, 50))
	e.block(10)
	if msgs, _ := e.tx.sent(); len(msgs) != 0 {
		t.Fatal("recorded below the minimum")
	}
	e.account.set("100", nil)
	e.r.HandleChainEvent(chaincli.ChainEvent{Typed: chaincli.BuilderCompensationFunded{Builder: "trueopen1other", Amount: "1", Balance: "100"}})
	e.block(11)
	if err := e.gate.CheckBuilderKey(ctx); !errors.Is(err, dispatcher.ErrCompensationBelowMin) {
		t.Fatalf("another Builder's funding opened the gate: %v", err)
	}
	e.r.HandleChainEvent(chaincli.ChainEvent{Typed: chaincli.BuilderCompensationFunded{Builder: builder, Amount: "1", Balance: "100"}})
	e.block(12)
	if err := e.gate.CheckBuilderKey(ctx); err != nil {
		t.Fatalf("funded gate = %v", err)
	}
	if msgs, _ := e.tx.sent(); len(msgs) != 1 {
		t.Fatal("not recorded once funded")
	}
	// The account is read again every compensationRefreshBlocks blocks without an event.
	e.account.set("5", nil)
	e.block(12 + compensationRefreshBlocks)
	if err := e.gate.CheckBuilderKey(ctx); !errors.Is(err, dispatcher.ErrCompensationBelowMin) {
		t.Fatalf("gate after the periodic read = %v", err)
	}
}

// The gate is the dispatcher's one Keys: this Builder's key check comes first, so a pending own
// rotation stays what it is.
func TestGateKeepsTheKeyCheck(t *testing.T) {
	ctx := context.Background()
	keys := &fakeKeys{err: fmt.Errorf("%w: nonce 4", handraise.ErrBuilderRotationPending)}
	account := &accountReader{balance: "0"}
	g := NewGate(GateConfig{Keys: keys, Builder: builder, Account: account.read, MinBalance: big.NewInt(1)})
	if err := g.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if err := g.CheckBuilderKey(ctx); !errors.Is(err, handraise.ErrBuilderRotationPending) {
		t.Fatalf("gate = %v", err)
	}
	keys.err = nil
	if err := g.CheckBuilderKey(ctx); !errors.Is(err, dispatcher.ErrCompensationBelowMin) {
		t.Fatalf("gate = %v", err)
	}
}

// No account is a zero balance; an account never read is unconfirmed, not below the minimum; a
// failed read keeps the last balance read. A zero minimum needs no account.
func TestGateAccountReads(t *testing.T) {
	ctx := context.Background()
	account := &accountReader{err: errUnreadable}
	g := NewGate(GateConfig{Keys: &fakeKeys{}, Builder: builder, Account: account.read, MinBalance: big.NewInt(10)})
	if err := g.Refresh(ctx); err == nil {
		t.Fatal("refresh of an unreadable account succeeded")
	}
	if err := g.CheckBuilderKey(ctx); err == nil || errors.Is(err, dispatcher.ErrCompensationBelowMin) {
		t.Fatalf("unread gate = %v", err)
	}
	account.set("50", nil)
	if err := g.Refresh(ctx); err != nil || g.CheckBuilderKey(ctx) != nil {
		t.Fatalf("read gate = %v", g.CheckBuilderKey(ctx))
	}
	account.set("1", errUnreadable)
	_ = g.Refresh(ctx)
	if err := g.CheckBuilderKey(ctx); err != nil {
		t.Fatalf("a failed read changed the gate: %v", err)
	}
	account.set("", nil)
	if err := g.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if err := g.CheckBuilderKey(ctx); !errors.Is(err, dispatcher.ErrCompensationBelowMin) {
		t.Fatalf("no account = %v", err)
	}
	g.SetMinBalance(new(big.Int))
	if err := g.CheckBuilderKey(ctx); err != nil {
		t.Fatalf("zero minimum = %v", err)
	}
}
