package app

import (
	"bytes"
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/attempt"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/coordinator"
	"github.com/TrueOpen/nexus/internal/handraise"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/types"
)

// orderChain is the task chain of the order path: dispatch params, transaction results and the
// claims the responder reads; the rest is the wiring chain.
type orderChain struct {
	*wiringChain
	claimReads atomic.Int32
}

func (c *orderChain) QueryDispatchParams(context.Context) (*taskv1.DispatchParamsV1, error) {
	return &taskv1.DispatchParamsV1{
		RecordDeadlineBlocks: 20, MaxDispatchEntriesPerRecord: 16, MaxDispatchRecordBytes: 1 << 20, MaxSkips: 2,
		MaxDispatchRosterBytes: 1 << 20, BuilderMaxInflightPerSession: 8, MaxPendingPerSession: 8,
		DispatchCompensationClaimWindowBlocks: 30, DispatchCompensationRebuttalBlocks: 10,
	}, nil
}

func (c *orderChain) QueryCandidateWeightParams(context.Context) (*taskv1.CandidateWeightParamsV1, error) {
	return &taskv1.CandidateWeightParamsV1{MaxWeightedDrawAttemptsPerSelection: 64}, nil
}

func (c *orderChain) QueryTx(context.Context, []byte) (chaincli.TxResult, error) {
	return chaincli.TxResult{}, chaincli.ErrNotFound
}

func (c *orderChain) QueryDispatchCompensationClaim(context.Context, []byte) (*taskv1.DispatchCompensationClaimState, error) {
	c.claimReads.Add(1)
	return nil, chaincli.ErrNotFound
}

type nopOrderObserver struct{}

func (nopOrderObserver) DispatchAccepted(string, string, [32]byte, string)                    {}
func (nopOrderObserver) DispatchFailed(string, string, error)                                 {}
func (nopOrderObserver) DispatchRecorded(string, string, uint64)                              {}
func (nopOrderObserver) RecordRejected(string, string, [32]byte, taskv1.DispatchRejectCodeV1) {}

type nopHeld struct{}

func (nopHeld) OnTakeover(context.Context, types.Order) error                              { return nil }
func (nopHeld) TakeoverRegistered(string, string, uint64)                                  {}
func (nopHeld) TakeoverActivated(string, string, uint64)                                   {}
func (nopHeld) TakeoverEnded(string, string, string, uint64, bool, *types.TaskEventDetail) {}
func (nopHeld) OnOrder(context.Context, types.Order) error                                 { return nil }

// A Builder role event the task chain delivers reaches the responder: a compensation claim on one
// of this Builder's tickets is followed (read on chain at the next block).
func TestRoleEventsReachTheResponder(t *testing.T) {
	f := newWiringFixture(t)
	chain := &orderChain{wiringChain: f.chain}
	log := slog.New(slog.DiscardHandler)
	attempts, err := attempt.New(f.store, servicekey.Static(f.builder, 1), log)
	if err != nil {
		t.Fatal(err)
	}
	od, err := newOrderDispatch(context.Background(), orderDispatchDeps{
		ChainID: wiringChainID, BuilderAddress: f.builder.Address(), Config: config.Load().Dispatch, InputChunkBytes: 1024,
		Signer: f.ring, Store: f.store, TaskChain: chain, HubChain: chain, Direct: f.d,
		Records: coordinator.NewRecordSubmitter(log, chain, f.builder, config.ChainConfig{ChainID: wiringChainID}, nil),
		Keys:    handraise.ChainServiceKeys{Resolver: chain, AddressPrefix: wiringPrefix, Ring: f.ring}, Observer: nopOrderObserver{}, Tasks: nopOrderObserver{}, Held: nopHeld{}, Attempts: attempts, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	events := &orderEvents{}
	events.order.Store(od)
	ticket := bytes.Repeat([]byte{0x31}, 32)
	events.observe(chaincli.ChainEvent{Type: chaincli.EventBuilderRole, Height: 140, Typed: chaincli.DispatchCompensationClaimed{
		TicketHash: ticket, Builder: f.builder.Address(), Worker: f.cortex.Address(), RebuttalDeadlineHeight: 150,
	}})
	events.observe(chaincli.ChainEvent{Type: chaincli.EventBuilderRole, Height: 140, Typed: chaincli.DispatchChallengeOpened{
		ChallengeID: bytes.Repeat([]byte{0x32}, 32), Kind: sharedv1.DispatchChallengeKindV1_DISPATCH_CHALLENGE_KIND_V1_OMISSION,
	}})
	if c := od.Responder.Counts(); c.ClaimsSeen != 1 || c.UnanswerableChallenges != 1 {
		t.Fatalf("responder counts = %+v", c)
	}
	// The next block reaches the running responder, which reads the claim on chain.
	if err := od.Responder.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = od.Responder.Stop(context.Background()) }()
	events.observe(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 141})
	deadline := time.Now().Add(5 * time.Second)
	for chain.claimReads.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the claim was not read after a block")
		}
		time.Sleep(time.Millisecond)
	}
}
