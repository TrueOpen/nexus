package supportrelay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/kv"
)

// threeOperators have address bytes 0x01.., 0x08.. and 0x40..: Bech32 text sorts them the other
// way round (q, p, g), so a batch sorted by text would be refused.
func threeOperators(t *testing.T, chain *fakeChain) []operator {
	t.Helper()
	var ops []operator
	for i, b := range []byte{0x40, 0x01, 0x08} {
		ops = append(ops, newOperator(t, chain, bytes.Repeat([]byte{b}, 20), fmt.Sprintf("%064x", 0x21+i), 3))
	}
	if !(ops[1].address > ops[2].address && ops[2].address > ops[0].address) {
		t.Fatalf("fixture addresses do not sort against their bytes: %s %s %s", ops[1].address, ops[2].address, ops[0].address)
	}
	return ops
}

func submitAll(t *testing.T, r *Relay, ops []operator, expiry uint64) {
	t.Helper()
	for _, op := range ops {
		if _, err := r.Submit(context.Background(), testEpoch, op.confirm(t, testEpoch, expiry)); err != nil {
			t.Fatal(err)
		}
	}
}

func batchOperators(msg *hubv1.MsgBatchConfirmModelSupport) []string {
	var out []string
	for _, c := range msg.GetConfirmations() {
		out = append(out, c.GetOperatorAddress())
	}
	return out
}

// One flush sends the held confirmations of the current epoch in one batch ordered by operator
// bytes, signed material untouched and this Builder as submitter; each leaves the queue only once
// the chain holds its row.
func TestFlushSendsOneBatchOrderedByOperatorBytes(t *testing.T) {
	chain := newFakeChain()
	ops := threeOperators(t, chain)
	sub := &fakeSubmitter{chain: chain}
	r := newTestRelay(t, chain, sub, nil)
	submitAll(t, r, ops, 1750)
	r.flush(context.Background())

	sent := sub.sent()
	if len(sent) != 1 {
		t.Fatalf("sent %d batches", len(sent))
	}
	got := batchOperators(sent[0])
	want := []string{ops[1].address, ops[2].address, ops[0].address}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("batch order = %v, want %v", got, want)
	}
	if sent[0].GetEpochIndex() != testEpoch || sent[0].GetSubmitterAddress() != testSubmitter || sub.gas[0] != 100+3*10+6*1 {
		t.Fatalf("batch epoch %d submitter %s gas %d", sent[0].GetEpochIndex(), sent[0].GetSubmitterAddress(), sub.gas[0])
	}
	if r.Held() != 0 {
		t.Fatalf("held %d after the chain accepted every row", r.Held())
	}
	r.flush(context.Background())
	if len(sub.sent()) != 1 {
		t.Fatal("an empty queue sent a batch")
	}
}

// Batches are cut at the Hub's confirmation, model item and byte limits.
func TestFlushCutsBatchesAtTheHubLimits(t *testing.T) {
	for name, limit := range map[string]func(*chaincli.SupportParams){
		"confirmations": func(p *chaincli.SupportParams) { p.MaxConfirmationsPerBatch = 2 },
		"items":         func(p *chaincli.SupportParams) { p.MaxItemsPerBatch = 5 },
		"bytes":         func(p *chaincli.SupportParams) { p.MaxBatchBytes = 410 },
	} {
		chain := newFakeChain()
		ops := threeOperators(t, chain)
		sub := &fakeSubmitter{chain: chain}
		r := newTestRelay(t, chain, sub, nil)
		submitAll(t, r, ops, 1750)
		chain.set(func(c *fakeChain) { limit(&c.params) })
		r.flush(context.Background())
		sent := sub.sent()
		if len(sent) != 2 || len(sent[0].GetConfirmations()) != 2 || len(sent[1].GetConfirmations()) != 1 {
			t.Fatalf("%s: batches %v", name, sent)
		}
		if batchOperators(sent[1])[0] != ops[0].address || r.Held() != 0 {
			t.Fatalf("%s: second batch %v, held %d", name, batchOperators(sent[1]), r.Held())
		}
	}
}

// A refused batch is split until the failing confirmation stands alone; the others are accepted
// and the one the chain refused on its own is retired.
func TestFlushIsolatesTheConfirmationTheChainRefuses(t *testing.T) {
	chain := newFakeChain()
	ops := threeOperators(t, chain)
	sub := &fakeSubmitter{chain: chain, poison: map[string]bool{ops[2].address: true}}
	r := newTestRelay(t, chain, sub, nil)
	submitAll(t, r, ops, 1750)
	r.flush(context.Background())

	for _, op := range []operator{ops[0], ops[1]} {
		if _, err := chain.QueryDailySupport(context.Background(), op.address, testEpoch); err != nil {
			t.Fatalf("%s not accepted: %v", op.address, err)
		}
	}
	if _, err := chain.QueryDailySupport(context.Background(), ops[2].address, testEpoch); !errors.Is(err, chaincli.ErrNotFound) {
		t.Fatalf("refused confirmation has a row: %v", err)
	}
	if r.Held() != 0 {
		t.Fatalf("held %d", r.Held())
	}
	singles := 0
	for _, msg := range sub.sent() {
		if len(msg.GetConfirmations()) == 1 && msg.GetConfirmations()[0].GetOperatorAddress() == ops[2].address {
			singles++
		}
	}
	if singles != 1 {
		t.Fatalf("the refused confirmation went alone %d times, want once", singles)
	}
}

// A refusal that is not the Hub's (fees, account) keeps every confirmation for the next round.
func TestFlushKeepsConfirmationsOnATransactionRefusal(t *testing.T) {
	chain := newFakeChain()
	ops := threeOperators(t, chain)
	sub := &fakeSubmitter{chain: chain}
	sub.next = func(*hubv1.MsgBatchConfirmModelSupport) (chaincli.TxResult, error) {
		return chaincli.TxResult{Code: 13, Codespace: "sdk", RawLog: "insufficient fee"}, errors.New("rejected by CheckTx")
	}
	r := newTestRelay(t, chain, sub, nil)
	submitAll(t, r, ops, 1750)
	r.flush(context.Background())
	if len(sub.sent()) != 1 || r.Held() != 3 {
		t.Fatalf("sent %d, held %d", len(sub.sent()), r.Held())
	}
	sub.next = nil
	r.flush(context.Background())
	if r.Held() != 0 {
		t.Fatalf("held %d after the retry", r.Held())
	}
}

// Out of gas splits a batch; a single confirmation goes again with more gas.
func TestFlushRetriesOutOfGasWithSmallerBatchesAndMoreGas(t *testing.T) {
	chain := newFakeChain()
	ops := threeOperators(t, chain)[:2]
	sub := &fakeSubmitter{chain: chain}
	calls := 0
	sub.next = func(*hubv1.MsgBatchConfirmModelSupport) (chaincli.TxResult, error) {
		calls++
		if calls <= 2 {
			return chaincli.TxResult{Code: 11, Codespace: "sdk"}, errors.New("out of gas")
		}
		return chaincli.TxResult{}, nil
	}
	r := newTestRelay(t, chain, sub, nil)
	submitAll(t, r, ops, 1750)
	r.flush(context.Background())
	// 2 together, then the first alone, then the first alone with twice the gas (accepted), then
	// the second alone (accepted).
	if fmt.Sprint(sub.gas) != fmt.Sprint([]uint64{100 + 20 + 4, 100 + 10 + 2, 2 * (100 + 10 + 2), 100 + 10 + 2}) {
		t.Fatalf("gas limits %v", sub.gas)
	}
	if r.Held() != 0 {
		t.Fatalf("held %d", r.Held())
	}
}

// A batch executed without the chain writing the row does not settle anything: the confirmation
// is held and sent again until its row exists.
func TestFlushSettlesOnlyOnTheChainRow(t *testing.T) {
	chain := newFakeChain()
	op := vectorOperator(t, chain)
	sub := &fakeSubmitter{chain: chain, noRows: true}
	r := newTestRelay(t, chain, sub, nil)
	if _, err := r.Submit(context.Background(), testEpoch, op.confirm(t, testEpoch, 1750)); err != nil {
		t.Fatal(err)
	}
	r.flush(context.Background())
	if r.Held() != 1 {
		t.Fatalf("held %d after a broadcast without a row", r.Held())
	}
	sub.noRows = false
	r.flush(context.Background())
	if r.Held() != 0 || len(sub.sent()) != 2 {
		t.Fatalf("held %d after %d batches", r.Held(), len(sub.sent()))
	}
}

// Confirmations survive a restart in the pebble store and are sent by the next run.
func TestRestartResumesStoredConfirmations(t *testing.T) {
	store, err := kv.NewPebble(t.TempDir(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	chain := newFakeChain()
	ops := threeOperators(t, chain)
	first := newTestRelay(t, chain, &fakeSubmitter{chain: chain}, store)
	submitAll(t, first, ops, 1750)

	sub := &fakeSubmitter{chain: chain}
	second := newTestRelay(t, chain, sub, store)
	if second.Held() != 3 {
		t.Fatalf("resumed %d", second.Held())
	}
	again, err := second.Submit(context.Background(), testEpoch, ops[0].confirm(t, testEpoch, 1750))
	if err != nil || !again.Idempotent {
		t.Fatalf("retry after restart = %+v, %v", again, err)
	}
	if _, err := second.Submit(context.Background(), testEpoch, ops[0].confirm(t, testEpoch, 1760)); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflict after restart: %v", err)
	}
	second.flush(context.Background())
	if len(sub.sent()) != 1 || second.Held() != 0 {
		t.Fatalf("sent %d, held %d", len(sub.sent()), second.Held())
	}
	third := newTestRelay(t, chain, &fakeSubmitter{chain: chain}, store)
	if third.Held() != 0 {
		t.Fatalf("settled confirmations came back: %d", third.Held())
	}
}

// At an epoch rollover a held confirmation of the ended epoch is never sent: it is settled if the
// chain holds its row and retired otherwise.
func TestFlushRetiresConfirmationsOfAnEndedEpoch(t *testing.T) {
	chain := newFakeChain()
	ops := threeOperators(t, chain)[:2]
	sub := &fakeSubmitter{chain: chain}
	r := newTestRelay(t, chain, sub, nil)
	submitAll(t, r, ops, 1750)
	accepted := ops[0].confirm(t, testEpoch, 1750)
	conf, err := Decode(accepted, "trueopen")
	if err != nil {
		t.Fatal(err)
	}
	chain.set(func(c *fakeChain) {
		c.accept(conf.Proto(), testEpoch)
		c.height = 1725
	})
	r.flush(context.Background())
	if len(sub.sent()) != 0 || r.Held() != 0 {
		t.Fatalf("sent %d, held %d", len(sub.sent()), r.Held())
	}
	// The slot of the new epoch is free for fresh material.
	if _, err := r.Submit(context.Background(), testEpoch+1, ops[1].confirm(t, testEpoch+1, 1750)); err != nil {
		t.Fatal(err)
	}
}

// While a sent batch's result is unknown, a confirmation the chain could still accept is not
// retired; once the chain refuses it from now on (its expiry passed) it is.
func TestFlushDoesNotRetireAConfirmationThatMayStillLand(t *testing.T) {
	chain := newFakeChain()
	op := vectorOperator(t, chain)
	sub := &fakeSubmitter{chain: chain, pending: true, noRows: true}
	r := newTestRelay(t, chain, sub, nil)
	if _, err := r.Submit(context.Background(), testEpoch, op.confirm(t, testEpoch, 1710)); err != nil {
		t.Fatal(err)
	}
	r.flush(context.Background())
	if r.Held() != 1 || len(sub.sent()) != 1 {
		t.Fatalf("held %d, sent %d", r.Held(), len(sub.sent()))
	}
	// Tombstoned: the chain does not check the bond, so the batch in flight could still land.
	chain.set(func(c *fakeChain) {
		c.bonds[op.address].Status = hubv1.ServiceBondStatus_SERVICE_BOND_STATUS_TOMBSTONED
	})
	r.flush(context.Background())
	if r.Held() != 1 || len(sub.sent()) != 1 {
		t.Fatalf("in flight: held %d, sent %d", r.Held(), len(sub.sent()))
	}
	chain.set(func(c *fakeChain) { c.height = 1711 })
	r.flush(context.Background())
	if r.Held() != 0 {
		t.Fatalf("an expired confirmation is still held")
	}
}

// Without anything in flight an invalidated confirmation is retired after the read found no row,
// and the slot takes newly valid material.
func TestFlushRetiresAnInvalidatedConfirmation(t *testing.T) {
	chain := newFakeChain()
	op := vectorOperator(t, chain)
	sub := &fakeSubmitter{chain: chain}
	r := newTestRelay(t, chain, sub, nil)
	if _, err := r.Submit(context.Background(), testEpoch, op.confirm(t, testEpoch, 1750)); err != nil {
		t.Fatal(err)
	}
	op.nonce = 8
	op.register(chain)
	r.flush(context.Background())
	if r.Held() != 0 || len(sub.sent()) != 0 {
		t.Fatalf("held %d, sent %d", r.Held(), len(sub.sent()))
	}
	if ack, err := r.Submit(context.Background(), testEpoch, op.confirm(t, testEpoch, 1750)); err != nil || ack.Idempotent {
		t.Fatalf("fresh material = %+v, %v", ack, err)
	}
}

// An unreadable chain leaves everything held and unsent.
func TestFlushWaitsWhileTheChainIsUnavailable(t *testing.T) {
	chain := newFakeChain()
	ops := threeOperators(t, chain)
	sub := &fakeSubmitter{chain: chain}
	r := newTestRelay(t, chain, sub, nil)
	submitAll(t, r, ops, 1750)
	for name, fail := range map[string]func(*fakeChain){
		"height": func(c *fakeChain) { c.heightErr = errors.New("down") },
		"daily":  func(c *fakeChain) { c.dailyErr = errors.New("down") },
		"key":    func(c *fakeChain) { c.keyErr = errors.New("down") },
	} {
		chain.set(fail)
		r.flush(context.Background())
		if len(sub.sent()) != 0 || r.Held() != 3 {
			t.Fatalf("%s: sent %d, held %d", name, len(sub.sent()), r.Held())
		}
		chain.set(func(c *fakeChain) { c.heightErr, c.dailyErr, c.keyErr = nil, nil, nil })
	}
}

// The loop flushes on its timer, and at once when FlushItems confirmations are held.
func TestRunFlushesOnTheTimerAndOnSize(t *testing.T) {
	chain := newFakeChain()
	ops := threeOperators(t, chain)
	sub := &fakeSubmitter{chain: chain}
	cfg := testConfig()
	cfg.FlushItems = 2
	r, err := New(cfg, nil, chain, sub, kv.NewMemStore())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer r.Stop(context.Background())
	submitAll(t, r, ops[:2], 1750)
	waitFor(t, func() bool { return r.Held() == 0 })

	timed := newFakeChain()
	op := vectorOperator(t, timed)
	cfg = testConfig()
	cfg.FlushInterval = 10 * time.Millisecond
	r2, err := New(cfg, nil, timed, &fakeSubmitter{chain: timed}, kv.NewMemStore())
	if err != nil {
		t.Fatal(err)
	}
	if err := r2.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer r2.Stop(context.Background())
	if _, err := r2.Submit(context.Background(), testEpoch, op.confirm(t, testEpoch, 1750)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return r2.Held() == 0 })
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(time.Millisecond)
	}
}
