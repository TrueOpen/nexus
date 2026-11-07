package recorder

import (
	"reflect"
	"testing"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

// answerByGas executes the record transaction last sent at height+1: out of gas below need (a
// multiple of the formula's gas in tenths), with every entry applied otherwise. It reports whether
// it ran out of gas.
func (e *env) answerByGas(height uint64, needTenths uint64) bool {
	e.t.Helper()
	msg, raw := e.lastSent()
	if gas := e.tx.gas[len(e.tx.gas)-1]; gas*10 < recordGas(msg)*needTenths {
		e.fail(raw, int64(height+1), "sdk", 11)
		return true
	}
	results := make([]result, len(msg.GetEntries()))
	for i := range results {
		results[i] = ok()
	}
	e.chain.execute(raw, executed(e.t, msg, int64(height+1), results...))
	return false
}

// A record that needs 1.3 times the formula's gas does not run out of gas every other
// transaction: a success at the raised factor does not halve it at once, only
// gasStepDownSuccesses of them in a row do.
func TestGasFactorDoesNotOscillateWhenTheNeedIsBetweenFactors(t *testing.T) {
	e := newEnv(t)
	const txs = 20
	outOfGas := 0
	height := uint64(10)
	for i := 0; i < txs; i++ {
		e.record(bundle(byte(0x10+i), 0, byte(i+1), 1000))
		e.block(height)
		if e.answerByGas(height, 13) {
			outOfGas++
		}
		height++
	}
	// One out of gas per gasStepDownSuccesses+1 transactions at most.
	if want := txs/(gasStepDownSuccesses+1) + 1; outOfGas > want {
		t.Fatalf("%d of %d record transactions out of gas, want at most %d", outOfGas, txs, want)
	}
}

// The gas factor follows the factor each transaction was sent with: two transactions sent at
// factor 1 that both run out of gas raise it to 2, not 4, and a success of a transaction sent at
// factor 1 does not count toward lowering factor 2.
func TestGasFactorFollowsTheFactorEachTransactionWasSentWith(t *testing.T) {
	e := newEnv(t)
	e.params.MaxEntries = 1
	e.open()
	e.record(bundle(0xaa, 0, 1, 1000), bundle(0xbb, 0, 2, 1000))
	e.block(10)
	msgs, raws := e.tx.sent()
	if len(msgs) != 2 {
		t.Fatalf("%d transactions, want 2", len(msgs))
	}
	e.fail(raws[0], 11, "sdk", 11)
	e.fail(raws[1], 11, "sdk", 11)
	e.block(11)
	if _, factor := e.r.limits(e.params.MaxEntries); factor != 2 {
		t.Fatalf("gas factor %d after two transactions of factor 1 out of gas, want 2", factor)
	}
	// Both go again at factor 2; a third entry is sent at factor 2 as well.
	msgs, raws = e.tx.sent()
	if len(msgs) != 4 || e.tx.gas[2] != 2*recordGas(msgs[2]) || e.tx.gas[3] != 2*recordGas(msgs[3]) {
		t.Fatalf("resent %d transactions with gas %v", len(msgs), e.tx.gas)
	}

	// A transaction sent at factor 1 that succeeds while the factor is 2 changes nothing.
	f := newEnv(t)
	f.params.MaxEntries = 1
	f.open()
	f.record(bundle(0xaa, 0, 1, 1000), bundle(0xbb, 0, 2, 1000))
	f.block(10)
	msgs, raws = f.tx.sent()
	f.fail(raws[0], 11, "sdk", 11)
	f.block(11) // the second result is not out yet
	f.chain.execute(raws[1], executed(t, msgs[1], 12, ok()))
	f.block(12)
	if _, factor := f.r.limits(f.params.MaxEntries); factor != 2 {
		t.Fatalf("gas factor %d after a factor-1 transaction succeeded, want 2", factor)
	}
	if wins := f.r.sizing.gasWins; wins != 0 {
		t.Fatalf("a factor-1 success counted toward lowering factor 2 (%d)", wins)
	}
}

// The gas of a record transaction never exceeds GasMax: a raised factor stops at the cap, and a
// batch out of gas at the cap is halved, since more factor gives it no more gas.
func TestRecordGasIsCapped(t *testing.T) {
	probe := newEnv(t)
	probe.recordFour()
	probe.block(10)
	msg, _ := probe.lastSent()
	formula := recordGas(msg)

	e := newEnv(t)
	e.gasMax = formula + formula/2 // room for 1.5 times the formula's gas
	e.open()
	msgs := func() []*taskv1.MsgRecordDispatch { m, _ := e.tx.sent(); return m }
	e.recordFour()
	e.block(10)
	if gas := e.tx.gas[0]; gas != formula {
		t.Fatalf("gas at factor 1 = %d, want %d", gas, formula)
	}
	_, raw := e.lastSent()
	e.fail(raw, 11, "sdk", 11)
	e.block(11)
	if gas := e.tx.gas[len(e.tx.gas)-1]; gas != e.gasMax {
		t.Fatalf("gas at factor 2 = %d, want the cap %d", gas, e.gasMax)
	}
	if got := entriesOf(msgs()[len(msgs())-1]); !reflect.DeepEqual(got, four()) {
		t.Fatalf("resent %v, want the same batch", got)
	}
	_, raw = e.lastSent()
	e.fail(raw, 12, "sdk", 11)
	e.block(12)
	m := msgs()
	n := len(m)
	if !reflect.DeepEqual(entriesOf(m[n-2]), four()[:2]) || !reflect.DeepEqual(entriesOf(m[n-1]), four()[2:]) {
		t.Fatalf("out of gas at the cap: %v then %v, want the batch halved", entriesOf(m[n-2]), entriesOf(m[n-1]))
	}
	for _, gas := range e.tx.gas {
		if gas > e.gasMax {
			t.Fatalf("gas %d above the cap %d", gas, e.gasMax)
		}
	}
}
