package dispatcher

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/opsmetrics"
	"github.com/TrueOpen/nexus/internal/wirefixture"
	"github.com/TrueOpen/nexus/internal/workerquota"
)

type quotaSource struct {
	facts map[string]workerquota.Facts
	err   error
}

func (s *quotaSource) WorkerQuota(_ context.Context, operator string) (workerquota.Facts, error) {
	if s.err != nil {
		return workerquota.Facts{}, s.err
	}
	return s.facts[operator], nil
}

type fixedPricing struct {
	bps uint32
	err error
}

func (p fixedPricing) VerifyRatioBps(context.Context, []byte, uint32) (uint32, error) {
	return p.bps, p.err
}

// quotaEnv is a metered env whose dispatcher checks Worker quotas read from src. Orders ask for
// 1000 output tokens at a price of 1 per token and a verify ratio of 10%: order_value 1100.
func quotaEnv(t *testing.T) (*env, *quotaSource) {
	t.Helper()
	e := newMeteredEnv(t)
	src := &quotaSource{facts: map[string]workerquota.Facts{}}
	e.orderTerms = func(o *taskv1.TaskOrderV3) {
		o.GenerationParams = &taskv1.GenerationParamsV1{MaxOutputTokens: 1000}
		o.PriceBid = &sharedv1.Amount{AtomicUnits: "1000000"}
		o.MaxFee = &sharedv1.Amount{AtomicUnits: "5000"}
	}
	e.d.cfg.Quota = workerquota.New(src, workerquota.Options{Refresh: time.Hour, Now: e.clock.Now})
	e.d.cfg.Pricing = fixedPricing{bps: 1000}
	return e, src
}

func enforcedQuota(remaining uint64) workerquota.Facts {
	return workerquota.Facts{Enforced: true, Quota: 10_000, Remaining: remaining, Period: 3}
}

func skips(e *env) map[string]uint64 { return e.metrics.Snapshot().Counters[opsmetrics.CounterSkips] }

// A member the chain paused gets a ticket that times out unsent, like an unreachable one, and the
// walk goes on to the next member. It is not a reject and not a received timeout of the Worker.
func TestPausedMemberIsSkippedUnsent(t *testing.T) {
	e, src := quotaEnv(t)
	src.facts[op1] = workerquota.Facts{Paused: true, PauseReasons: workerquota.PauseLateSubmission}
	s := e.session(0xaa, 0)
	e.dispatch(e.order(s, 0, 1)) // drawn op7, op1, op3
	operator, _, _ := e.lastOffer()
	if operator == op1 {
		t.Fatalf("the paused member was offered the order")
	}
	// Take the walk past op1: reject at whoever holds the ticket until op3 has it.
	for operator != op3 {
		e.reject()
		operator, _, _ = e.lastOffer()
	}
	if got := skips(e)[opsmetrics.SkipWorkerPaused]; got != 1 {
		t.Fatalf("skips = %v, want one worker_paused", skips(e))
	}
	if w := e.metrics.Snapshot().Workers[op1]; w.Unsent != 1 || w.Received != 0 || w.Rejected != 0 || w.Timeouts != 0 {
		t.Fatalf("paused Worker's outcomes = %+v, want one unsent ticket only", w)
	}
	for _, c := range e.handraises.outcomeCalls() {
		if c.operator == op1 {
			t.Fatalf("the paused member's skipped ticket fed its reject rate: %+v", c)
		}
	}
}

// A member whose remaining quota does not cover the order is skipped the same way; one whose
// quota covers it is offered the order, and its value is held while the ticket is out.
func TestMemberWithoutQuotaIsSkippedAndTheNextHoldsTheValue(t *testing.T) {
	e, src := quotaEnv(t)
	src.facts[op7] = enforcedQuota(1099) // order_value is 1100
	src.facts[op1] = enforcedQuota(1100)
	src.facts[op3] = enforcedQuota(5000)
	s := e.session(0xaa, 0)
	e.dispatch(e.order(s, 0, 1))
	operator, _, _ := e.lastOffer()
	if operator != op1 {
		t.Fatalf("offered to %s, want op1 (op7 has no quota for the order)", operator)
	}
	if got := skips(e); !reflect.DeepEqual(got, map[string]uint64{opsmetrics.SkipWorkerQuota: 1}) {
		t.Fatalf("skips = %v", got)
	}
	// While op1's ticket is out a second order does not fit op1 any more: it goes to op3.
	s2 := e.session(0xbb, 0)
	e.dispatch(e.order(s2, 0, 2))
	if operator, _, _ := e.lastOffer(); operator != op3 {
		t.Fatalf("second order offered to %s, want op3 (op1's quota is held by the first)", operator)
	}
}

// A reject returns the value to the Worker: its quota is not used up by orders it did not take.
func TestRejectReturnsTheQuota(t *testing.T) {
	e, src := quotaEnv(t)
	src.facts[op7] = enforcedQuota(0)
	src.facts[op1] = enforcedQuota(1100)
	src.facts[op3] = enforcedQuota(1100)
	s := e.session(0xaa, 0)
	e.dispatch(e.order(s, 0, 1))
	if got := e.reject(); got != op1 {
		t.Fatalf("rejected by %s, want op1", got)
	}
	// The order moved on to op3; op1 can take another order of the same value.
	s2 := e.session(0xbb, 0)
	e.dispatch(e.order(s2, 0, 2))
	if operator, _, _ := e.lastOffer(); operator != op1 {
		t.Fatalf("second order offered to %s, want op1 again", operator)
	}
}

// The value stays held after the accept until the chain recorded the order and its figure was read
// again; a refused record gives it back at once.
func TestAcceptedOrderHoldsItsQuotaUntilRecordedOrRefused(t *testing.T) {
	e, src := quotaEnv(t)
	src.facts[op7] = enforcedQuota(0)
	src.facts[op1] = enforcedQuota(1100)
	src.facts[op3] = enforcedQuota(0)
	s := e.session(0xaa, 0)
	e.dispatch(e.order(s, 0, 1))
	if operator, _ := e.accept(); operator != op1 {
		t.Fatalf("accepted by %s, want op1", operator)
	}
	e.clock.advance(10 * time.Minute) // far beyond the accept window: the accept extended the hold
	q := e.d.cfg.Quota.(*workerquota.Ledger)
	if d := q.Admit(context.Background(), op1, "probe", 1, time.Second); d.OK {
		t.Fatal("the accepted order's value was not held while its record is on the way")
	}
	q.Release("probe")
	if err := e.d.RecordRejected(s, 0, errors.New("refused")); err != nil {
		t.Fatal(err)
	}
	if d := q.Admit(context.Background(), op1, "probe", 1100, time.Second); !d.OK {
		t.Fatalf("a refused record did not return the quota: %+v", d)
	}
}

// Without a readable chain figure the order is offered as before Worker quotas existed.
func TestUnreadableQuotaChangesNothing(t *testing.T) {
	e, src := quotaEnv(t)
	src.err = errors.New("endpoint unavailable")
	s := e.session(0xaa, 0)
	e.dispatch(e.order(s, 0, 1))
	if operator, _, _ := e.lastOffer(); operator != op7 {
		t.Fatalf("offered to %s, want the first drawn member op7", operator)
	}
	if got := skips(e); len(got) != 0 {
		t.Fatalf("skips = %v, want none", got)
	}
}

// A chain that does not serve the quota query (an older node) changes nothing either.
func TestChainWithoutQuotaQueryChangesNothing(t *testing.T) {
	e, src := quotaEnv(t)
	src.err = workerquota.ErrUnsupported
	s := e.session(0xaa, 0)
	e.dispatch(e.order(s, 0, 1))
	if operator, _, _ := e.lastOffer(); operator != op7 {
		t.Fatalf("offered to %s, want op7", operator)
	}
}

// Without the Profile's verify ratio the largest value the order can have is charged.
func TestOrderValueWithoutPricingIsTheUpperBound(t *testing.T) {
	e, _ := quotaEnv(t)
	order := &taskv1.TaskOrderV3{
		GenerationParams: &taskv1.GenerationParamsV1{MaxOutputTokens: 1000},
		PriceBid:         &sharedv1.Amount{AtomicUnits: "1000000"},
		MaxFee:           &sharedv1.Amount{AtomicUnits: "5000"}, TxFeeReserve: &sharedv1.Amount{AtomicUnits: "100"},
	}
	if got := e.d.orderValue(context.Background(), order); got != 1100 {
		t.Fatalf("with the ratio: %d, want 1100", got)
	}
	e.d.cfg.Pricing = fixedPricing{err: errors.New("unreadable")}
	if got := e.d.orderValue(context.Background(), order); got != 2000 {
		t.Fatalf("without the ratio: %d, want 2000 (verify share equal to the Worker share)", got)
	}
	order.MaxFee = &sharedv1.Amount{AtomicUnits: "1500"}
	if got := e.d.orderValue(context.Background(), order); got != 1400 {
		t.Fatalf("capped by max_fee minus the reserve: %d, want 1400", got)
	}
}

// OrderValue follows the wire vectors of the chain's derivation.
func TestOrderValueMatchesTheWireVectors(t *testing.T) {
	var vectors struct {
		Cases []struct {
			Name   string `json:"name"`
			Inputs struct {
				MaxOutputTokens string `json:"max_output_tokens"`
				PriceBid        string `json:"price_bid"`
				VerifyRatioBps  uint32 `json:"verify_ratio_bps"`
			} `json:"inputs"`
			Expect     string `json:"expect"`
			OrderValue string `json:"order_value"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(wirefixture.ReadFile(t, "testdata/v1/task/order_economics_v1.json"), &vectors); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, c := range vectors.Cases {
		if c.Expect != "accept" {
			continue
		}
		tokens, err1 := strconv.ParseUint(c.Inputs.MaxOutputTokens, 10, 64)
		price, err2 := strconv.ParseUint(c.Inputs.PriceBid, 10, 64)
		want, err3 := strconv.ParseUint(c.OrderValue, 10, 64)
		if err1 != nil || err2 != nil || err3 != nil {
			t.Fatalf("%s: unreadable vector", c.Name)
		}
		if got := OrderValue(tokens, price, c.Inputs.VerifyRatioBps); got != want {
			t.Errorf("%s: order_value = %d, want %d", c.Name, got, want)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no accepted vector was checked")
	}
	if got := OrderValue(^uint64(0), ^uint64(0), 1000); got != ^uint64(0) {
		t.Fatalf("an overflowing order did not saturate: %d", got)
	}
}
