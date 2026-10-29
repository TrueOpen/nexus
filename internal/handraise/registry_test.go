package handraise

import (
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

func TestAcceptKeepsOneCurrentHandraisePerMember(t *testing.T) {
	e := newEnv(t)
	c := e.addCortex(0x11, 4)
	first := e.handraise(c, 100, 1)
	e.mustAccept(c, first)

	e.clock.advance(time.Second)
	second := e.handraise(c, 100, 2)
	e.mustAccept(c, second)

	got, ok := e.reg.Current(c.operator())
	if !ok || !proto.Equal(got, second) {
		t.Fatalf("current = %v, want the newer handraise", got)
	}
	root := e.mustIssue()
	if len(root.Leaves) != 1 || !proto.Equal(root.Leaves[0].GetHandraise(), second) {
		t.Fatalf("root leaves = %v, want only the newer handraise", root.Leaves)
	}
}

func TestAcceptOrdersByIssuedHeightThenNonce(t *testing.T) {
	e := newEnv(t)
	c := e.addCortex(0x11, 4)
	e.mustAccept(c, e.handraise(c, 100, 5))
	e.clock.advance(time.Second)
	// A higher issued height wins even with a smaller nonce.
	newer := e.handraise(c, 101, 0)
	e.mustAccept(c, newer)
	e.clock.advance(time.Second)
	sameKey := e.handraise(c, 101, 0)
	sameKey.FreeSlotCount = 9 // a different handraise with the same (issued_height, handraise_nonce)
	for _, old := range []*taskv1.StandingHandraiseV1{
		signHandraise(t, c.key, sameKey),
		e.handraise(c, 100, 9), // lower height, bigger nonce
	} {
		wantCode(t, e.accept(c, old), ErrInvalid)
	}
	if got, _ := e.reg.Current(c.operator()); !proto.Equal(got, newer) {
		t.Fatal("a replayed handraise replaced the current one")
	}
}

// Resending the current handraise, as a reconnecting Cortex does, is accepted without effect.
func TestAcceptResendOfCurrentIsIdempotent(t *testing.T) {
	e := newEnv(t)
	c := e.addCortex(0x11, 4)
	h := e.handraise(c, 100, 1)
	e.mustAccept(c, h)
	e.mustAccept(c, proto.Clone(h).(*taskv1.StandingHandraiseV1))
}

func TestAcceptRefusesRapidResign(t *testing.T) {
	e := newEnv(t)
	c := e.addCortex(0x11, 4)
	e.mustAccept(c, e.handraise(c, 100, 1))
	e.clock.advance(50 * time.Millisecond) // under half of handraise_min_change_interval_ms
	wantCode(t, e.accept(c, e.handraise(c, 100, 2)), ErrInvalid)
	e.clock.advance(60 * time.Millisecond)
	e.mustAccept(c, e.handraise(c, 100, 2))
}

func TestAcceptRejectsMalformedWithoutTrace(t *testing.T) {
	e := newEnv(t)
	c := e.addCortex(0x11, 4)
	other := e.addCortex(0x22, 5)
	cases := map[string]func(*taskv1.StandingHandraiseV1){
		"wrong chain":           func(h *taskv1.StandingHandraiseV1) { h.ChainId = "other-chain" },
		"other builder":         func(h *taskv1.StandingHandraiseV1) { h.BuilderAddress = other.operator() },
		"member is not sender":  func(h *taskv1.StandingHandraiseV1) { h.Member.OperatorAddress = other.operator() },
		"schema version":        func(h *taskv1.StandingHandraiseV1) { h.SchemaVersion = 2 },
		"no profiles":           func(h *taskv1.StandingHandraiseV1) { h.Profiles = nil },
		"unsorted profiles":     func(h *taskv1.StandingHandraiseV1) { h.Profiles = append(h.Profiles, testProfile()) },
		"bad model id":          func(h *taskv1.StandingHandraiseV1) { h.Profiles[0].ModelId = []byte{1} },
		"expired":               func(h *taskv1.StandingHandraiseV1) { h.IssuedHeight, h.ExpiryHeight = 90, 99 },
		"issued in the future":  func(h *taskv1.StandingHandraiseV1) { h.IssuedHeight, h.ExpiryHeight = 102, 150 },
		"expiry before issue":   func(h *taskv1.StandingHandraiseV1) { h.IssuedHeight, h.ExpiryHeight = 101, 100 },
		"no authorization":      func(h *taskv1.StandingHandraiseV1) { h.ServiceAuthorizationNonce = 0 },
		"no member":             func(h *taskv1.StandingHandraiseV1) { h.Member = nil },
		"short signature bytes": func(h *taskv1.StandingHandraiseV1) {},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			h := e.handraise(c, 100, 1)
			mutate(h)
			switch name {
			case "short signature bytes":
				h.ServiceSignature = h.ServiceSignature[:10]
			case "bad model id", "no member":
				// No signing digest exists; the stale signature stays.
			default:
				h = signHandraise(t, c.key, h)
			}
			wantCode(t, e.accept(c, h), ErrInvalid)
		})
	}
	if _, ok := e.reg.Current(c.operator()); ok {
		t.Fatal("a malformed handraise became current")
	}
	if root := e.issue(); root != nil {
		t.Fatalf("malformed handraises left leaves: %v", root.Leaves)
	}
}

func TestInvalidHandraiseIsTracedInTheNextRoot(t *testing.T) {
	cases := map[string]struct {
		prepare func(e *env, c cortex, h *taskv1.StandingHandraiseV1) *taskv1.StandingHandraiseV1
		code    error
	}{
		"bad signature": {func(e *env, c cortex, h *taskv1.StandingHandraiseV1) *taskv1.StandingHandraiseV1 {
			return signHandraise(e.t, newSigner(e.t, 0x77), h)
		}, ErrInvalid},
		"no current service key": {func(e *env, c cortex, h *taskv1.StandingHandraiseV1) *taskv1.StandingHandraiseV1 {
			delete(e.keys.cortex, c.operator())
			return h
		}, ErrInvalid},
		"stale authorization nonce": {func(e *env, c cortex, h *taskv1.StandingHandraiseV1) *taskv1.StandingHandraiseV1 {
			h.ServiceAuthorizationNonce = c.nonce - 1
			return signHandraise(e.t, c.key, h)
		}, ErrInvalid},
		"not in the candidate pool": {func(e *env, c cortex, h *taskv1.StandingHandraiseV1) *taskv1.StandingHandraiseV1 {
			e.pool.members[c.operator()] = false
			return h
		}, ErrNotEligible},
		"profile without fresh support": {func(e *env, c cortex, h *taskv1.StandingHandraiseV1) *taskv1.StandingHandraiseV1 {
			e.pool.support[c.operator()] = nil
			return h
		}, ErrNotEligible},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			c := e.addCortex(0x11, 4)
			valid := e.addCortex(0x22, 5)
			e.mustAccept(valid, e.handraise(valid, 100, 1))

			h := tc.prepare(e, c, e.handraise(c, 100, 1))
			wantCode(t, e.accept(c, h), tc.code)
			if _, ok := e.reg.Current(c.operator()); ok {
				t.Fatal("an invalid handraise became current")
			}

			root := e.mustIssue()
			if len(root.Leaves) != 2 {
				t.Fatalf("leaves = %d, want the valid one and the invalid trace", len(root.Leaves))
			}
			var trace *taskv1.HandraiseRootLeafV1
			for _, leaf := range root.Leaves {
				if leaf.GetHandraise().GetMember().GetOperatorAddress() == c.operator() {
					trace = leaf
				}
			}
			if trace == nil || trace.GetAdmitted() ||
				trace.GetAdmitRejectReason() != taskv1.AdmitRejectReasonV1_ADMIT_REJECT_REASON_V1_INVALID_HANDRAISE ||
				trace.GetBuilderMeasuredRttMs() != 0 || !proto.Equal(trace.GetHandraise(), h) {
				t.Fatalf("invalid trace leaf = %v", trace)
			}
			if notice, ok := root.Notice(c.operator()); !ok || !proto.Equal(notice.GetProof().GetLeaf(), trace) {
				t.Fatalf("notice for the invalid sender = %v", notice)
			}
			// The trace appears once; the next root only carries the valid handraise.
			e.height.set(101)
			next := e.mustIssue()
			if len(next.Leaves) != 1 || next.Leaves[0].GetHandraise().GetMember().GetOperatorAddress() != valid.operator() {
				t.Fatalf("next root leaves = %v", next.Leaves)
			}
		})
	}
}

// An invalid handraise never displaces the sender's current one.
func TestInvalidHandraiseKeepsTheCurrentOne(t *testing.T) {
	e := newEnv(t)
	c := e.addCortex(0x11, 4)
	current := e.handraise(c, 100, 1)
	e.mustAccept(c, current)
	e.clock.advance(time.Second)
	forged := signHandraise(t, newSigner(t, 0x77), e.handraise(c, 100, 2))
	wantCode(t, e.accept(c, forged), ErrInvalid)
	if got, _ := e.reg.Current(c.operator()); !proto.Equal(got, current) {
		t.Fatal("an invalid handraise replaced the current one")
	}
	root := e.mustIssue()
	if len(root.Leaves) != 2 || !leafOf(t, root, c.operator()).GetAdmitted() {
		t.Fatalf("leaves = %v", root.Leaves)
	}
	notice, ok := root.Notice(c.operator())
	if !ok || !notice.GetProof().GetLeaf().GetAdmitted() {
		t.Fatalf("notice should prove the current handraise, got %v", notice)
	}
}

// A chain lookup failure is neither a verdict nor a trace: the caller may retry.
func TestAcceptChainFailureIsNotAVerdict(t *testing.T) {
	e := newEnv(t)
	c := e.addCortex(0x11, 4)
	e.keys.err = errors.New("node down")
	err := e.accept(c, e.handraise(c, 100, 1))
	if err == nil || errors.Is(err, ErrInvalid) || errors.Is(err, ErrNotEligible) {
		t.Fatalf("err = %v, want a lookup failure", err)
	}
	e.keys.err = nil
	e.pool.err = errors.New("node down")
	err = e.accept(c, e.handraise(c, 100, 1))
	if err == nil || errors.Is(err, ErrInvalid) || errors.Is(err, ErrNotEligible) {
		t.Fatalf("err = %v, want a lookup failure", err)
	}
	if root := e.issue(); root != nil {
		t.Fatalf("lookup failures left leaves: %v", root.Leaves)
	}
}

func TestHandraiseExpiresAfterTTL(t *testing.T) {
	e := newEnv(t)
	c := e.addCortex(0x11, 4)
	e.mustAccept(c, e.handraise(c, 100, 1))
	first := e.mustIssue()
	if len(first.Leaves) != 1 {
		t.Fatalf("leaves = %d", len(first.Leaves))
	}
	e.clock.advance(6*time.Second + time.Millisecond)
	if _, ok := e.reg.Current(c.operator()); ok {
		t.Fatal("handraise still current after handraise_ttl_ms")
	}
	empty := e.mustIssue()
	if len(empty.Leaves) != 0 || empty.Root.GetLeafCount() != 0 {
		t.Fatalf("expired handraise still in the root: %v", empty.Leaves)
	}
	if _, found := e.store.Get(nsCurrentKey(c.operator())); found {
		t.Fatal("expired handraise still stored")
	}
}

func TestHandraiseExpiresAtExpiryHeight(t *testing.T) {
	e := newEnv(t)
	c := e.addCortex(0x11, 4)
	e.mustAccept(c, e.handraise(c, 100, 1)) // expiry_height 150
	e.height.set(150)
	if root := e.mustIssue(); len(root.Leaves) != 1 {
		t.Fatal("handraise dropped at its expiry height")
	}
	e.height.set(151)
	if root := e.mustIssue(); len(root.Leaves) != 0 {
		t.Fatal("handraise kept after its expiry height")
	}
}
