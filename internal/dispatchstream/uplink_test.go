package dispatchstream

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

func acceptFrame(m *taskv1.DispatchAcceptV1) *nexusv1.DispatchStreamFrameV1 {
	return &nexusv1.DispatchStreamFrameV1{Message: &nexusv1.DispatchStreamFrameV1_Accept{Accept: m}}
}
func rejectFrame(m *taskv1.DispatchRejectV1) *nexusv1.DispatchStreamFrameV1 {
	return &nexusv1.DispatchStreamFrameV1{Message: &nexusv1.DispatchStreamFrameV1_Reject{Reject: m}}
}
func inputRequestFrame(m *nexusv1.DispatchInputRequestV1) *nexusv1.DispatchStreamFrameV1 {
	return &nexusv1.DispatchStreamFrameV1{Message: &nexusv1.DispatchStreamFrameV1_InputRequest{InputRequest: m}}
}
func standingFrame(m *taskv1.StandingHandraiseV1) *nexusv1.DispatchStreamFrameV1 {
	return &nexusv1.DispatchStreamFrameV1{Message: &nexusv1.DispatchStreamFrameV1_Handraise{Handraise: m}}
}
func noticeFrame(m *nexusv1.VerifyResultSubmittedNoticeV1) *nexusv1.DispatchStreamFrameV1 {
	return &nexusv1.DispatchStreamFrameV1{Message: &nexusv1.DispatchStreamFrameV1_VerifyResultSubmitted{VerifyResultSubmitted: m}}
}
func verifierHandraiseFrame(m *taskv1.VerifierHandraiseV1) *nexusv1.DispatchStreamFrameV1 {
	return &nexusv1.DispatchStreamFrameV1{Message: &nexusv1.DispatchStreamFrameV1_VerifierHandraise{VerifierHandraise: m}}
}

// Every verified uplink message reaches its receiver, with the bytes and digest it was verified
// over, and its cursor is acknowledged only after that.
func TestUplinkRoutesVerifiedMessages(t *testing.T) {
	h := newHarness(t)
	s := h.connect(cortexA, "1")
	frames := []struct {
		kind  string
		frame *nexusv1.DispatchStreamFrameV1
		name  string
	}{
		{"handraise", standingFrame(h.keys.standing(t, cortexA)), "task.v1.StandingHandraiseV1"},
		{"accept", acceptFrame(h.keys.accept(t, cortexA, "t1")), "task.v1.DispatchAcceptV1"},
		{"reject", rejectFrame(h.keys.reject(t, cortexA, "t2")), "task.v1.DispatchRejectV1"},
		{"input_request", inputRequestFrame(h.keys.inputRequest(t, cortexA, "t1")), "nexus.v1.DispatchInputRequestV1"},
		{"verifier_handraise", verifierHandraiseFrame(h.keys.verifierHandraise(t, cortexA)), ""},
		{"verify_result_submitted", noticeFrame(h.keys.verifyNotice(t, cortexA, "t3")), "nexus.v1.VerifyResultSubmittedNoticeV1"},
	}
	var want []string
	for _, f := range frames {
		cursor := s.send(f.frame)
		if got := s.stream.nextAck(t); got != cursor {
			t.Fatalf("%s acked %d, want %d", f.kind, got, cursor)
		}
		want = append(want, f.kind)
	}
	if got := h.sinks.kinds(); !slices.Equal(got, want) {
		t.Fatalf("routed %v, want %v", got, want)
	}
	for i, f := range frames {
		if h.sinks.operators[i] != cortexA {
			t.Fatalf("%s routed for operator %s", f.kind, h.sinks.operators[i])
		}
		if f.name == "" || f.kind == "verify_result_submitted" {
			continue
		}
		origin := h.sinks.origins[i]
		digest, err := dispatch.SigningDigest(f.name, origin.Raw)
		if err != nil || digest != origin.Digest {
			t.Fatalf("%s origin digest does not match its raw bytes: %v", f.kind, err)
		}
	}
}

// Each message is verified on its own: a valid binding does not vouch for a message signed by
// another key, naming another signer or chain, carrying an old nonce or altered after signing.
// Such a message is dropped (and acknowledged, since it can never become valid); the stream goes on.
func TestUplinkRefusesUnverifiedMessages(t *testing.T) {
	h := newHarness(t)
	k := h.keys
	resign := func(m proto.Message, name, operator string, set func([]byte)) {
		sign(t, k.signer(operator), name, m, set)
	}
	type tc struct {
		name  string
		frame *nexusv1.DispatchStreamFrameV1
	}
	var cases []tc
	{
		m := k.accept(t, cortexA, "a")
		resign(m, "task.v1.DispatchAcceptV1", cortexB, func(s []byte) { m.ServiceSignature = s })
		cases = append(cases, tc{"accept signed by another key", acceptFrame(m)})
	}
	cases = append(cases, tc{"accept of another Cortex", acceptFrame(k.accept(t, cortexB, "a"))})
	{
		m := k.accept(t, cortexA, "a")
		m.ChainId = "other-chain"
		resign(m, "task.v1.DispatchAcceptV1", cortexA, func(s []byte) { m.ServiceSignature = s })
		cases = append(cases, tc{"accept for another chain", acceptFrame(m)})
	}
	{
		m := k.accept(t, cortexA, "a")
		m.ServiceAuthorizationNonce = testNonce - 1
		resign(m, "task.v1.DispatchAcceptV1", cortexA, func(s []byte) { m.ServiceSignature = s })
		cases = append(cases, tc{"accept with an old nonce", acceptFrame(m)})
	}
	{
		m := k.accept(t, cortexA, "a")
		m.DispatchTicketHash = hash32("another ticket")
		cases = append(cases, tc{"accept altered after signing", acceptFrame(m)})
	}
	{
		m := k.reject(t, cortexA, "r")
		m.RejectReason = 2
		cases = append(cases, tc{"reject altered after signing", rejectFrame(m)})
	}
	cases = append(cases, tc{"reject of another Cortex", rejectFrame(k.reject(t, cortexB, "r"))})
	{
		m := k.inputRequest(t, cortexA, "i")
		m.TaskId = hash32("other task")
		cases = append(cases, tc{"input request altered after signing", inputRequestFrame(m)})
	}
	cases = append(cases, tc{"input request of another Cortex", inputRequestFrame(k.inputRequest(t, cortexB, "i"))})
	{
		m := k.standing(t, cortexA)
		m.FreeSlotCount = 9
		cases = append(cases, tc{"standing handraise altered after signing", standingFrame(m)})
	}
	{
		m := k.standing(t, cortexA)
		m.BuilderAddress = cortexB
		resign(m, "task.v1.StandingHandraiseV1", cortexA, func(s []byte) { m.ServiceSignature = s })
		cases = append(cases, tc{"standing handraise for another Builder", standingFrame(m)})
	}
	{
		m := k.verifyNotice(t, cortexA, "v")
		m.CommitKey = hash32("other commit")
		cases = append(cases, tc{"verify notice altered after signing", noticeFrame(m)})
	}
	cases = append(cases, tc{"verify notice of another Cortex", noticeFrame(k.verifyNotice(t, cortexB, "v"))})
	cases = append(cases, tc{"verifier handraise of another Cortex", verifierHandraiseFrame(k.verifierHandraise(t, cortexB))})
	{
		m := k.verifierHandraise(t, cortexA)
		m.ServiceAuthorizationNonce = testNonce + 1
		resign(m, verifierHandraiseMessage, cortexA, func(s []byte) { m.ServiceSignature = s })
		cases = append(cases, tc{"verifier handraise with another nonce", verifierHandraiseFrame(m)})
	}
	{
		m := k.verifierHandraise(t, cortexA)
		m.ChainId = "other-chain"
		resign(m, verifierHandraiseMessage, cortexA, func(s []byte) { m.ServiceSignature = s })
		cases = append(cases, tc{"verifier handraise for another chain", verifierHandraiseFrame(m)})
	}
	{
		m := k.verifierHandraise(t, cortexA)
		m.ExpiryHeight++
		cases = append(cases, tc{"verifier handraise altered after signing", verifierHandraiseFrame(m)})
	}
	{
		m := k.verifierHandraise(t, cortexA)
		resign(m, verifierHandraiseMessage, cortexB, func(s []byte) { m.ServiceSignature = s })
		cases = append(cases, tc{"verifier handraise signed by another key", verifierHandraiseFrame(m)})
	}

	s := h.connect(cortexA, "1")
	for _, c := range cases {
		cursor := s.send(c.frame)
		if got := s.stream.nextAck(t); got != cursor {
			t.Fatalf("%s: acked %d, want %d", c.name, got, cursor)
		}
		if routed := h.sinks.kinds(); len(routed) != 0 {
			t.Fatalf("%s was routed: %v", c.name, routed)
		}
	}
	if !h.hub.Connected(cortexA) {
		t.Fatal("refused messages ended the stream")
	}
}

// After a Cortex's cutover its accepts and rejects signed with the retired key still prove a
// ticket whose order's earliest_submit_height and own bound_change_height are both below the
// retirement height; later orders, tickets bound at or after the cutover even for an earlier
// order, and tickets whose order is unknown, need the current key.
func TestUplinkAcceptsPreviousKeyAnswersOfOrdersBeforeTheCutover(t *testing.T) {
	h := newHarness(t)
	old := testAccount("old|" + cortexA)
	h.keys.previous[cortexA] = previousKey{key: old, nonce: testNonce - 1, retired: 120}
	h.sinks.heights = map[string][2]uint64{string(hash32("ticket|before")): {119, 110}, string(hash32("ticket|at")): {120, 110},
		string(hash32("ticket|rebound")): {119, 120}, string(hash32("ticket|rbefore")): {119, 110}}
	byOld := func(m proto.Message, name string, setNonce func(), set func([]byte)) {
		setNonce()
		sign(t, old, name, m, set)
	}
	before, at, unknown := h.keys.accept(t, cortexA, "before"), h.keys.accept(t, cortexA, "at"), h.keys.accept(t, cortexA, "unknown")
	rebound := h.keys.accept(t, cortexA, "rebound")
	for _, m := range []*taskv1.DispatchAcceptV1{before, at, unknown, rebound} {
		byOld(m, "task.v1.DispatchAcceptV1", func() { m.ServiceAuthorizationNonce = testNonce - 1 }, func(s []byte) { m.ServiceSignature = s })
	}
	reject := h.keys.reject(t, cortexA, "rbefore")
	byOld(reject, "task.v1.DispatchRejectV1", func() { reject.ServiceAuthorizationNonce = testNonce - 1 }, func(s []byte) { reject.ServiceSignature = s })

	s := h.connect(cortexA, "1")
	for _, f := range []*nexusv1.DispatchStreamFrameV1{acceptFrame(before), acceptFrame(at), acceptFrame(unknown), acceptFrame(rebound), rejectFrame(reject),
		acceptFrame(h.keys.accept(t, cortexA, "at"))} {
		cursor := s.send(f)
		if got := s.stream.nextAck(t); got != cursor {
			t.Fatalf("acked %d, want %d", got, cursor)
		}
	}
	if got := h.sinks.kinds(); !slices.Equal(got, []string{"accept", "reject", "accept"}) {
		t.Fatalf("routed %v; want the pre-cutover accept and reject and the current-key accept", got)
	}
}

// A verifier handraise is verified like every other uplink message: the wire vector's exact
// protobuf verifies under its key, and the same message with another signature does not.
func TestVerifierHandraiseVerifiesTheWireVector(t *testing.T) {
	var file struct {
		Vectors []struct {
			Name         string `json:"name"`
			ProtobufHex  string `json:"protobuf_hex"`
			DigestHex    string `json:"digest_hex"`
			PublicKeyHex string `json:"public_key_hex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(wirefixture.ReadFile(t, "testdata/v1/task/dispatch_v1.json"), &file); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, vector := range file.Vectors {
		if vector.Name != "task_v1_verifierhandraisev1" {
			continue
		}
		found = true
		raw, _ := hex.DecodeString(vector.ProtobufHex)
		m := &taskv1.VerifierHandraiseV1{}
		if err := proto.Unmarshal(raw, m); err != nil {
			t.Fatal(err)
		}
		pub, _ := hex.DecodeString(vector.PublicKeyHex)
		operator := m.GetMember().GetOperatorAddress()
		keys := vectorKeys{operator, CortexKey{PubKey: pub, AuthorizationNonce: m.GetServiceAuthorizationNonce()}}
		hub, err := New(nil, Config{ChainID: m.GetChainId(), BuilderOperator: testBuilder}, keys, kv.NewMemStore())
		if err != nil {
			t.Fatal(err)
		}
		claims, _ := claimsOf(verifierHandraiseFrame(m))
		from, err := hub.verifyUplink(context.Background(), operator, claims)
		if err != nil {
			t.Fatalf("wire vector verifier handraise refused: %v", err)
		}
		if hex.EncodeToString(from.Digest[:]) != vector.DigestHex {
			t.Fatalf("verified digest %x, want %s", from.Digest, vector.DigestHex)
		}
		m.ServiceSignature[0] ^= 1
		claims, _ = claimsOf(verifierHandraiseFrame(m))
		if _, err := hub.verifyUplink(context.Background(), operator, claims); !errors.Is(err, errUplinkRefused) {
			t.Fatalf("altered signature: err = %v, want refused", err)
		}
	}
	if !found {
		t.Fatal("wire vector task_v1_verifierhandraisev1 not found")
	}
}

// A message that cannot be judged now (the chain cannot be read, or the receiver asks for a retry)
// is not acknowledged: the stream ends and the Cortex sends it again after reconnecting. Losing an
// accept or reject silently is worse than a reconnect.
func TestUplinkTransientFailureEndsTheStreamUnacknowledged(t *testing.T) {
	keys := newTestKeys()
	for name, frame := range map[string]*nexusv1.DispatchStreamFrameV1{
		"accept":             acceptFrame(keys.accept(t, cortexA, "a")),
		"reject":             rejectFrame(keys.reject(t, cortexA, "r")),
		"input request":      inputRequestFrame(keys.inputRequest(t, cortexA, "i")),
		"verifier handraise": verifierHandraiseFrame(keys.verifierHandraise(t, cortexA)),
		"verify notice":      noticeFrame(keys.verifyNotice(t, cortexA, "n")),
	} {
		t.Run("key lookup/"+name, func(t *testing.T) {
			h := newHarness(t)
			s := h.connect(cortexA, "1")
			h.keys.setTransient(true)
			s.send(frame)
			if err := s.wait(t); !errors.Is(err, ErrTransient) {
				t.Fatalf("Serve = %v, want ErrTransient", err)
			}
			assertNoAck(t, s)
		})
	}
	t.Run("receiver", func(t *testing.T) {
		h := newHarness(t)
		s := h.connect(cortexA, "1")
		h.sinks.setErr(fmt.Errorf("%w: store busy", ErrTransient))
		s.send(acceptFrame(h.keys.accept(t, cortexA, "a")))
		if err := s.wait(t); !errors.Is(err, ErrTransient) {
			t.Fatalf("Serve = %v, want ErrTransient", err)
		}
		assertNoAck(t, s)
	})
}

// A standing handraise whose CORTEX key cannot be read is acknowledged and dropped and the stream
// goes on: handraises are soft state the Cortex re-signs every heartbeat. The drops are warned
// about at most once a minute.
func TestUplinkStandingHandraiseKeyFailureKeepsTheStream(t *testing.T) {
	h := newHarness(t)
	logs := &countingHandler{}
	h.hub.log = slog.New(logs)
	s := h.connect(cortexA, "1")
	h.keys.setTransient(true)
	for range 2 {
		cursor := s.send(standingFrame(h.keys.standing(t, cortexA)))
		if got := s.stream.nextAck(t); got != cursor {
			t.Fatalf("acked cursor %d, want %d", got, cursor)
		}
	}
	if got := h.sinks.kinds(); len(got) != 0 {
		t.Fatalf("routed %v, want the handraises dropped", got)
	}
	if got := logs.count(slog.LevelWarn); got != 1 {
		t.Fatalf("warnings = %d, want 1", got)
	}
	h.clock.advance(time.Minute)
	cursor := s.send(standingFrame(h.keys.standing(t, cortexA)))
	if got := s.stream.nextAck(t); got != cursor {
		t.Fatalf("acked cursor %d, want %d", got, cursor)
	}
	if got := logs.count(slog.LevelWarn); got != 2 {
		t.Fatalf("warnings after a minute = %d, want 2", got)
	}

	h.keys.setTransient(false)
	cursor = s.send(acceptFrame(h.keys.accept(t, cortexA, "a")))
	if got := s.stream.nextAck(t); got != cursor || !slices.Equal(h.sinks.kinds(), []string{"accept"}) {
		t.Fatalf("stream after the drops: acked %d (want %d), routed %v", got, cursor, h.sinks.kinds())
	}
}

// countingHandler counts log records by level.
type countingHandler struct {
	mu     sync.Mutex
	counts map[slog.Level]int
}

func (c *countingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (c *countingHandler) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.counts == nil {
		c.counts = map[slog.Level]int{}
	}
	c.counts[r.Level]++
	return nil
}
func (c *countingHandler) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *countingHandler) WithGroup(string) slog.Handler      { return c }

func (c *countingHandler) count(level slog.Level) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[level]
}

func assertNoAck(t *testing.T, s *served) {
	t.Helper()
	for {
		select {
		case f := <-s.stream.out:
			if f.GetAck() != nil {
				t.Fatalf("frame acknowledged: %v", f)
			}
		default:
			return
		}
	}
}

// A receiver's ordinary refusal is final: logged, acknowledged, the stream goes on.
func TestUplinkReceiverRefusalIsAcknowledged(t *testing.T) {
	h := newHarness(t)
	s := h.connect(cortexA, "1")
	h.sinks.setErr(errors.New("ticket closed"))
	cursor := s.send(acceptFrame(h.keys.accept(t, cortexA, "a")))
	if got := s.stream.nextAck(t); got != cursor {
		t.Fatalf("acked %d, want %d", got, cursor)
	}
	if !h.hub.Connected(cortexA) {
		t.Fatal("a receiver refusal ended the stream")
	}
}

// An acknowledgement of zero acknowledges nothing: the message stays retained and the stream goes on.
func TestAckZeroAcknowledgesNothing(t *testing.T) {
	h := newHarness(t)
	s := h.connect(cortexA, "1")
	if err := h.hub.Send(context.Background(), cortexA, offer("a")); err != nil {
		t.Fatal(err)
	}
	s.stream.nextBusiness(t)
	s.ack(0)
	s.stream.quiet(t)
	if !h.hub.Connected(cortexA) {
		t.Fatal("ack 0 ended the stream")
	}
	h.hub.mu.Lock()
	pending := len(h.hub.pending[cortexA])
	h.hub.mu.Unlock()
	if pending != 1 {
		t.Fatalf("%d messages retained after ack 0, want 1", pending)
	}
}

// Frames that break the stream rules end the stream.
func TestUplinkProtocolViolationsEndTheStream(t *testing.T) {
	cases := []struct {
		name  string
		frame func(h *harness, s *served) *nexusv1.DispatchStreamFrameV1
	}{
		{"business frame without cursor", func(h *harness, s *served) *nexusv1.DispatchStreamFrameV1 {
			f := acceptFrame(h.keys.accept(t, cortexA, "a"))
			f.StreamNonce = s.nonce
			return f
		}},
		{"wrong stream_nonce", func(h *harness, s *served) *nexusv1.DispatchStreamFrameV1 {
			f := acceptFrame(h.keys.accept(t, cortexA, "a"))
			f.StreamNonce, f.Cursor = hash32("other"), 1
			return f
		}},
		{"downlink message kind", func(h *harness, s *served) *nexusv1.DispatchStreamFrameV1 {
			f := offer("x")
			f.StreamNonce, f.Cursor = s.nonce, 1
			return f
		}},
		{"second binding", func(h *harness, s *served) *nexusv1.DispatchStreamFrameV1 {
			f := bindingFrame(h.keys.binding(t, cortexA, s.nonce))
			f.Cursor = 1
			return f
		}},
		{"empty frame", func(h *harness, s *served) *nexusv1.DispatchStreamFrameV1 {
			return &nexusv1.DispatchStreamFrameV1{StreamNonce: s.nonce, Cursor: 1}
		}},
		{"first business cursor is not 1", func(h *harness, s *served) *nexusv1.DispatchStreamFrameV1 {
			f := acceptFrame(h.keys.accept(t, cortexA, "a"))
			f.StreamNonce, f.Cursor = s.nonce, 2
			return f
		}},
		{"business cursor skips one", func(h *harness, s *served) *nexusv1.DispatchStreamFrameV1 {
			s.send(acceptFrame(h.keys.accept(t, cortexA, "a")))
			s.stream.nextAck(t)
			f := acceptFrame(h.keys.accept(t, cortexA, "b"))
			f.StreamNonce, f.Cursor = s.nonce, 3
			return f
		}},
		{"business cursor repeated", func(h *harness, s *served) *nexusv1.DispatchStreamFrameV1 {
			frame := acceptFrame(h.keys.accept(t, cortexA, "a"))
			cursor := s.send(frame)
			s.stream.nextAck(t)
			return &nexusv1.DispatchStreamFrameV1{StreamNonce: s.nonce, Cursor: cursor, Message: frame.GetMessage()}
		}},
		{"ack with a cursor", func(h *harness, s *served) *nexusv1.DispatchStreamFrameV1 {
			return &nexusv1.DispatchStreamFrameV1{StreamNonce: s.nonce, Cursor: 1,
				Message: &nexusv1.DispatchStreamFrameV1_Ack{Ack: &nexusv1.StreamAckV1{}}}
		}},
		{"keepalive with a cursor", func(h *harness, s *served) *nexusv1.DispatchStreamFrameV1 {
			return &nexusv1.DispatchStreamFrameV1{StreamNonce: s.nonce, Cursor: 1,
				Message: &nexusv1.DispatchStreamFrameV1_Keepalive{Keepalive: &nexusv1.StreamKeepaliveV1{SentAtMs: 1}}}
		}},
		{"ack beyond the last cursor sent", func(h *harness, s *served) *nexusv1.DispatchStreamFrameV1 {
			if err := h.hub.Send(context.Background(), cortexA, offer("a")); err != nil {
				t.Fatal(err)
			}
			s.stream.nextBusiness(t)
			return &nexusv1.DispatchStreamFrameV1{StreamNonce: s.nonce,
				Message: &nexusv1.DispatchStreamFrameV1_Ack{Ack: &nexusv1.StreamAckV1{AckedCursor: 2}}}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			s := h.connect(cortexA, "1")
			s.stream.in <- c.frame(h, s)
			if err := s.wait(t); !errors.Is(err, ErrProtocol) {
				t.Fatalf("Serve = %v, want ErrProtocol", err)
			}
			h.waitConn(cortexA, false)
		})
	}
}
