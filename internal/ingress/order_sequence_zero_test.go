package ingress

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
)

// TestSubmitOrderAcceptsSequenceZero pins down that "0 is a valid first value".
//
// The first order of every on-chain session has order_sequence = 0: the Keeper does not assign
// NextExpectedSequence when creating StreamState (Go zero value 0), and consumeOrderSequence requires
// order_sequence to equal it exactly (node x/task/keeper/order_sequence.go:35).
//
// Previously ingress treated `GetOrderSequence() == 0` as "unset" and rejected it, so **the first order of
// any new session could never reach nexus** -- the SDK side only saw "order_sequence ... are
// required", while the value it filled in was the only correct one. uint64 has no "unset" state to test anyway:
// proto3 scalars carry no presence.
func TestSubmitOrderAcceptsSequenceZero(t *testing.T) {
	sg := mustSigner(t, testKeyHex)
	fake := &fakeHandler{}
	client := newTestClient(t, fake, AuthParams{ChainID: "trueopen-localnet", Bech32Prefix: "trueopen", RequireEnvelope: true})
	ctx := context.Background()

	req := canonicalOrderRequest(t, sg, testSessionID("sess-seq-zero"), 0, "model-test")
	req.RequestEnvelope = signedEnvelope(t, sg, "SubmitOrder", submitOrderBodyDigest(req))

	resp, err := client.SubmitOrder(ctx, connect.NewRequest(req))
	if err != nil {
		t.Fatalf("order_sequence=0 is the valid first value of every session but was rejected: %v", err)
	}
	if !resp.Msg.GetAccepted() {
		t.Fatalf("order_sequence=0 was not accepted: %+v", resp.Msg)
	}
	if fake.lastOrder.OrderSequence != 0 {
		t.Fatalf("persisted order_sequence = %d, want 0", fake.lastOrder.OrderSequence)
	}
}

// TestOpenTaskHeaderAcceptsSequenceZero covers the other half of the same check: the data-plane
// OpenTask header previously had an identical `== 0` check, and the two must stay in sync.
func TestOpenTaskHeaderAcceptsSequenceZero(t *testing.T) {
	sg := mustSigner(t, testKeyHex)
	s := &service{}
	header := &nexusv1.OpenTaskHeader{
		SessionId: testSessionID("sess-header-zero"), OrderSequence: 0,
		UserAddress: sg.Address(),
	}
	// Only assert "not rejected as malformed because of order_sequence=0": the other required fields are
	// deliberately left empty here, so it still fails -- but the reason must not be the sequence.
	_, _, err := s.validateOpenTaskHeader(context.Background(), header)
	if err == nil {
		t.Skip("header validation passed, so the other required fields are not needed either; this case is no longer meaningful")
	}
	// Swap order_sequence for an "obviously valid" non-zero value; the error must be exactly the same --
	// if it differs, 0 is still being singled out.
	header.OrderSequence = 7
	_, _, other := s.validateOpenTaskHeader(context.Background(), header)
	if other == nil || err.Error() != other.Error() {
		t.Fatalf("order_sequence=0 and =7 validate differently, so 0 is still treated as unset:\n 0 -> %v\n 7 -> %v", err, other)
	}
}
