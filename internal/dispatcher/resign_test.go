package dispatcher

import (
	"bytes"
	"testing"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

// verifies reports whether m's signature (sig) verifies under key for its wire signing digest.
func verifies(t *testing.T, name string, m proto.Message, sig []byte, key []byte) bool {
	t.Helper()
	m = proto.Clone(m)
	switch x := m.(type) {
	case *nexusv1.DispatchInputResponseV1:
		x.BuilderServiceSignature = nil
	case *nexusv1.RecordResultNoticeV1:
		x.BuilderServiceSignature = nil
	}
	raw, err := marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := dispatch.SigningDigest(name, raw)
	if err != nil {
		t.Fatal(err)
	}
	return dispatch.VerifyDigestSignature(key, digest[:], sig) == nil
}

// Input responses and record notices carry no key generation: a replay signs them again with the
// current key. Offers keep their signature: a ticket is bound to the generation that issued it.
func TestResignTransportSignsOnlyTransportMessages(t *testing.T) {
	old, current := newTestSigner(t, 0x31), newTestSigner(t, 0x32)
	input := &nexusv1.DispatchInputResponseV1{TaskId: bytes.Repeat([]byte{3}, 32), DispatchTicketHash: bytes.Repeat([]byte{1}, 32),
		InputHash: bytes.Repeat([]byte{4}, 32), InputSizeBytes: 4, Input: []byte("data"), ChunkCount: 1}
	if _, _, err := signInputResponse(old, input); err != nil {
		t.Fatal(err)
	}
	notice := &nexusv1.RecordResultNoticeV1{DispatchTicketHash: bytes.Repeat([]byte{2}, 32), RecordedHeight: 9}
	if _, _, err := SignRecordResultNotice(old, notice); err != nil {
		t.Fatal(err)
	}
	ticketSig := []byte("ticket signature")
	frames := []*nexusv1.DispatchStreamFrameV1{
		{Message: &nexusv1.DispatchStreamFrameV1_InputResponse{InputResponse: input}},
		{Message: &nexusv1.DispatchStreamFrameV1_RecordResult{RecordResult: notice}},
		{Message: &nexusv1.DispatchStreamFrameV1_Offer{Offer: &nexusv1.DispatchOfferV1{Ticket: &taskv1.DispatchTicketV1{BuilderServiceSignature: ticketSig}}}},
	}
	resign := ResignTransport(current)
	for _, f := range frames {
		if err := resign(f); err != nil {
			t.Fatal(err)
		}
	}
	if r := frames[0].GetInputResponse(); !verifies(t, inputResponseName, r, r.GetBuilderServiceSignature(), current.PubKeyCompressed()) {
		t.Fatal("input response not signed with the current key")
	}
	if n := frames[1].GetRecordResult(); !verifies(t, noticeName, n, n.GetBuilderServiceSignature(), current.PubKeyCompressed()) {
		t.Fatal("record notice not signed with the current key")
	}
	if !bytes.Equal(frames[2].GetOffer().GetTicket().GetBuilderServiceSignature(), ticketSig) {
		t.Fatal("an offer was signed again")
	}
}
