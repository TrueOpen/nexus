package dispatcher

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

const dispatchVectors = "task/dispatch_v1.json"

type signedVector struct {
	ProtobufHex  string `json:"protobuf_hex"`
	PublicKeyHex string `json:"public_key_hex"`
	SignatureHex string `json:"signature_hex"`
}

// loadVector decodes a signed wire vector into m and returns its bytes and signature.
func loadVector(t *testing.T, name string, m proto.Message) (wirefixture.Vector, []byte, []byte) {
	t.Helper()
	v := wirefixture.Load(t, dispatchVectors).Vector(t, name, 0)
	v.CheckPreimage(t)
	var sv signedVector
	if err := json.Unmarshal(v.Raw, &sv); err != nil {
		t.Fatal(err)
	}
	raw, _ := hex.DecodeString(sv.ProtobufHex)
	sig, _ := hex.DecodeString(sv.SignatureHex)
	pub, _ := hex.DecodeString(sv.PublicKeyHex)
	if !bytes.Equal(newTestSigner(t, 0x01).PubKeyCompressed(), pub) {
		t.Fatal("fixture key is not the vector key")
	}
	if err := proto.Unmarshal(raw, m); err != nil {
		t.Fatal(err)
	}
	return v, raw, sig
}

func checkSigned(t *testing.T, v wirefixture.Vector, wantRaw, wantSig, gotRaw []byte, gotDigest [32]byte, gotSig []byte) {
	t.Helper()
	if gotDigest != v.Digest(t) {
		t.Fatalf("digest = %x, want %s", gotDigest, v.DigestHex)
	}
	if !bytes.Equal(gotSig, wantSig) {
		t.Fatalf("signature = %x, want %x", gotSig, wantSig)
	}
	if !bytes.Equal(gotRaw, wantRaw) {
		t.Fatalf("bytes = %x, want %x", gotRaw, wantRaw)
	}
}

// The ticket built from an order's state for a candidate is the wire DispatchTicketV1 vector: its
// fields, bytes, dispatch_ticket_hash and signature.
func TestTicketVector(t *testing.T) {
	var want taskv1.DispatchTicketV1
	v, wantRaw, wantSig := loadVector(t, "task_v1_dispatchticketv1", &want)
	if want.GetServiceAuthorizationNonce() == 0 {
		t.Fatal("the ticket vector signs no Builder nonce")
	}
	d := &Dispatcher{cfg: Config{ChainID: want.GetChainId(), Builder: want.GetBuilderAddress(),
		Signer: servicekey.Static(newTestSigner(t, 0x01), want.GetServiceAuthorizationNonce())}}
	o := &order{
		st: &orderState{
			Sequence: want.GetOrderSequence(), TaskID: hex.EncodeToString(want.GetTaskId()), TaskHash: hex.EncodeToString(want.GetTaskHash()),
			Epoch: &epochState{
				Number: want.GetVrfEpoch(), ReferenceHeight: want.GetReferenceHeight(), SnapshotID: want.GetCandidatePoolSnapshotId(),
				VRFOutput: want.GetVrfOutput(), VRFProof: want.GetVrfProof(),
			},
			BoundChangeHeight: want.GetBoundChangeHeight(),
		},
		signed:      &taskv1.SignedOrderV2{Order: &taskv1.TaskOrderV3{SessionId: want.GetSessionId(), InputHash: want.GetInputHash()}},
		roster:      &dispatchdraw.Roster{RootDigest: [32]byte(want.GetHandraiseRootDigest()), Hash: [32]byte(want.GetRosterHash())},
		rosterRound: want.GetDispatchRound(),
	}
	target := want.GetTarget()
	cand := dispatchdraw.Candidate{
		Rank:                 want.GetRank(),
		Member:               dispatch.RosterMember{Slot: target.GetSlot(), SlotVersion: target.GetSlotVersion(), OperatorAddress: target.GetOperatorAddress()},
		StickyAnchorSequence: want.GetStickyAnchorSequence(), StickyRunCount: want.GetStickyRunCount(),
	}
	ticket := d.ticket(o, cand, want.GetAcceptDeadlineMs())
	raw, digest, err := signTicket(d.cfg.Signer.Key(), ticket)
	if err != nil {
		t.Fatal(err)
	}
	checkSigned(t, v, wantRaw, wantSig, raw, digest, ticket.GetBuilderServiceSignature())
}

// The record built from an order's rounds and winner ticket is the wire DispatchRecordV1 vector.
// The vector's one attempt carries placeholder values in every field (an ACCEPTED attempt with a
// reject digest and a timeout tier), which the builder would zero; they are set back before
// signing, so the test pins every other field.
func TestRecordVector(t *testing.T) {
	var want taskv1.DispatchRecordV1
	v, wantRaw, wantSig := loadVector(t, "task_v1_dispatchrecordv1", &want)
	var ticket taskv1.DispatchTicketV1
	tv, ticketRaw, _ := loadVector(t, "task_v1_dispatchticketv1", &ticket)
	ticketHash := tv.Digest(t)
	wantRound := want.GetRounds()[0]
	wantAttempt := wantRound.GetAttempts()[0]
	if !bytes.Equal(wantAttempt.GetDispatchTicketHash(), ticketHash[:]) || !bytes.Equal(wantRound.GetRosterHash(), ticket.GetRosterHash()) {
		t.Fatal("the record vector does not name the ticket vector")
	}
	st := &orderState{
		Sequence: want.GetOrderSequence(), TaskID: hex.EncodeToString(want.GetTaskId()), TaskHash: hex.EncodeToString(want.GetTaskHash()),
		StickyApplied: want.GetStickyApplied(),
		Rounds: []roundState{{Number: wantRound.GetDispatchRound(), RootDigest: wantRound.GetHandraiseRootDigest(), Attempts: []attemptState{{
			Ticket: ticketRaw, Hash: ticketHash[:], Rank: wantAttempt.GetRank(), Outcome: wantAttempt.GetOutcome(),
		}}}},
	}
	record, err := buildRecord(want.GetChainId(), want.GetBuilderAddress(), st, &ticket, ticketHash[:])
	if err != nil {
		t.Fatal(err)
	}
	got := record.GetRounds()[0].GetAttempts()[0]
	if !bytes.Equal(got.GetRejectDigestOrZero32(), make([]byte, 32)) || got.GetTimeoutTierOrZero() != 0 {
		t.Fatalf("an ACCEPTED attempt carries reject digest %x tier %d", got.GetRejectDigestOrZero32(), got.GetTimeoutTierOrZero())
	}
	got.RejectDigestOrZero32, got.TimeoutTierOrZero = wantAttempt.GetRejectDigestOrZero32(), wantAttempt.GetTimeoutTierOrZero()
	if want.GetServiceAuthorizationNonce() == 0 {
		t.Fatal("the record vector signs no Builder nonce")
	}
	raw, digest, err := signRecord(servicekey.Key{Signer: newTestSigner(t, 0x01), Nonce: want.GetServiceAuthorizationNonce()}, record)
	if err != nil {
		t.Fatal(err)
	}
	checkSigned(t, v, wantRaw, wantSig, raw, digest, record.GetBuilderServiceSignature())
}

// An input is served as wire's input chunk vectors: zero-based chunks with a positive count, each
// naming the whole input's size and hash, here three chunks of "abcdef" with their bytes and
// signatures.
func TestInputResponseVectors(t *testing.T) {
	var assembly struct {
		Assembly struct {
			Count   uint32   `json:"chunk_count"`
			Input   string   `json:"input_utf8"`
			Vectors []string `json:"vector_names"`
		} `json:"input_chunk_assembly"`
	}
	if err := json.Unmarshal(wirefixture.ReadFile(t, "testdata/v1/"+dispatchVectors), &assembly); err != nil {
		t.Fatal(err)
	}
	a := assembly.Assembly
	if a.Input != "abcdef" || a.Count != 3 || len(a.Vectors) != 3 {
		t.Fatalf("input chunk assembly = %+v", a)
	}
	var first nexusv1.DispatchInputResponseV1
	loadVector(t, a.Vectors[0], &first)
	nonce := first.GetServiceAuthorizationNonce()
	if nonce == 0 {
		t.Fatal("the input response vector signs no Builder nonce")
	}
	streams := &fakeStreams{}
	d := &Dispatcher{cfg: Config{
		Signer: servicekey.Static(newTestSigner(t, 0x01), nonce), InputChunkBytes: 2, Streams: streams,
		Inputs: fakeInputs{data: map[string][]byte{"task-hash": []byte(a.Input)}},
	}}
	if err := d.sendInput(context.Background(), "worker", "session", "task", "task-hash", first.GetTaskId(), first.GetDispatchTicketHash(), first.GetInputHash(), nonce); err != nil {
		t.Fatal(err)
	}
	if len(streams.sent) != 3 {
		t.Fatalf("sent %d chunks", len(streams.sent))
	}
	for i, name := range a.Vectors {
		var want nexusv1.DispatchInputResponseV1
		v, wantRaw, wantSig := loadVector(t, name, &want)
		if want.GetChunkIndex() != uint32(i) {
			t.Fatalf("vector %s has chunk_index %d", name, want.GetChunkIndex())
		}
		got := streams.sent[i].frame.GetInputResponse()
		raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := dispatch.SigningDigest(inputResponseName, raw)
		if err != nil {
			t.Fatal(err)
		}
		checkSigned(t, v, wantRaw, wantSig, raw, digest, got.GetBuilderServiceSignature())
	}
}

// The accept digest the stream hands over is the wire dispatch_accept_digest an input request must
// name.
func TestAcceptDigestVector(t *testing.T) {
	var accept taskv1.DispatchAcceptV1
	v, raw, _ := loadVector(t, "task_v1_dispatchacceptv1", &accept)
	digest, err := dispatch.SigningDigest(acceptName, raw)
	if err != nil || digest != v.Digest(t) {
		t.Fatalf("accept digest = %x, %v; want %s", digest, err, v.DigestHex)
	}
}

func TestRecordResultNoticeVector(t *testing.T) {
	var want nexusv1.RecordResultNoticeV1
	v, wantRaw, wantSig := loadVector(t, "nexus_v1_recordresultnoticev1", &want)
	if want.GetServiceAuthorizationNonce() == 0 {
		t.Fatal("the record notice vector signs no Builder nonce")
	}
	n := &nexusv1.RecordResultNoticeV1{
		DispatchTicketHash: want.GetDispatchTicketHash(), Status: want.GetStatus(), RejectCode: want.GetRejectCode(),
		RecordedHeight: want.GetRecordedHeight(),
	}
	key := servicekey.Key{Signer: newTestSigner(t, 0x01), Nonce: want.GetServiceAuthorizationNonce()}
	raw, digest, err := SignRecordResultNotice(key, want.GetServiceAuthorizationNonce(), n)
	if err != nil {
		t.Fatal(err)
	}
	checkSigned(t, v, wantRaw, wantSig, raw, digest, n.GetBuilderServiceSignature())
}

// Input responses and record notices are signed under the nonce of the key that signs them, never
// one older than their ticket's: such a message could never verify.
func TestTicketBoundMessagesRefuseAnOlderGenerationThanTheTicket(t *testing.T) {
	sg := newTestSigner(t, 0x01)
	for _, nonce := range []uint64{0, 4} {
		key := servicekey.Key{Signer: sg, Nonce: nonce}
		if _, _, err := signInputResponse(key, 5, &nexusv1.DispatchInputResponseV1{}); err == nil {
			t.Fatalf("input response signed under nonce %d for a ticket of nonce 5", nonce)
		}
		if _, _, err := SignRecordResultNotice(key, 5, &nexusv1.RecordResultNoticeV1{}); err == nil {
			t.Fatalf("record notice signed under nonce %d for a ticket of nonce 5", nonce)
		}
	}
	key := servicekey.Key{Signer: sg, Nonce: 6}
	input := &nexusv1.DispatchInputResponseV1{TaskId: bytes.Repeat([]byte{3}, 32), DispatchTicketHash: bytes.Repeat([]byte{1}, 32), InputHash: bytes.Repeat([]byte{4}, 32), InputSizeBytes: 4,
		Input: []byte("data"), ChunkCount: 1}
	notice := &nexusv1.RecordResultNoticeV1{DispatchTicketHash: bytes.Repeat([]byte{2}, 32), RecordedHeight: 9}
	if _, _, err := signInputResponse(key, 5, input); err != nil || input.GetServiceAuthorizationNonce() != 6 {
		t.Fatalf("input response under a newer key: nonce %d, %v", input.GetServiceAuthorizationNonce(), err)
	}
	if _, _, err := SignRecordResultNotice(key, 5, notice); err != nil || notice.GetServiceAuthorizationNonce() != 6 {
		t.Fatalf("record notice under a newer key: nonce %d, %v", notice.GetServiceAuthorizationNonce(), err)
	}
}

// An input response and a record notice signed before a cutover are retained and resent as
// signed: they name the retired key's nonce and still prove their ticket's order below its
// retirement height, but not one at it.
func TestTicketBoundMessagesStillVerifyAfterACutover(t *testing.T) {
	var ticket taskv1.DispatchTicketV1
	_, ticketRaw, _ := loadVector(t, "task_v1_dispatchticketv1", &ticket)
	ticketHash, err := dispatch.SigningDigest(ticketName, ticketRaw)
	if err != nil {
		t.Fatal(err)
	}
	oldKey, newKey := newTestSigner(t, 0x01), newTestSigner(t, 0x02)
	signed := servicekey.Key{Signer: oldKey, Nonce: ticket.GetServiceAuthorizationNonce()}
	input := &nexusv1.DispatchInputResponseV1{TaskId: ticket.GetTaskId(), DispatchTicketHash: ticketHash[:], InputHash: ticket.GetInputHash(),
		InputSizeBytes: 4, Input: []byte("data"), ChunkCount: 1}
	inputRaw, _, err := signInputResponse(signed, ticket.GetServiceAuthorizationNonce(), input)
	if err != nil {
		t.Fatal(err)
	}
	notice := &nexusv1.RecordResultNoticeV1{DispatchTicketHash: ticketHash[:], Status: taskv1.DispatchRecordStatusV1_DISPATCH_RECORD_STATUS_V1_RECORDED, RecordedHeight: 9}
	noticeRaw, _, err := SignRecordResultNotice(signed, ticket.GetServiceAuthorizationNonce(), notice)
	if err != nil {
		t.Fatal(err)
	}
	const retired = 120
	lookup := func(s dispatch.ServiceProofSigner) (dispatch.ProofKeyBinding, error) {
		switch {
		case s.ServiceAuthorizationNonce == signed.Nonce:
			return dispatch.ProofKeyBinding{PublicKey: oldKey.PubKeyCompressed(), ServiceAuthorizationNonce: signed.Nonce, Status: dispatch.ProofKeyPrevious, PreviousRetiredHeight: retired}, nil
		case s.ServiceAuthorizationNonce == signed.Nonce+1:
			return dispatch.ProofKeyBinding{PublicKey: newKey.PubKeyCompressed(), ServiceAuthorizationNonce: signed.Nonce + 1, Status: dispatch.ProofKeyActive}, nil
		}
		return dispatch.ProofKeyBinding{}, errors.New("unknown generation")
	}
	for _, m := range []struct {
		name string
		raw  []byte
	}{{inputResponseName, inputRaw}, {noticeName, noticeRaw}} {
		below, at := uint64(retired-1), uint64(retired)
		if err := dispatch.VerifyTicketBoundDispatchProof(ticket.GetChainId(), m.name, m.raw, ticketRaw, dispatch.ProofKeyOptions{LookupProofKey: lookup, OrderEarliestSubmitHeight: &below}); err != nil {
			t.Fatalf("%s signed before the cutover, order below the retirement: %v", m.name, err)
		}
		if err := dispatch.VerifyTicketBoundDispatchProof(ticket.GetChainId(), m.name, m.raw, ticketRaw, dispatch.ProofKeyOptions{LookupProofKey: lookup, OrderEarliestSubmitHeight: &at}); err == nil {
			t.Fatalf("%s signed before the cutover proved an order at the retirement", m.name)
		}
	}
}
