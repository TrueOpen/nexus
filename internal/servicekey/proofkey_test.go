package servicekey

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

const proofChainID = "trueopen-proof-1"

// rotationVectors is the part of wire's service-key rotation vectors the Builder consumes.
type rotationVectors struct {
	Schedules []struct {
		Name             string `json:"name"`
		RegisteredHeight uint64 `json:"registered_height"`
		EffectiveHeight  uint64 `json:"effective_height"`
	} `json:"schedules"`
	ProofCases []struct {
		Name                  string `json:"name"`
		EarliestSubmitHeight  uint64 `json:"earliest_submit_height"`
		BoundChangeHeight     uint64 `json:"bound_change_height"`
		PreviousRetiredHeight uint64 `json:"previous_retired_height"`
		Allowed               bool   `json:"allowed"`
	} `json:"proof_cases"`
	RootProofCases []struct {
		Name                 string  `json:"name"`
		RootHeight           uint64  `json:"root_height"`
		EarliestSubmitHeight *uint64 `json:"earliest_submit_height"`
		CutoffHeight         uint64  `json:"cutoff_height"`
		Allowed              bool    `json:"allowed"`
	} `json:"root_proof_cases"`
	RecordProofContextCases []struct {
		Name                    string  `json:"name"`
		EarliestSubmitHeight    uint64  `json:"earliest_submit_height"`
		BoundChangeHeight       *uint64 `json:"bound_change_height"`
		RecordBoundChangeHeight uint64  `json:"record_bound_change_height"`
		CutoffHeight            uint64  `json:"cutoff_height"`
		Allowed                 bool    `json:"allowed"`
	} `json:"record_proof_context_cases"`
}

func readRotationVectors(t *testing.T) rotationVectors {
	t.Helper()
	var vectors rotationVectors
	if err := json.Unmarshal(wirefixture.ReadFile(t, "testdata/v1/shared/service_key_rotation_v1.json"), &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

// previousBinding is a resolver whose operator's current key (nonce 5) replaced previous (nonce 4)
// at retired.
func previousBinding(t *testing.T, participantType, operator string, previous, current signer.Signer, retired uint64) *fakeResolver {
	t.Helper()
	state := activeState(participantType, operator, current)
	state.AuthorizationNonce = 5
	state.Previous = &chaincli.PreviousServiceKey{ServicePubKey: hex.EncodeToString(previous.PubKeyCompressed()), AuthorizationNonce: 4, RetiredHeight: retired}
	return &fakeResolver{states: map[string]chaincli.ServiceKeyState{participantType + "|" + operator: state}}
}

// signedAccept is a DispatchAcceptV1 of operator signed by key under nonce.
func signedAccept(t *testing.T, operator string, key signer.Signer, nonce uint64) []byte {
	t.Helper()
	accept := &taskv1.DispatchAcceptV1{
		SchemaVersion: 1, ChainId: proofChainID, TaskId: bytes.Repeat([]byte{1}, 32), TaskHash: bytes.Repeat([]byte{2}, 32),
		DispatchTicketHash:        bytes.Repeat([]byte{3}, 32),
		Member:                    &taskv1.CandidateMemberRefV1{CandidatePoolSnapshotId: bytes.Repeat([]byte{4}, 32), Slot: 1, SlotVersion: 1, OperatorAddress: operator},
		ServiceAuthorizationNonce: nonce,
	}
	unsigned, err := proto.MarshalOptions{Deterministic: true}.Marshal(accept)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := dispatch.SigningDigest("task.v1.DispatchAcceptV1", unsigned)
	if err != nil {
		t.Fatal(err)
	}
	if accept.ServiceSignature, err = key.SignDigest(digest); err != nil {
		t.Fatal(err)
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(accept)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Wire's cutover vectors: a key registered in the last block of an epoch is retired at the second
// epoch start after it; material it signed proves a ticket only when the larger of the order's
// earliest_submit_height and the ticket's bound_change_height is below that height, while the
// current key proves any order.
func TestProofKeysFollowTheCutoverVectors(t *testing.T) {
	vectors := readRotationVectors(t)
	var retired uint64
	for _, s := range vectors.Schedules {
		if s.Name == "last_block" {
			if s.RegisteredHeight != 109 || s.EffectiveHeight != 120 {
				t.Fatalf("last_block schedule = %+v", s)
			}
			retired = s.EffectiveHeight
		}
	}
	operator := testSigner(t, 9).Address()
	previous, current := testSigner(t, 1), testSigner(t, 2)
	resolver := previousBinding(t, ParticipantCortex, operator, previous, current, retired)
	oldAccept, newAccept := signedAccept(t, operator, previous, 4), signedAccept(t, operator, current, 5)
	if len(vectors.ProofCases) == 0 {
		t.Fatal("no proof cases")
	}
	for _, c := range vectors.ProofCases {
		if c.PreviousRetiredHeight != retired {
			t.Fatalf("%s: previous_retired_height %d, want %d", c.Name, c.PreviousRetiredHeight, retired)
		}
		esh, bound := c.EarliestSubmitHeight, c.BoundChangeHeight
		err := dispatch.VerifyDispatchProof(proofChainID, "task.v1.DispatchAcceptV1", oldAccept, ProofOptions(context.Background(), resolver, testPrefix, &esh, &bound))
		if (err == nil) != c.Allowed {
			t.Fatalf("%s: previous-key accept at esh %d, binding %d = %v, allowed %v", c.Name, esh, bound, err, c.Allowed)
		}
		if err := dispatch.VerifyDispatchProof(proofChainID, "task.v1.DispatchAcceptV1", newAccept, ProofOptions(context.Background(), resolver, testPrefix, &esh, &bound)); err != nil {
			t.Fatalf("%s: current-key accept at esh %d = %v", c.Name, esh, err)
		}
	}
	// Without the order's height, or without its ticket's binding height, only the current key
	// proves an accept.
	esh, bound := uint64(100), uint64(100)
	for _, opts := range []dispatch.ProofKeyOptions{
		ProofOptions(context.Background(), resolver, testPrefix, nil, &bound),
		ProofOptions(context.Background(), resolver, testPrefix, &esh, nil),
	} {
		if err := dispatch.VerifyDispatchProof(proofChainID, "task.v1.DispatchAcceptV1", oldAccept, opts); err == nil {
			t.Fatal("a previous-key accept proved without its full order context")
		}
	}
}

// Wire's root proof cases: a handraise root signed by a previous key proves only below the
// retirement by its own root_height, whatever order it is checked for.
func TestProofKeysFollowTheRootVectors(t *testing.T) {
	vectors := readRotationVectors(t)
	if len(vectors.RootProofCases) == 0 {
		t.Fatal("no root proof cases")
	}
	operator := testSigner(t, 9).Address()
	previous, current := testSigner(t, 1), testSigner(t, 2)
	for _, c := range vectors.RootProofCases {
		resolver := previousBinding(t, ParticipantBuilder, operator, previous, current, c.CutoffHeight)
		root := &taskv1.SignedHandraiseRootV1{ChainId: proofChainID, BuilderAddress: operator, RootHeight: c.RootHeight, RootVersion: 1,
			LeafCount: 1, Root: bytes.Repeat([]byte{7}, 32), ServiceAuthorizationNonce: 4}
		raw := signRetained(t, previous, "task.v1.SignedHandraiseRootV1", root, func(s []byte) { root.BuilderServiceSignature = s })
		err := dispatch.VerifyDispatchProof(proofChainID, "task.v1.SignedHandraiseRootV1", raw, ProofOptions(context.Background(), resolver, testPrefix, c.EarliestSubmitHeight, nil))
		if (err == nil) != c.Allowed {
			t.Fatalf("%s: previous-key root at height %d = %v, allowed %v", c.Name, c.RootHeight, err, c.Allowed)
		}
	}
}

// Wire's record proof context cases: a previous-key record is checked against the frozen ticket
// (or claim) binding height passed by the caller, never its own signed bound_change_height, and
// a missing frozen binding height refuses it.
func TestProofKeysFollowTheRecordContextVectors(t *testing.T) {
	vectors := readRotationVectors(t)
	if len(vectors.RecordProofContextCases) == 0 {
		t.Fatal("no record proof context cases")
	}
	var base taskv1.DispatchRecordV1
	vectorMessage(t, "task_v1_dispatchrecordv1", &base)
	operator := testSigner(t, 9).Address()
	previous, current := testSigner(t, 1), testSigner(t, 2)
	for _, c := range vectors.RecordProofContextCases {
		resolver := previousBinding(t, ParticipantBuilder, operator, previous, current, c.CutoffHeight)
		record := proto.Clone(&base).(*taskv1.DispatchRecordV1)
		record.BuilderAddress, record.BoundChangeHeight, record.ServiceAuthorizationNonce = operator, c.RecordBoundChangeHeight, 4
		raw := signRetained(t, previous, "task.v1.DispatchRecordV1", record, func(s []byte) { record.BuilderServiceSignature = s })
		esh := c.EarliestSubmitHeight
		err := dispatch.VerifyDispatchProof(record.GetChainId(), "task.v1.DispatchRecordV1", raw, ProofOptions(context.Background(), resolver, testPrefix, &esh, c.BoundChangeHeight))
		if (err == nil) != c.Allowed {
			t.Fatalf("%s: previous-key record = %v, allowed %v", c.Name, err, c.Allowed)
		}
	}
}

func TestProofKeysResolveGenerations(t *testing.T) {
	operator := testSigner(t, 9).Address()
	previous, current := testSigner(t, 1), testSigner(t, 2)
	state := activeState(ParticipantBuilder, operator, current)
	state.AuthorizationNonce = 5
	state.Previous = &chaincli.PreviousServiceKey{ServicePubKey: hex.EncodeToString(previous.PubKeyCompressed()), AuthorizationNonce: 4, RetiredHeight: 120}
	resolver := &fakeResolver{states: map[string]chaincli.ServiceKeyState{ParticipantBuilder + "|" + operator: state}}
	lookup := ProofKeys(context.Background(), resolver, testPrefix)
	at := func(nonce uint64) (dispatch.ProofKeyBinding, error) {
		return lookup(dispatch.ServiceProofSigner{ParticipantType: dispatch.ProofParticipantBuilder, OperatorAddress: operator, ServiceAuthorizationNonce: nonce})
	}
	for _, nonce := range []uint64{0, 5} {
		key, err := at(nonce)
		if err != nil || key.Status != dispatch.ProofKeyActive || key.ServiceAuthorizationNonce != 5 || !bytes.Equal(key.PublicKey, current.PubKeyCompressed()) {
			t.Fatalf("nonce %d = %+v, %v", nonce, key, err)
		}
	}
	if key, err := at(4); err != nil || key.Status != dispatch.ProofKeyPrevious || key.PreviousRetiredHeight != 120 || !bytes.Equal(key.PublicKey, previous.PubKeyCompressed()) {
		t.Fatalf("previous = %+v, %v", key, err)
	}
	if _, err := at(3); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unknown generation = %v, want ErrUnavailable", err)
	}
	// The current key must derive the binding's service address.
	forged := state
	forged.ServiceAddress = previous.Address()
	resolver.states[ParticipantBuilder+"|"+operator] = forged
	if _, err := at(5); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("current key of another service address = %v, want ErrUnavailable", err)
	}
	resolver.states[ParticipantBuilder+"|"+operator] = state
	other := ProofKeys(context.Background(), resolver, "other")
	if _, err := other(dispatch.ServiceProofSigner{ParticipantType: dispatch.ProofParticipantBuilder, OperatorAddress: operator, ServiceAuthorizationNonce: 5}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("service address under another prefix = %v, want ErrUnavailable", err)
	}
	state.Status = StatusRevoked
	resolver.states[ParticipantBuilder+"|"+operator] = state
	if key, err := at(5); err != nil || key.Status != dispatch.ProofKeyRevoked {
		t.Fatalf("revoked current = %+v, %v", key, err)
	}
	resolver.err = errors.New("node offline")
	if _, err := at(5); !errors.Is(err, ErrAuthority) {
		t.Fatalf("outage = %v, want ErrAuthority", err)
	}
	// A binding the chain answers malformed stays so: it is unavailable, not an outage to retry.
	resolver.err = fmt.Errorf("query current service key: %w", chaincli.ErrMalformedBinding)
	if _, err := at(5); !errors.Is(err, ErrUnavailable) || !errors.Is(err, chaincli.ErrMalformedBinding) {
		t.Fatalf("malformed binding = %v, want ErrUnavailable", err)
	}
	if _, _, err := Current(context.Background(), resolver, testPrefix, ParticipantBuilder, operator); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Current of a malformed binding = %v, want ErrUnavailable", err)
	}
}

// retainedCase is one of wire's retained_message_cases: a retained Builder message signed under
// signed_nonce for a ticket of ticket_nonce, against a binding whose current generation is
// current_nonce (current_status) and whose previous one is previous_nonce, retired at
// previous_retired_height, its ticket committing bound_change_height; earliest_submit_height is the
// order's (absent: not known), revoked_height the current key's explicit emergency-revoke cutoff.
type retainedCase struct {
	Name                  string  `json:"name"`
	SignedNonce           uint64  `json:"signed_nonce"`
	TicketNonce           uint64  `json:"ticket_nonce"`
	CurrentNonce          uint64  `json:"current_nonce"`
	CurrentStatus         string  `json:"current_status"`
	PreviousNonce         uint64  `json:"previous_nonce"`
	EarliestSubmitHeight  *uint64 `json:"earliest_submit_height"`
	BoundChangeHeight     uint64  `json:"bound_change_height"`
	PreviousRetiredHeight uint64  `json:"previous_retired_height"`
	RevokedHeight         uint64  `json:"revoked_height"`
	Allowed               bool    `json:"allowed"`
}

// vectorMessage decodes the protobuf bytes of wire's dispatch vector name into m.
func vectorMessage(t *testing.T, name string, m proto.Message) {
	t.Helper()
	v := wirefixture.Load(t, "task/dispatch_v1.json").Vector(t, name, 0)
	var sv struct {
		ProtobufHex string `json:"protobuf_hex"`
	}
	if err := json.Unmarshal(v.Raw, &sv); err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(sv.ProtobufHex)
	if err != nil {
		t.Fatal(err)
	}
	if err := proto.Unmarshal(raw, m); err != nil {
		t.Fatal(err)
	}
}

// signRetained signs m under name with key and returns its signed bytes; sign sets the signature.
func signRetained(t *testing.T, key signer.Signer, name string, m proto.Message, sign func([]byte)) []byte {
	t.Helper()
	sign(nil)
	unsigned, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := dispatch.SigningDigest(name, unsigned)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := key.SignDigest(digest)
	if err != nil {
		t.Fatal(err)
	}
	sign(sig)
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Wire's retained message cases: a result header, input response, revoke or record notice keeps
// the nonce it was signed under across a cutover and verifies under the current key, or the
// previous one (an explicitly revoked current key) only when the larger of the order's height and
// its ticket's binding height is below the retirement (the revoke), never under a generation older
// than its ticket's, an unknown one, nonce 0, or a bounded key without the order's height. The Builder
// verifies the synced result header (VerifyDispatchProof) and the ticket-bound messages
// (VerifyTicketBoundDispatchProof) through ProofOptions.
func TestProofKeysFollowTheRetainedMessageVectors(t *testing.T) {
	var vectors struct {
		Cases []retainedCase `json:"retained_message_cases"`
	}
	if err := json.Unmarshal(wirefixture.ReadFile(t, "testdata/v1/shared/service_key_rotation_v1.json"), &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Cases) == 0 {
		t.Fatal("no retained message cases")
	}
	var header nexusv1.DispatchResultHeaderV1
	vectorMessage(t, "nexus_v1_dispatchresultheaderv1", &header)
	chainID := header.GetWinnerTicket().GetChainId()
	operator := testSigner(t, 9).Address()
	previous, current, unknown := testSigner(t, 1), testSigner(t, 2), testSigner(t, 3)
	for _, c := range vectors.Cases {
		t.Run(c.Name, func(t *testing.T) {
			state := activeState(ParticipantBuilder, operator, current)
			state.AuthorizationNonce = c.CurrentNonce
			state.Status = c.CurrentStatus
			state.RevokedHeight = c.RevokedHeight
			state.Previous = &chaincli.PreviousServiceKey{ServicePubKey: hex.EncodeToString(previous.PubKeyCompressed()),
				AuthorizationNonce: c.PreviousNonce, RetiredHeight: c.PreviousRetiredHeight}
			resolver := &fakeResolver{states: map[string]chaincli.ServiceKeyState{ParticipantBuilder + "|" + operator: state}}
			key := unknown
			switch c.SignedNonce {
			case c.CurrentNonce, 0:
				key = current
			case c.PreviousNonce:
				key = previous
			}
			ticket := proto.Clone(header.GetWinnerTicket()).(*taskv1.DispatchTicketV1)
			ticket.BuilderAddress, ticket.ServiceAuthorizationNonce, ticket.BoundChangeHeight = operator, c.TicketNonce, c.BoundChangeHeight
			ticketRaw := signRetained(t, previous, "task.v1.DispatchTicketV1", ticket, func(s []byte) { ticket.BuilderServiceSignature = s })
			ticketHash, err := dispatch.SigningDigest("task.v1.DispatchTicketV1", ticketRaw)
			if err != nil {
				t.Fatal(err)
			}
			// Both verifiers take the binding height from the actual ticket.
			opts := ProofOptions(context.Background(), resolver, testPrefix, c.EarliestSubmitHeight, nil)

			h := proto.Clone(&header).(*nexusv1.DispatchResultHeaderV1)
			h.WinnerTicket, h.ServiceAuthorizationNonce = ticket, c.SignedNonce
			headerRaw := signRetained(t, key, "nexus.v1.DispatchResultHeaderV1", h, func(s []byte) { h.BuilderServiceSignature = s })
			if err := dispatch.VerifyDispatchProof(chainID, "nexus.v1.DispatchResultHeaderV1", headerRaw, opts); (err == nil) != c.Allowed {
				t.Fatalf("result header = %v, allowed %v", err, c.Allowed)
			}
			notice := &nexusv1.RecordResultNoticeV1{DispatchTicketHash: ticketHash[:], RecordedHeight: 9, ServiceAuthorizationNonce: c.SignedNonce}
			noticeRaw := signRetained(t, key, "nexus.v1.RecordResultNoticeV1", notice, func(s []byte) { notice.BuilderServiceSignature = s })
			if err := dispatch.VerifyTicketBoundDispatchProof(chainID, "nexus.v1.RecordResultNoticeV1", noticeRaw, ticketRaw, opts); (err == nil) != c.Allowed {
				t.Fatalf("record notice = %v, allowed %v", err, c.Allowed)
			}
		})
	}
}
