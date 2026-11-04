package builderreg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/coordinator"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
)

const (
	vrfTestChainID = "trueopen-hub-localnet"
	vrfTestBuilder = "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz"
)

func vrfTestKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

func vrfTestPub(seed byte) []byte { return []byte(vrfTestKey(seed).Public().(ed25519.PublicKey)) }

// fakeVRFHub is the Hub as a registration sees it: the VRF key row, and a block result for the
// broadcast transaction that applies the registration the way the chain does.
type fakeVRFHub struct {
	row      *chaincli.VrfKey
	queryErr error
	// result is the block result of the broadcast transaction; nil means none is ever found.
	result  *chaincli.TxResult
	queries int
	sent    []*hubv1.MsgRegisterVrfKey
	sendErr error
}

func (h *fakeVRFHub) QueryVrfKey(_ context.Context, participantType, operator string) (chaincli.VrfKey, error) {
	h.queries++
	if participantType != "BUILDER" || operator != vrfTestBuilder {
		return chaincli.VrfKey{}, errors.New("wrong domain or operator")
	}
	if h.queryErr != nil {
		return chaincli.VrfKey{}, h.queryErr
	}
	if h.row == nil {
		return chaincli.VrfKey{}, chaincli.ErrNotFound
	}
	return *h.row, nil
}

func (h *fakeVRFHub) SubmitRegisterVrfKey(_ context.Context, msg *hubv1.MsgRegisterVrfKey) (chaincli.TxResult, error) {
	h.sent = append(h.sent, msg)
	if h.sendErr != nil {
		return chaincli.TxResult{}, h.sendErr
	}
	return chaincli.TxResult{TxHash: []byte{0xab, 0xcd}}, nil
}

func (h *fakeVRFHub) QueryTx(_ context.Context, txHash []byte) (chaincli.TxResult, error) {
	if !bytes.Equal(txHash, []byte{0xab, 0xcd}) {
		return chaincli.TxResult{}, errors.New("unknown tx hash")
	}
	if h.result == nil {
		return chaincli.TxResult{}, chaincli.ErrNotFound
	}
	if h.result.Code == 0 {
		msg := h.sent[len(h.sent)-1]
		next := chaincli.VrfKey{AuthorizationNonce: msg.GetVrfAuthorizationNonce(), PendingPubKey: msg.GetVrfPubkey(), PendingFromEpoch: 8}
		if h.row != nil {
			next.ActivePubKey, next.ActiveFromEpoch = h.row.ActivePubKey, h.row.ActiveFromEpoch
		}
		h.row = &next
	}
	return *h.result, nil
}

var _ coordinator.VRFKeySubmitter = (*fakeVRFHub)(nil)

func registerTestVRFKey(hub *fakeVRFHub, key ed25519.PrivateKey) (VRFKeyOutcome, error) {
	return RegisterVRFKey(context.Background(), VRFKeyRegistration{
		ChainID: vrfTestChainID, Builder: vrfTestBuilder, Key: key,
		Chain: hub, Submit: hub, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		WaitInterval: time.Millisecond, WaitTimeout: 20 * time.Millisecond,
	})
}

// A Builder with no VRF key row registers with nonce 1 and a possession proof over the digest of
// that nonce; it returns once the transaction is in a block, with the chain's pending key.
func TestRegisterVRFKeyFirstRegistration(t *testing.T) {
	hub := &fakeVRFHub{result: &chaincli.TxResult{TxHash: []byte{0xab, 0xcd}, Height: 12}}
	key := vrfTestKey(1)
	out, err := registerTestVRFKey(hub, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(hub.sent) != 1 {
		t.Fatalf("sent %d messages, want 1", len(hub.sent))
	}
	msg := hub.sent[0]
	proof, err := dispatchdraw.ProveVRFKeyPossession(key, vrfTestChainID, vrfTestBuilder, 1)
	if err != nil {
		t.Fatal(err)
	}
	if msg.GetParticipantType() != sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER || msg.GetOperatorAddress() != vrfTestBuilder ||
		!bytes.Equal(msg.GetVrfPubkey(), vrfTestPub(1)) || msg.GetVrfAuthorizationNonce() != 1 || !bytes.Equal(msg.GetVrfKeyPop(), proof) {
		t.Fatalf("message = %v", msg)
	}
	if !out.Submitted || !bytes.Equal(out.TxHash, []byte{0xab, 0xcd}) || out.Status != VRFKeyPending ||
		out.State.PendingFromEpoch != 8 || out.State.AuthorizationNonce != 1 {
		t.Fatalf("outcome = %+v", out)
	}
}

// A rotation takes the next nonce after the chain's current one.
func TestRegisterVRFKeyRotationUsesTheNextNonce(t *testing.T) {
	hub := &fakeVRFHub{
		row:    &chaincli.VrfKey{ActivePubKey: vrfTestPub(9), ActiveFromEpoch: 3, AuthorizationNonce: 3},
		result: &chaincli.TxResult{TxHash: []byte{0xab, 0xcd}},
	}
	out, err := registerTestVRFKey(hub, vrfTestKey(1))
	if err != nil {
		t.Fatal(err)
	}
	if len(hub.sent) != 1 || hub.sent[0].GetVrfAuthorizationNonce() != 4 {
		t.Fatalf("sent = %v, want one message with nonce 4", hub.sent)
	}
	if out.Status != VRFKeyPending || !bytes.Equal(out.State.ActivePubKey, vrfTestPub(9)) {
		t.Fatalf("outcome = %+v", out)
	}
}

// A key the chain already holds, active or pending, is not registered again.
func TestRegisterVRFKeySendsNothingForARegisteredKey(t *testing.T) {
	for name, tc := range map[string]struct {
		row  chaincli.VrfKey
		want VRFKeyStatus
	}{
		"active":                      {chaincli.VrfKey{ActivePubKey: vrfTestPub(1), ActiveFromEpoch: 3, AuthorizationNonce: 1}, VRFKeyActive},
		"pending":                     {chaincli.VrfKey{ActivePubKey: vrfTestPub(9), ActiveFromEpoch: 3, PendingPubKey: vrfTestPub(1), PendingFromEpoch: 5, AuthorizationNonce: 2}, VRFKeyPending},
		"pending first key":           {chaincli.VrfKey{PendingPubKey: vrfTestPub(1), PendingFromEpoch: 5, AuthorizationNonce: 1}, VRFKeyPending},
		"active with another pending": {chaincli.VrfKey{ActivePubKey: vrfTestPub(1), ActiveFromEpoch: 3, PendingPubKey: vrfTestPub(9), PendingFromEpoch: 5, AuthorizationNonce: 2}, VRFKeyActive},
	} {
		t.Run(name, func(t *testing.T) {
			row := tc.row
			hub := &fakeVRFHub{row: &row}
			out, err := registerTestVRFKey(hub, vrfTestKey(1))
			if err != nil {
				t.Fatal(err)
			}
			if len(hub.sent) != 0 || out.Submitted || out.Status != tc.want || out.State.AuthorizationNonce != row.AuthorizationNonce {
				t.Fatalf("sent %d, outcome %+v", len(hub.sent), out)
			}
		})
	}
}

// The chain keeps one pending rotation at a time: with another key pending, registering would be
// refused, so nothing is sent and the operator is told to wait for the activation.
func TestRegisterVRFKeyRefusesWhileAnotherKeyIsPending(t *testing.T) {
	hub := &fakeVRFHub{row: &chaincli.VrfKey{ActivePubKey: vrfTestPub(8), ActiveFromEpoch: 3, PendingPubKey: vrfTestPub(9), PendingFromEpoch: 5, AuthorizationNonce: 2}}
	_, err := registerTestVRFKey(hub, vrfTestKey(1))
	if !errors.Is(err, ErrVRFKeyRotationPending) || !strings.Contains(err.Error(), "epoch 5") {
		t.Fatalf("err = %v", err)
	}
	if len(hub.sent) != 0 {
		t.Fatal("a registration was sent while another key is pending")
	}
}

func TestRegisterVRFKeyReportsFailures(t *testing.T) {
	cases := map[string]struct {
		hub  *fakeVRFHub
		want []string
		is   error
		sent int
	}{
		"rejected in the block": {
			hub:  &fakeVRFHub{result: &chaincli.TxResult{TxHash: []byte{0xab, 0xcd}, Code: 18, Codespace: "hub", RawLog: "vrf possession proof: does not verify"}},
			want: []string{"rejected", "hub code 18", "vrf possession proof: does not verify"},
			sent: 1,
		},
		"rejected at broadcast": {
			hub:  &fakeVRFHub{sendErr: errors.New("submit MsgRegisterVrfKey: rejected by CheckTx (code 13): insufficient fee")},
			want: []string{"insufficient fee"},
			sent: 1,
		},
		"never in a block": {
			hub:  &fakeVRFHub{},
			want: []string{"abcd", "register-vrf-key"},
			is:   chaincli.ErrTxUnknown,
			sent: 1,
		},
		"chain unreadable": {
			hub:  &fakeVRFHub{queryErr: errors.New("endpoint unavailable")},
			want: []string{"endpoint unavailable"},
		},
		"nonce exhausted": {
			hub:  &fakeVRFHub{row: &chaincli.VrfKey{ActivePubKey: vrfTestPub(9), ActiveFromEpoch: 3, AuthorizationNonce: ^uint64(0)}},
			want: []string{"nonce"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := registerTestVRFKey(tc.hub, vrfTestKey(1))
			if err == nil {
				t.Fatal("expected an error")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("err = %v, want it to mention %q", err, want)
				}
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("err = %v, want %v", err, tc.is)
			}
			if len(tc.hub.sent) != tc.sent {
				t.Fatalf("sent %d messages, want %d", len(tc.hub.sent), tc.sent)
			}
		})
	}
}
