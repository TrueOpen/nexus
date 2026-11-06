package coordinator

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"testing"

	"google.golang.org/protobuf/proto"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/signer"
)

func testVRFKeyMsg(operator string) *hubv1.MsgRegisterVrfKey {
	return &hubv1.MsgRegisterVrfKey{
		ParticipantType:       sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER,
		OperatorAddress:       operator,
		VrfPubkey:             bytes.Repeat([]byte{0x11}, 32),
		VrfAuthorizationNonce: 2,
		VrfKeyPop:             bytes.Repeat([]byte{0x22}, 80),
	}
}

// MsgRegisterVrfKey is signed by the Builder operator account itself, at the account's sequence,
// and is what the offline relay check accepts as a Builder VRF key registration.
func TestVRFKeySubmitterBuildsRegisterVrfKeyTx(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sg, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatal(err)
	}
	chain := &captureChain{acc: chaincli.AccountInfo{AccountNumber: 7, Sequence: 42}}
	sub := NewVRFKeySubmitter(log, chain, sg, config.ChainConfig{
		ChainID: "trueopen-hub", GasLimit: 200000, FeeDenom: "utrueopen", FeeAmount: "5000",
	})
	want := testVRFKeyMsg(sg.Address())
	if _, err := sub.SubmitRegisterVrfKey(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	if len(chain.broadcast) != 1 {
		t.Fatalf("broadcasts = %d, want 1", len(chain.broadcast))
	}
	got, err := chaincli.CheckRegisterVrfKeyTx(chain.broadcast[0], sg.Address())
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(got, want) {
		t.Fatalf("message = %v, want %v", got, want)
	}
	_, auth := decodeBuilderTx(t, chain.broadcast[0])
	if seq := auth.SignerInfos[0].Sequence; seq != 42 {
		t.Fatalf("sequence = %d, want 42", seq)
	}
}

func TestVRFKeySubmitterRefusesAMessageItCannotSign(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sg, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*hubv1.MsgRegisterVrfKey){
		"another operator": func(m *hubv1.MsgRegisterVrfKey) {
			m.OperatorAddress = "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz"
		},
		"validator domain": func(m *hubv1.MsgRegisterVrfKey) {
			m.ParticipantType = sharedv1.ParticipantType_PARTICIPANT_TYPE_VALIDATOR
		},
		"short pubkey":  func(m *hubv1.MsgRegisterVrfKey) { m.VrfPubkey = m.VrfPubkey[:31] },
		"zero nonce":    func(m *hubv1.MsgRegisterVrfKey) { m.VrfAuthorizationNonce = 0 },
		"missing proof": func(m *hubv1.MsgRegisterVrfKey) { m.VrfKeyPop = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			chain := &captureChain{}
			sub := NewVRFKeySubmitter(log, chain, sg, config.ChainConfig{ChainID: "trueopen-hub"})
			msg := testVRFKeyMsg(sg.Address())
			mutate(msg)
			if _, err := sub.SubmitRegisterVrfKey(context.Background(), msg); err == nil {
				t.Fatal("expected an error")
			}
			if len(chain.broadcast) != 0 || chain.accountCalls != 0 {
				t.Fatalf("broadcasts = %d, account reads = %d; want none", len(chain.broadcast), chain.accountCalls)
			}
		})
	}
	unsigned := NewVRFKeySubmitter(log, &captureChain{}, nil, config.ChainConfig{ChainID: "trueopen-hub"})
	if _, err := unsigned.SubmitRegisterVrfKey(context.Background(), testVRFKeyMsg(sg.Address())); err == nil {
		t.Fatal("submitted without a signer")
	}
}
