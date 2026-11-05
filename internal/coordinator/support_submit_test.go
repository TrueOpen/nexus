package coordinator

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"google.golang.org/protobuf/proto"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/signer"
)

func supportMsg(submitter string) *hubv1.MsgBatchConfirmModelSupport {
	return &hubv1.MsgBatchConfirmModelSupport{EpochIndex: 9, SubmitterAddress: submitter,
		Confirmations: []*hubv1.ModelSupportConfirmationV1{{
			OperatorAddress: "trueopen15x328f9956n632d24wk2mt40kzcm9va5vw5e0a", SupportedModels: [][]byte{make([]byte, 32)},
			ServiceAuthorizationNonce: 2, ExpiryHeight: 950, ServiceSignature: make([]byte, 64),
		}}}
}

func newSupportSubmitter(t *testing.T, chain chaincli.Client, keyHex string, shared Submitter) (SupportSubmitter, signer.Signer) {
	t.Helper()
	sg, err := signer.NewFromHex(keyHex, "trueopen")
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewSupportSubmitter(log, chain, sg, config.ChainConfig{ChainID: "trueopen-localnet", GasLimit: 200000}, shared), sg
}

// The batch is signed by the Builder account with the given gas limit; on the chain that carries
// the task transactions it shares their account sequence.
func TestSupportSubmitterSignsWithTheBuilderAccountSequence(t *testing.T) {
	chain := &seqChain{accSeq: 42}
	tasks, address := newSeqSubmitter(t, chain)
	sub, sg := newSupportSubmitter(t, chain, testKeyHex, tasks)
	if _, err := tasks.SubmitSettle(context.Background(), sequenceSettle(address, "t")); err != nil {
		t.Fatal(err)
	}
	res, err := sub.SubmitBatchConfirmModelSupport(context.Background(), supportMsg(sg.Address()), 700_000)
	if err != nil || res.Code != 0 {
		t.Fatalf("submit = %+v, %v", res, err)
	}
	if chain.accQueries != 1 || chain.broadcasts[1] != 43 {
		t.Fatalf("queries %d, sequences %v", chain.accQueries, chain.broadcasts)
	}
	body, auth := decodeBuilderTx(t, chain.raws[1])
	if body.Messages[0].TypeUrl != chaincli.TypeURLMsgBatchConfirmModelSupport || auth.Fee.GasLimit != 700_000 {
		t.Fatalf("tx = %s with gas %d", body.Messages[0].TypeUrl, auth.Fee.GasLimit)
	}
	var msg hubv1.MsgBatchConfirmModelSupport
	if err := proto.Unmarshal(body.Messages[0].Value, &msg); err != nil || !proto.Equal(&msg, supportMsg(sg.Address())) {
		t.Fatalf("message = %v, %v", &msg, err)
	}

	other := &seqChain{accSeq: 5}
	separate, _ := newSupportSubmitter(t, other, testKeyHex, tasks)
	if _, err := separate.SubmitBatchConfirmModelSupport(context.Background(), supportMsg(sg.Address()), 0); err != nil {
		t.Fatal(err)
	}
	if other.accQueries != 1 || other.broadcasts[0] != 5 {
		t.Fatalf("another chain did not read its own sequence: queries %d, sequences %v", other.accQueries, other.broadcasts)
	}
}

func TestSupportSubmitterRefusesAnotherSubmitter(t *testing.T) {
	chain := &seqChain{accSeq: 1}
	sub, _ := newSupportSubmitter(t, chain, testKeyHex, nil)
	if _, err := sub.SubmitBatchConfirmModelSupport(context.Background(), supportMsg("trueopen1other"), 0); err == nil {
		t.Fatal("a batch naming another submitter was signed")
	}
	if len(chain.broadcasts) != 0 {
		t.Fatalf("broadcast %v", chain.broadcasts)
	}
}
