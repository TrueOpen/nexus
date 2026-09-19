package chaincli

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	txv1beta1 "cosmossdk.io/api/cosmos/tx/v1beta1"
	ethsecp256k1 "github.com/TrueOpen/nexus/gen/cosmosevm/crypto/v1/ethsecp256k1"
	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/signer"
)

const testKeyHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

func TestBuildSignedTxRoundTrip(t *testing.T) {
	s, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	msgAny, err := PackAny(TypeURLMsgSettleTask, &taskv1.MsgSettleTask{
		TaskId: make([]byte, 32), SubmitterAddress: s.Address(),
	})
	if err != nil {
		t.Fatalf("pack any: %v", err)
	}

	p := TxParams{ChainID: "trueopen-localnet", AccountNumber: 7, Sequence: 42,
		GasLimit: 200000, FeeDenom: "utrueopen", FeeAmount: "5000"}
	raw, err := BuildSignedTx(s, p, msgAny)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	// Decode TxRaw back: body / auth_info / signature structure is complete.
	var txRaw txv1beta1.TxRaw
	if err := proto.Unmarshal(raw, &txRaw); err != nil {
		t.Fatalf("unmarshal TxRaw: %v", err)
	}
	if len(txRaw.Signatures) != 1 || len(txRaw.Signatures[0]) != 64 {
		t.Fatalf("signatures: %d × %d bytes", len(txRaw.Signatures), len(txRaw.Signatures[0]))
	}

	var body txv1beta1.TxBody
	if err := proto.Unmarshal(txRaw.BodyBytes, &body); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if len(body.Messages) != 1 || body.Messages[0].TypeUrl != TypeURLMsgSettleTask {
		t.Fatalf("body messages: %+v", body.Messages)
	}
	var msg taskv1.MsgSettleTask
	if err := proto.Unmarshal(body.Messages[0].Value, &msg); err != nil {
		t.Fatalf("unmarshal MsgSettleTask: %v", err)
	}
	if len(msg.GetTaskId()) != 32 || msg.GetSubmitterAddress() != s.Address() {
		t.Fatalf("msg fields: %+v", &msg)
	}

	var auth txv1beta1.AuthInfo
	if err := proto.Unmarshal(txRaw.AuthInfoBytes, &auth); err != nil {
		t.Fatalf("unmarshal auth info: %v", err)
	}
	si := auth.SignerInfos[0]
	if si.Sequence != 42 {
		t.Fatalf("sequence = %d", si.Sequence)
	}
	// Account and Signing Protocol §2.3: SignerInfo.public_key must be the eth_secp256k1 type URL;
	// the message shape is identical to cosmos.crypto.secp256k1.PubKey, but a different type URL is a
	// different type, and node's ante (requireEthSecp256k1PublicKey) rejects /cosmos.crypto.secp256k1.PubKey.
	if si.PublicKey.TypeUrl != "/cosmos.evm.crypto.v1.ethsecp256k1.PubKey" {
		t.Fatalf("pubkey type_url = %s", si.PublicKey.TypeUrl)
	}
	var pk ethsecp256k1.PubKey
	if err := proto.Unmarshal(si.PublicKey.Value, &pk); err != nil {
		t.Fatalf("unmarshal pubkey: %v", err)
	}
	if string(pk.Key) != string(s.PubKeyCompressed()) {
		t.Fatal("pubkey mismatch")
	}
	if auth.Fee.GasLimit != 200000 || auth.Fee.Amount[0].Denom != "utrueopen" {
		t.Fatalf("fee: %+v", auth.Fee)
	}

	// Rebuild the SignDoc: the signature covers keccak256(SignDoc) of §5.1 path A, not SHA-256.
	// Signing the keccak digest directly with the signer must match byte for byte
	// (deterministic → the signature covers the right content), while the SHA-256 path
	// signature must *not* be equal; otherwise node's ante would fail keccak verification.
	signDoc, _ := proto.Marshal(&txv1beta1.SignDoc{
		BodyBytes: txRaw.BodyBytes, AuthInfoBytes: txRaw.AuthInfoBytes,
		ChainId: p.ChainID, AccountNumber: p.AccountNumber,
	})
	re, err := s.SignDigest(keccak256(signDoc))
	if err != nil {
		t.Fatalf("re-sign: %v", err)
	}
	if string(re) != string(txRaw.Signatures[0]) {
		t.Fatal("signature does not match keccak256(SignDoc)")
	}
	sha, err := s.Sign(signDoc)
	if err != nil {
		t.Fatalf("sha256 sign: %v", err)
	}
	if string(sha) == string(txRaw.Signatures[0]) {
		t.Fatal("signature still covers sha256(SignDoc); node verifies keccak256(SignDoc)")
	}
	if !func() bool {
		d := keccak256(signDoc)
		return signer.VerifyDigestSig(s.PubKeyCompressed(), d[:], txRaw.Signatures[0])
	}() {
		t.Fatal("signature does not verify against keccak256(SignDoc)")
	}
}

func TestBuildSignedTxRejectsEmpty(t *testing.T) {
	s, _ := signer.NewFromHex(testKeyHex, "trueopen")
	if _, err := BuildSignedTx(s, TxParams{ChainID: "x"}); err == nil {
		t.Fatal("want error for no messages")
	}
	dummy, err := PackAny(TypeURLMsgSettleTask, &taskv1.MsgSettleTask{})
	if err != nil {
		t.Fatalf("pack dummy message: %v", err)
	}
	if _, err := BuildSignedTx(nil, TxParams{ChainID: "x"}, dummy); err == nil {
		t.Fatal("want error for nil signer")
	}
}

func TestPackAnyRejectsTypeURLThatDoesNotMatchMessageDescriptor(t *testing.T) {
	_, err := PackAny("/hub.v1.MsgRegisterBuilder", &taskv1.MsgSettleTask{})
	if err == nil {
		t.Fatal("want error for mismatched type URL")
	}
}

func TestNodeMessageDescriptorsMatchNodeAPI(t *testing.T) {
	tests := []struct {
		typeURL string
		msg     proto.Message
	}{
		// wire v0.4.1: the Builder bond Msgs (MsgBondBuilder / MsgBeginBuilderUnbonding)
		// were removed; Phase 0 BuilderBond is fixed at zero.
		{"/hub.v1.MsgRegisterBuilder", &hubv1.MsgRegisterBuilder{}},
		{"/hub.v1.MsgUpdateServiceDescriptor", &hubv1.MsgUpdateServiceDescriptor{}},
		// Keeper Interface Contract §9.4 Task Msg surface.
		{"/task.v1.MsgSubmitWorkerHandraises", &taskv1.MsgSubmitWorkerHandraises{}},
		{"/task.v1.MsgSubmitInferReceipt", &taskv1.MsgSubmitInferReceipt{}},
		{"/task.v1.MsgSubmitVerifierHandraises", &taskv1.MsgSubmitVerifierHandraises{}},
		{"/task.v1.MsgReportDataUnavailable", &taskv1.MsgReportDataUnavailable{}},
		{"/task.v1.MsgSubmitVerifyCommit", &taskv1.MsgSubmitVerifyCommit{}},
		{"/task.v1.MsgBatchSubmitVerifyCommit", &taskv1.MsgBatchSubmitVerifyCommit{}},
		{"/task.v1.MsgSubmitVerifyResult", &taskv1.MsgSubmitVerifyResult{}},
		{"/task.v1.MsgBatchSubmitVerifyResult", &taskv1.MsgBatchSubmitVerifyResult{}},
		{"/task.v1.MsgSettleTask", &taskv1.MsgSettleTask{}},
		{"/task.v1.MsgSweepDeadline", &taskv1.MsgSweepDeadline{}},
	}
	for _, tt := range tests {
		t.Run(tt.typeURL, func(t *testing.T) {
			if _, err := PackAny(tt.typeURL, tt.msg); err != nil {
				t.Fatalf("PackAny: %v", err)
			}
		})
	}

	// The frozen contract reshaped MsgRegisterBuilder: the signer is builder_operator_address(4),
	// the descriptor payload is ServiceDescriptorV1(3), and there is no authorization_nonce.
	register := (&hubv1.MsgRegisterBuilder{}).ProtoReflect().Descriptor().Fields()
	if field := register.ByNumber(4); field.Name() != "builder_operator_address" || field.Kind() != protoreflect.StringKind {
		t.Fatalf("register field 4 = %s/%s", field.Name(), field.Kind())
	}
	if field := register.ByNumber(3); field.Name() != "descriptor" || field.Kind() != protoreflect.MessageKind {
		t.Fatalf("register field 3 = %s/%s", field.Name(), field.Kind())
	}
}
