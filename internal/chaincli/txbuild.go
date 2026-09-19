// SIGN_MODE_DIRECT transaction assembly (using the Cosmos SDK's official protobuf types),
// i.e. path A of the Account and Signing Protocol §5.1:
// Flow: TxBody(msgs) + AuthInfo(pubkey/sequence/fee) → SignDoc(chain_id/account_number)
// → keccak256(SignDoc) → signer.SignDigest → raw64 R||S → TxRaw bytes → BroadcastTx.
//
// The digest is keccak256 rather than the SHA-256 Cosmos usually uses: on-chain accounts
// are eth_secp256k1 (§2.1), and node's ante verifies path A only with keccak256(SignDoc).
// A transaction signed over the wrong digest is rejected at CheckTx.
package chaincli

import (
	"fmt"

	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	basev1beta1 "cosmossdk.io/api/cosmos/base/v1beta1"
	signingv1beta1 "cosmossdk.io/api/cosmos/tx/signing/v1beta1"
	txv1beta1 "cosmossdk.io/api/cosmos/tx/v1beta1"

	ethsecp256k1 "github.com/TrueOpen/nexus/gen/cosmosevm/crypto/v1/ethsecp256k1"
)

// pubKeyTypeURL is the Any type_url of SignerInfo.public_key (Account and Signing
// Protocol §2.3, from the pinned cosmos/evm, mirrored in proto/cosmos/evm/crypto/v1/ethsecp256k1).
// The message shape is identical to cosmos.crypto.secp256k1.PubKey (single bytes key = 1),
// but a different type URL is a different type: writing /cosmos.crypto.secp256k1.PubKey
// makes the chain derive the address via ripemd160, which does not match the signer's
// keccak address, and node's ante rejects it outright.
const pubKeyTypeURL = "/cosmos.evm.crypto.v1.ethsecp256k1.PubKey"

// keccak256 is the SignDoc digest function for path A.
func keccak256(data []byte) [32]byte {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(data)
	var out [32]byte
	copy(out[:], hash.Sum(nil))
	return out
}

// Task / Builder Msg type URLs must match the current Node descriptors exactly.
// The Task names come from Keeper Interface Contract §9.4; V1 registers no MsgFailSettle,
// no Worker reveal Msg and no public Challenge Msg (§9.5/§10.14).
const (
	TypeURLMsgSubmitWorkerHandraises   = "/task.v1.MsgSubmitWorkerHandraises"
	TypeURLMsgSubmitInferReceipt       = "/task.v1.MsgSubmitInferReceipt"
	TypeURLMsgSubmitVerifierHandraises = "/task.v1.MsgSubmitVerifierHandraises"
	TypeURLMsgSubmitVerifyCommit       = "/task.v1.MsgSubmitVerifyCommit"
	TypeURLMsgBatchSubmitVerifyCommit  = "/task.v1.MsgBatchSubmitVerifyCommit"
	TypeURLMsgSubmitVerifyResult       = "/task.v1.MsgSubmitVerifyResult"
	TypeURLMsgBatchSubmitVerifyResult  = "/task.v1.MsgBatchSubmitVerifyResult"
	TypeURLMsgSettleTask               = "/task.v1.MsgSettleTask"
	TypeURLMsgSweepDeadline            = "/task.v1.MsgSweepDeadline"
	TypeURLMsgRegisterBuilder          = "/hub.v1.MsgRegisterBuilder"
	TypeURLMsgUpdateServiceDescriptor  = "/hub.v1.MsgUpdateServiceDescriptor"
)

// /task.v1.MsgReportDataUnavailable is deliberately not declared.
//
// msg_verification.proto states explicitly that this message has no relay path: the Cosmos
// Tx signer must be the current service address of a Verifier operator selected in this
// round, and no second detached signature is accepted. Nexus is a Builder and can never
// satisfy that signer condition; ProtocolEventCodeV1 also has no data-unavailable event
// code, so even inclusion confirmation is out of the question.
//
// Declaring a type URL that is never used would misread "forbidden by contract" as "relay
// point to be added", so this stays a comment rather than a constant. Only the Verifier
// can submit this message itself.

// TxSigner is the signing capability chaincli needs to assemble transactions (satisfied by internal/signer.Signer).
type TxSigner interface {
	PubKeyCompressed() []byte
	Address() string
	// SignDigest signs an already derived 32-byte digest directly and returns 64-byte r||s;
	// transactions use it to sign keccak256(SignDoc).
	SignDigest(digest [32]byte) ([]byte, error)
}

// TxParams holds the parameters for one transaction.
type TxParams struct {
	ChainID       string
	AccountNumber uint64
	Sequence      uint64
	GasLimit      uint64
	FeeDenom      string // empty = no fee (zero-fee devnet)
	FeeAmount     string
	Memo          string
}

// PackAny packs a proto message into an Any with the given type_url (matching the chain-side convention).
func PackAny(typeURL string, msg proto.Message) (*anypb.Any, error) {
	if msg == nil {
		return nil, fmt.Errorf("txbuild: nil message for %s", typeURL)
	}
	expectedTypeURL := "/" + string(msg.ProtoReflect().Descriptor().FullName())
	if typeURL != expectedTypeURL {
		return nil, fmt.Errorf("txbuild: type URL %q does not match message descriptor %q", typeURL, expectedTypeURL)
	}
	value, err := proto.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("txbuild: marshal %s: %w", typeURL, err)
	}
	return &anypb.Any{TypeUrl: typeURL, Value: value}, nil
}

// BuildSignedTx assembles and signs, returning TxRaw bytes ready for BroadcastTx.
func BuildSignedTx(s TxSigner, p TxParams, msgs ...*anypb.Any) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("txbuild: nil signer")
	}
	if len(msgs) == 0 {
		return nil, fmt.Errorf("txbuild: no messages")
	}

	bodyBytes, err := proto.Marshal(&txv1beta1.TxBody{Messages: msgs, Memo: p.Memo})
	if err != nil {
		return nil, fmt.Errorf("txbuild: marshal body: %w", err)
	}

	pubAny, err := PackAny(pubKeyTypeURL, &ethsecp256k1.PubKey{Key: s.PubKeyCompressed()})
	if err != nil {
		return nil, err
	}
	fee := &txv1beta1.Fee{GasLimit: p.GasLimit}
	if p.FeeDenom != "" {
		fee.Amount = []*basev1beta1.Coin{{Denom: p.FeeDenom, Amount: p.FeeAmount}}
	}
	authInfoBytes, err := proto.Marshal(&txv1beta1.AuthInfo{
		SignerInfos: []*txv1beta1.SignerInfo{{
			PublicKey: pubAny,
			ModeInfo: &txv1beta1.ModeInfo{
				Sum: &txv1beta1.ModeInfo_Single_{Single: &txv1beta1.ModeInfo_Single{Mode: signingv1beta1.SignMode_SIGN_MODE_DIRECT}},
			},
			Sequence: p.Sequence,
		}},
		Fee: fee,
	})
	if err != nil {
		return nil, fmt.Errorf("txbuild: marshal auth info: %w", err)
	}

	signDocBytes, err := proto.Marshal(&txv1beta1.SignDoc{
		BodyBytes:     bodyBytes,
		AuthInfoBytes: authInfoBytes,
		ChainId:       p.ChainID,
		AccountNumber: p.AccountNumber,
	})
	if err != nil {
		return nil, fmt.Errorf("txbuild: marshal sign doc: %w", err)
	}
	sig, err := s.SignDigest(keccak256(signDocBytes))
	if err != nil {
		return nil, fmt.Errorf("txbuild: sign: %w", err)
	}

	raw, err := proto.Marshal(&txv1beta1.TxRaw{
		BodyBytes:     bodyBytes,
		AuthInfoBytes: authInfoBytes,
		Signatures:    [][]byte{sig},
	})
	if err != nil {
		return nil, fmt.Errorf("txbuild: marshal tx raw: %w", err)
	}
	return raw, nil
}
