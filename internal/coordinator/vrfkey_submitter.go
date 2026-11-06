package coordinator

import (
	"context"
	"crypto/ed25519"
	"log/slog"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
)

// VRFKeySubmitter sends the Builder's MsgRegisterVrfKey, signed by the Builder operator account.
type VRFKeySubmitter interface {
	SubmitRegisterVrfKey(ctx context.Context, msg *hubv1.MsgRegisterVrfKey) (chaincli.TxResult, error)
}

// NewVRFKeySubmitter constructs the Builder VRF key registration submitter on the authority chain.
func NewVRFKeySubmitter(log *slog.Logger, chain chaincli.Client, s chaincli.TxSigner, chainCfg config.ChainConfig) VRFKeySubmitter {
	return &defaultSubmitter{log: log, chain: chain, hub: chain, signer: s, chainCfg: chainCfg}
}

// SubmitRegisterVrfKey submits a Builder VRF key registration. The signer must be the operator the
// message registers for: the chain takes operator_address as the message signer.
func (s *defaultSubmitter) SubmitRegisterVrfKey(ctx context.Context, msg *hubv1.MsgRegisterVrfKey) (chaincli.TxResult, error) {
	switch {
	case msg == nil:
		return chaincli.TxResult{}, prepareSubmissionError("MsgRegisterVrfKey: message is nil")
	case s.signer == nil:
		return chaincli.TxResult{}, prepareSubmissionError("submit MsgRegisterVrfKey: account signer is required")
	case msg.GetParticipantType() != sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER:
		return chaincli.TxResult{}, prepareSubmissionError("MsgRegisterVrfKey: participant_type is %s, want BUILDER", msg.GetParticipantType())
	case msg.GetOperatorAddress() != s.signer.Address():
		return chaincli.TxResult{}, prepareSubmissionError("MsgRegisterVrfKey: operator_address %q is not the signing account %q",
			msg.GetOperatorAddress(), s.signer.Address())
	case len(msg.GetVrfPubkey()) != ed25519.PublicKeySize:
		return chaincli.TxResult{}, prepareSubmissionError("MsgRegisterVrfKey: vrf_pubkey is %d bytes, want %d", len(msg.GetVrfPubkey()), ed25519.PublicKeySize)
	case msg.GetVrfAuthorizationNonce() == 0:
		return chaincli.TxResult{}, prepareSubmissionError("MsgRegisterVrfKey: vrf_authorization_nonce must be greater than zero")
	case len(msg.GetVrfKeyPop()) == 0:
		return chaincli.TxResult{}, prepareSubmissionError("MsgRegisterVrfKey: vrf_key_pop is empty")
	}
	return s.submitMsg(ctx, "MsgRegisterVrfKey", chaincli.TypeURLMsgRegisterVrfKey, msg)
}
