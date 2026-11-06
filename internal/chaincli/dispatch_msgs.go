package chaincli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	abciv1beta1 "cosmossdk.io/api/cosmos/base/abci/v1beta1"
	txv1beta1 "cosmossdk.io/api/cosmos/tx/v1beta1"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

// Phase 1 dispatch Msg type URLs. The Builder signs the three Task Msgs with its service account;
// MsgRegisterVrfKey is signed offline by the operator and only relayed.
const (
	TypeURLMsgRecordDispatch            = "/task.v1.MsgRecordDispatch"
	TypeURLMsgRebutDispatchCompensation = "/task.v1.MsgRebutDispatchCompensation"
	TypeURLMsgRespondDispatchChallenge  = "/task.v1.MsgRespondDispatchChallenge"
	TypeURLMsgRegisterVrfKey            = "/hub.v1.MsgRegisterVrfKey"
)

// BuildRecordDispatchTx signs a MsgRecordDispatch. Every entry is a complete dispatch entry
// (signed order, record, winner ticket, accept) or a takeover entry (signed order); the chain
// admits each entry on its own and reports per-entry results (DecodeRecordDispatchResponse).
// Batch size limits from task params are the caller's to apply.
func BuildRecordDispatchTx(s TxSigner, p TxParams, msg *taskv1.MsgRecordDispatch) ([]byte, error) {
	if err := checkDispatchMsgSigner(s, "submitter_address", msg.GetSubmitterAddress()); err != nil {
		return nil, fmt.Errorf("record dispatch: %w", err)
	}
	if len(msg.GetEntries()) == 0 {
		return nil, fmt.Errorf("record dispatch: no entries")
	}
	for i, entry := range msg.GetEntries() {
		switch e := entry.GetEntry().(type) {
		case *taskv1.DispatchRecordEntryV1_Dispatch:
			d := e.Dispatch
			if d == nil || d.GetSignedOrder() == nil || d.GetRecord() == nil || d.GetWinnerTicket() == nil || d.GetAccept() == nil {
				return nil, fmt.Errorf("record dispatch: entry %d needs signed_order, record, winner_ticket and accept", i)
			}
		case *taskv1.DispatchRecordEntryV1_Takeover:
			if e.Takeover == nil || e.Takeover.GetSignedOrder() == nil {
				return nil, fmt.Errorf("record dispatch: takeover entry %d needs signed_order", i)
			}
		default:
			return nil, fmt.Errorf("record dispatch: entry %d selects neither dispatch nor takeover", i)
		}
	}
	return buildDispatchTx(s, p, TypeURLMsgRecordDispatch, msg)
}

// BuildRebutDispatchCompensationTx signs a rebuttal of the compensation claimed on one ticket: the
// signed record shows the attempt's outcome, with the Worker's signed reject when it rejected.
func BuildRebutDispatchCompensationTx(s TxSigner, p TxParams, msg *taskv1.MsgRebutDispatchCompensation) ([]byte, error) {
	if err := checkDispatchMsgSigner(s, "responder_address", msg.GetResponderAddress()); err != nil {
		return nil, fmt.Errorf("rebut dispatch compensation: %w", err)
	}
	if err := checkHash32("dispatch_ticket_hash", msg.GetDispatchTicketHash()); err != nil {
		return nil, fmt.Errorf("rebut dispatch compensation: %w", err)
	}
	if msg.GetRecord() == nil {
		return nil, fmt.Errorf("rebut dispatch compensation: record is required")
	}
	return buildDispatchTx(s, p, TypeURLMsgRebutDispatchCompensation, msg)
}

// BuildRespondDispatchChallengeTx signs the Builder's bounded answer to one dispatch challenge: a
// Worker's signed reject or the complete roster.
func BuildRespondDispatchChallengeTx(s TxSigner, p TxParams, msg *taskv1.MsgRespondDispatchChallenge) ([]byte, error) {
	if err := checkDispatchMsgSigner(s, "responder_address", msg.GetResponderAddress()); err != nil {
		return nil, fmt.Errorf("respond dispatch challenge: %w", err)
	}
	if err := checkHash32("challenge_id", msg.GetChallengeId()); err != nil {
		return nil, fmt.Errorf("respond dispatch challenge: %w", err)
	}
	if msg.GetReject() == nil && msg.GetRoster() == nil {
		return nil, fmt.Errorf("respond dispatch challenge: response selects neither reject nor roster")
	}
	return buildDispatchTx(s, p, TypeURLMsgRespondDispatchChallenge, msg)
}

func checkDispatchMsgSigner(s TxSigner, field, address string) error {
	if s == nil {
		return fmt.Errorf("nil signer")
	}
	if address != s.Address() {
		return fmt.Errorf("%s must be the signing service address %q, got %q", field, s.Address(), address)
	}
	return nil
}

func buildDispatchTx(s TxSigner, p TxParams, typeURL string, msg proto.Message) ([]byte, error) {
	packed, err := PackAny(typeURL, msg)
	if err != nil {
		return nil, err
	}
	return BuildSignedTx(s, p, packed)
}

// DecodeMsgResponse unpacks the Msg response at msgIndex of an executed transaction into out. The
// result must come from QueryTx: a broadcast result only reports CheckTx and carries no responses.
func DecodeMsgResponse(result TxResult, msgIndex int, out proto.Message) error {
	if result.Code != 0 {
		return fmt.Errorf("msg response: transaction failed with %s code %d", result.Codespace, result.Code)
	}
	var data abciv1beta1.TxMsgData
	if err := proto.Unmarshal(result.Data, &data); err != nil {
		return fmt.Errorf("msg response: decode TxMsgData: %w", err)
	}
	if msgIndex < 0 || msgIndex >= len(data.GetMsgResponses()) {
		return fmt.Errorf("msg response: transaction has %d responses, no index %d", len(data.GetMsgResponses()), msgIndex)
	}
	response := data.GetMsgResponses()[msgIndex]
	if want := "/" + string(out.ProtoReflect().Descriptor().FullName()); response.GetTypeUrl() != want {
		return fmt.Errorf("msg response %d is %s, want %s", msgIndex, response.GetTypeUrl(), want)
	}
	if err := proto.Unmarshal(response.GetValue(), out); err != nil {
		return fmt.Errorf("msg response: decode %s: %w", response.GetTypeUrl(), err)
	}
	return nil
}

// ErrBatchDigestMismatch reports a MsgRecordDispatch response whose batch_digest is not the one
// computed from its results; none of its results is returned.
var ErrBatchDigestMismatch = errors.New("record dispatch: batch_digest does not match the results")

// DecodeRecordDispatchResponse reads the per-entry results of the MsgRecordDispatch at msgIndex
// of an executed transaction. objectIDs are the keys of the entries sent, in entry order
// (DispatchEntryObjectID, TakeoverEntryObjectID). There is one result per entry, in entry order,
// echoing that entry's key as object_id (also for a NOOP replay); a REJECTED entry carries its
// DispatchRejectCodeV1 and only a REJECTED entry does. batch_digest commits to every
// (object_id, status) in entry order; a response whose batch_digest does not match is refused
// with ErrBatchDigestMismatch.
func DecodeRecordDispatchResponse(result TxResult, msgIndex int, chainID string, objectIDs [][32]byte) (*taskv1.MsgRecordDispatchResponse, error) {
	response, mismatched, err := DecodeRecordDispatchResults(result, msgIndex, chainID, objectIDs)
	if len(mismatched) > 0 {
		return nil, fmt.Errorf("record dispatch: result %d object_id is not the key of entry %d", mismatched[0], mismatched[0])
	}
	return response, err
}

// DecodeRecordDispatchResults is DecodeRecordDispatchResponse that does not refuse results whose
// object_id is not the key of their entry: it lists their indexes, so the other entries keep
// their results. A takeover entry's key commits to the session's bound_change_height when it was
// sent, which the chain may have moved since.
func DecodeRecordDispatchResults(result TxResult, msgIndex int, chainID string, objectIDs [][32]byte) (*taskv1.MsgRecordDispatchResponse, []int, error) {
	response := &taskv1.MsgRecordDispatchResponse{}
	if err := DecodeMsgResponse(result, msgIndex, response); err != nil {
		return nil, nil, fmt.Errorf("record dispatch: %w", err)
	}
	if len(response.GetResults()) != len(objectIDs) {
		return nil, nil, fmt.Errorf("record dispatch: %d results for %d entries", len(response.GetResults()), len(objectIDs))
	}
	var mismatched []int
	for i, item := range response.GetResults() {
		if item.GetItemIndex() != uint32(i) {
			return nil, nil, fmt.Errorf("record dispatch: result %d has item_index %d", i, item.GetItemIndex())
		}
		rejected := item.GetStatus() == sharedv1.MutationStatusV1_MUTATION_STATUS_V1_REJECTED
		switch {
		case item.GetStatus() == sharedv1.MutationStatusV1_MUTATION_STATUS_V1_UNSPECIFIED:
			return nil, nil, fmt.Errorf("record dispatch: result %d has no status", i)
		case rejected != (item.GetRejectCode() != taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_UNSPECIFIED):
			return nil, nil, fmt.Errorf("record dispatch: result %d status %s with reject_code %s", i, item.GetStatus(), item.GetRejectCode())
		}
		if !bytes.Equal(item.GetObjectId(), objectIDs[i][:]) {
			mismatched = append(mismatched, i)
		}
	}
	if digest := RecordDispatchBatchDigest(chainID, response.GetResults()); !bytes.Equal(response.GetBatchDigest(), digest[:]) {
		return nil, nil, ErrBatchDigestMismatch
	}
	return response, mismatched, nil
}

// TxBroadcaster sends signed transaction bytes to the chain.
type TxBroadcaster interface {
	BroadcastTx(ctx context.Context, tx []byte) (TxResult, error)
}

// CheckRegisterVrfKeyTx decodes a transaction the operator signed offline and returns its
// MsgRegisterVrfKey. Nexus never holds the operator key: it only relays these exact bytes, so it
// checks that they register a Builder VRF key for builder and nothing else.
func CheckRegisterVrfKeyTx(raw []byte, builder string) (*hubv1.MsgRegisterVrfKey, error) {
	var tx txv1beta1.TxRaw
	if err := proto.Unmarshal(raw, &tx); err != nil {
		return nil, fmt.Errorf("register vrf key tx: decode: %w", err)
	}
	if len(tx.GetSignatures()) == 0 || len(tx.GetAuthInfoBytes()) == 0 {
		return nil, fmt.Errorf("register vrf key tx: transaction is not signed")
	}
	var body txv1beta1.TxBody
	if err := proto.Unmarshal(tx.GetBodyBytes(), &body); err != nil {
		return nil, fmt.Errorf("register vrf key tx: decode body: %w", err)
	}
	if len(body.GetMessages()) != 1 || body.GetMessages()[0].GetTypeUrl() != TypeURLMsgRegisterVrfKey {
		return nil, fmt.Errorf("register vrf key tx: must carry exactly one %s", TypeURLMsgRegisterVrfKey)
	}
	msg := &hubv1.MsgRegisterVrfKey{}
	if err := proto.Unmarshal(body.GetMessages()[0].GetValue(), msg); err != nil {
		return nil, fmt.Errorf("register vrf key tx: decode message: %w", err)
	}
	switch {
	case msg.GetParticipantType() != sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER:
		return nil, fmt.Errorf("register vrf key tx: participant_type is %s, want BUILDER", msg.GetParticipantType())
	case msg.GetOperatorAddress() != builder:
		return nil, fmt.Errorf("register vrf key tx: operator_address %q is not this Builder %q", msg.GetOperatorAddress(), builder)
	case len(msg.GetVrfPubkey()) != ed25519.PublicKeySize:
		return nil, fmt.Errorf("register vrf key tx: vrf_pubkey is %d bytes, want %d", len(msg.GetVrfPubkey()), ed25519.PublicKeySize)
	case len(msg.GetVrfKeyPop()) == 0:
		return nil, fmt.Errorf("register vrf key tx: vrf_key_pop is empty")
	}
	return msg, nil
}

// BroadcastRegisterVrfKeyTx checks an operator-signed VRF key registration with
// CheckRegisterVrfKeyTx and broadcasts the bytes unchanged.
func BroadcastRegisterVrfKeyTx(ctx context.Context, b TxBroadcaster, raw []byte, builder string) (TxResult, error) {
	if _, err := CheckRegisterVrfKeyTx(raw, builder); err != nil {
		return TxResult{}, err
	}
	return b.BroadcastTx(ctx, raw)
}
