package nodecontract

import (
	"bytes"
	"crypto/sha256"
	"fmt"
)

const (
	// DomainDailySupportConfirmationV1 is the domain a Cortex service key signs a model support
	// confirmation under.
	DomainDailySupportConfirmationV1 = "TRUEOPEN_DAILY_SUPPORT_CONFIRMATION_V1"
	// DomainSupportModelsV1 is the domain of DailySupportState.supported_models_hash.
	DomainSupportModelsV1 = "TRUEOPEN_SUPPORT_MODELS_V1"
)

// operatorAddressBytes is the length of a decoded operator address.
const operatorAddressBytes = 20

// DailySupportConfirmationPreimage is the H_FIELDS_V1 preimage of
// DailySupportConfirmationSigningDigest.
func DailySupportConfirmationPreimage(chainID string, operator []byte, epoch, nonce, expiryHeight uint64, models [][]byte) ([]byte, error) {
	fields, err := dailySupportConfirmationFields(chainID, operator, epoch, nonce, expiryHeight, models)
	if err != nil {
		return nil, err
	}
	return CanonicalFramePreimage(DomainDailySupportConfirmationV1, fields...), nil
}

// DailySupportConfirmationSigningDigest is the digest a Cortex current service key signs for one
// hub.v1.ModelSupportConfirmationV1:
//
//	H_FIELDS_V1("TRUEOPEN_DAILY_SUPPORT_CONFIRMATION_V1",
//	  chain_id, operator_address (raw 20 bytes), epoch_index, service_authorization_nonce,
//	  expiry_height, u32 model_count, frame(u32 model_count, model_id...))
//
// The signature, the relayer and the protobuf encoding are not part of it. models must be raw
// Hash32 ids, strictly ascending and unique.
func DailySupportConfirmationSigningDigest(chainID string, operator []byte, epoch, nonce, expiryHeight uint64, models [][]byte) ([32]byte, error) {
	preimage, err := DailySupportConfirmationPreimage(chainID, operator, epoch, nonce, expiryHeight, models)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(preimage), nil
}

// SupportedModelsHash is DailySupportState.supported_models_hash:
// H_FIELDS_V1("TRUEOPEN_SUPPORT_MODELS_V1", u32 model_count, frame(u32 model_count, model_id...)).
func SupportedModelsHash(models [][]byte) ([32]byte, error) {
	frame, err := supportedModelsFrame(models)
	if err != nil {
		return [32]byte{}, err
	}
	return CanonicalHashBytes(DomainSupportModelsV1, Uint32BE(uint32(len(models))), frame), nil
}

func dailySupportConfirmationFields(chainID string, operator []byte, epoch, nonce, expiryHeight uint64, models [][]byte) ([][]byte, error) {
	chain, err := CanonicalUTF8Field("chain_id", chainID)
	if err != nil {
		return nil, err
	}
	if len(operator) != operatorAddressBytes {
		return nil, fmt.Errorf("operator_address must be %d address bytes, got %d", operatorAddressBytes, len(operator))
	}
	frame, err := supportedModelsFrame(models)
	if err != nil {
		return nil, err
	}
	return [][]byte{
		chain, operator, Uint64BE(epoch), Uint64BE(nonce), Uint64BE(expiryHeight),
		Uint32BE(uint32(len(models))), frame,
	}, nil
}

// supportedModelsFrame is the repeated model id field: one nested frame holding the element count
// and then each raw id.
func supportedModelsFrame(models [][]byte) ([]byte, error) {
	if len(models) == 0 {
		return nil, fmt.Errorf("supported_models must not be empty")
	}
	elements := make([][]byte, 0, len(models)+1)
	elements = append(elements, Uint32BE(uint32(len(models))))
	for i, model := range models {
		if len(model) != sha256.Size {
			return nil, fmt.Errorf("supported_models[%d] must be %d raw bytes, got %d", i, sha256.Size, len(model))
		}
		if i > 0 && bytes.Compare(models[i-1], model) >= 0 {
			return nil, fmt.Errorf("supported_models must be strictly ascending and unique")
		}
		elements = append(elements, model)
	}
	return CanonicalFrameBytes(elements...), nil
}
