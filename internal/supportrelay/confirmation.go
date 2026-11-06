package supportrelay

import (
	"fmt"
	"unicode/utf8"

	"github.com/cosmos/cosmos-sdk/types/bech32"
	"google.golang.org/protobuf/encoding/protowire"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	"github.com/TrueOpen/nexus/internal/nodecontract"
)

// Confirmation is one decoded hub.v1.ModelSupportConfirmationV1: a Cortex operator's signed
// list of the models it keeps supporting, valid for one epoch.
type Confirmation struct {
	// Operator is the canonical Bech32 operator address and OperatorRaw its 20 address bytes;
	// confirmations in a batch are ordered by OperatorRaw.
	Operator    string
	OperatorRaw []byte
	// Models are raw Hash32 model ids, strictly ascending and unique, as signed.
	Models       [][]byte
	Nonce        uint64
	ExpiryHeight uint64
	// Signature is the raw64 low-S signature of the operator's current service key.
	Signature []byte
}

// ModelSupportConfirmationV1 field numbers.
const (
	fieldOperatorAddress = 1
	fieldSupportedModels = 2
	fieldNonce           = 3
	fieldExpiryHeight    = 4
	fieldSignature       = 5
)

const (
	operatorAddressBytes = 20
	modelIDBytes         = 32
	signatureBytes       = 64
)

// Decode reads the protobuf bytes of one ModelSupportConfirmationV1 and checks its fields are
// canonical. It refuses rather than guesses: an empty payload, unknown fields, a repeated
// singular field and a wrong wire type are errors, as is an operator that is not lowercase
// Bech32 of prefix over 20 bytes, a model list that is empty or not strictly ascending raw Hash32
// ids, a zero nonce or expiry and a signature that is not 64 bytes. Field order and other
// equivalent encodings decode to the same Confirmation. Every error wraps ErrMalformed.
func Decode(raw []byte, prefix string) (Confirmation, error) {
	if len(raw) == 0 {
		return Confirmation{}, fmt.Errorf("%w: confirmation is empty", ErrMalformed)
	}
	var c Confirmation
	seen := map[protowire.Number]bool{}
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return Confirmation{}, fmt.Errorf("%w: confirmation tag: %v", ErrMalformed, protowire.ParseError(n))
		}
		raw = raw[n:]
		if num != fieldSupportedModels && seen[num] {
			return Confirmation{}, fmt.Errorf("%w: confirmation field %d appears more than once", ErrMalformed, num)
		}
		seen[num] = true
		switch num {
		case fieldOperatorAddress, fieldSupportedModels, fieldSignature:
			if typ != protowire.BytesType {
				return Confirmation{}, fmt.Errorf("%w: confirmation field %d has wire type %d, want bytes", ErrMalformed, num, typ)
			}
			value, n := protowire.ConsumeBytes(raw)
			if n < 0 {
				return Confirmation{}, fmt.Errorf("%w: confirmation field %d: %v", ErrMalformed, num, protowire.ParseError(n))
			}
			raw = raw[n:]
			switch num {
			case fieldOperatorAddress:
				if !utf8.Valid(value) {
					return Confirmation{}, fmt.Errorf("%w: operator_address is not UTF-8", ErrMalformed)
				}
				c.Operator = string(value)
			case fieldSupportedModels:
				c.Models = append(c.Models, append([]byte(nil), value...))
			default:
				c.Signature = append([]byte(nil), value...)
			}
		case fieldNonce, fieldExpiryHeight:
			if typ != protowire.VarintType {
				return Confirmation{}, fmt.Errorf("%w: confirmation field %d has wire type %d, want varint", ErrMalformed, num, typ)
			}
			value, n := protowire.ConsumeVarint(raw)
			if n < 0 {
				return Confirmation{}, fmt.Errorf("%w: confirmation field %d: %v", ErrMalformed, num, protowire.ParseError(n))
			}
			raw = raw[n:]
			if num == fieldNonce {
				c.Nonce = value
			} else {
				c.ExpiryHeight = value
			}
		default:
			return Confirmation{}, fmt.Errorf("%w: unknown confirmation field %d", ErrMalformed, num)
		}
	}
	if err := c.canonical(prefix); err != nil {
		return Confirmation{}, err
	}
	return c, nil
}

func (c *Confirmation) canonical(prefix string) error {
	hrp, operator, err := bech32.DecodeAndConvert(c.Operator)
	if err != nil {
		return fmt.Errorf("%w: operator_address is not Bech32: %v", ErrMalformed, err)
	}
	if hrp != prefix || len(operator) != operatorAddressBytes {
		return fmt.Errorf("%w: operator_address must be a %s address of %d bytes", ErrMalformed, prefix, operatorAddressBytes)
	}
	if canonical, err := bech32.ConvertAndEncode(hrp, operator); err != nil || canonical != c.Operator {
		return fmt.Errorf("%w: operator_address is not canonical lowercase Bech32", ErrMalformed)
	}
	c.OperatorRaw = operator
	if _, err := nodecontract.SupportedModelsHash(c.Models); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	switch {
	case c.Nonce == 0:
		return fmt.Errorf("%w: service_authorization_nonce is required", ErrMalformed)
	case c.ExpiryHeight == 0:
		return fmt.Errorf("%w: expiry_height is required", ErrMalformed)
	case len(c.Signature) != signatureBytes:
		return fmt.Errorf("%w: service_signature must be %d bytes, got %d", ErrMalformed, signatureBytes, len(c.Signature))
	}
	return nil
}

// Digest is the TRUEOPEN_DAILY_SUPPORT_CONFIRMATION_V1 digest the service key signed for epoch.
func (c Confirmation) Digest(chainID string, epoch uint64) ([32]byte, error) {
	return nodecontract.DailySupportConfirmationSigningDigest(chainID, c.OperatorRaw, epoch, c.Nonce, c.ExpiryHeight, c.Models)
}

// Proto is the confirmation as it goes into MsgBatchConfirmModelSupport, every field as signed.
func (c Confirmation) Proto() *hubv1.ModelSupportConfirmationV1 {
	return &hubv1.ModelSupportConfirmationV1{
		OperatorAddress: c.Operator, SupportedModels: c.Models,
		ServiceAuthorizationNonce: c.Nonce, ExpiryHeight: c.ExpiryHeight, ServiceSignature: c.Signature,
	}
}
