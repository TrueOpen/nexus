package nodecontract

import (
	"crypto/sha256"
	"encoding/binary"
	"strconv"
)

const (
	DomainOrderV1        = "TRUEOPEN_ORDER_V1"
	DomainInferReceiptV3 = "TRUEOPEN_INFER_RECEIPT_V3"
)

func OrderSigningBytes(chainID, ownerAddress, sessionID string, orderSequence uint64, orderEnvelope string) []byte {
	return domainHash(DomainOrderV1, chainID, ownerAddress, sessionID, strconv.FormatUint(orderSequence, 10), orderEnvelope)
}

// CurrentOrderSigningBytes mirrors the current task order contract.
// OrderSigningBytes remains for the deprecated SubmitOrder compatibility path.
func CurrentOrderSigningBytes(chainID, ownerAddress, sessionID string, orderSequence uint64, orderEnvelope string) []byte {
	return domainHash(DomainOrderV1, chainID, ownerAddress, sessionID, strconv.FormatUint(orderSequence, 10), orderEnvelope)
}

func domainHash(domain string, fields ...string) []byte {
	parts := make([]string, 0, len(fields)+1)
	parts = append(parts, domain)
	parts = append(parts, fields...)
	hasher := sha256.New()
	var length [8]byte
	for _, part := range parts {
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		_, _ = hasher.Write(length[:])
		_, _ = hasher.Write([]byte(part))
	}
	return hasher.Sum(nil)
}
