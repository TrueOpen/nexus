package nodecontract

import (
	"encoding/hex"
	"testing"
)

// TrueOpen/wire testdata/v1/task/token_ids_v1.json, compared byte-for-byte.
func TestGoldenTokenIDsHash(t *testing.T) {
	for _, c := range []struct {
		domain, raw, want string
	}{
		{DomainInputTokenIDsV1, "000000020000000100000100", "5ab982d47fc3c3b0a07e401f1c040c7fe2ef79ae93d0e44c50afe7d07a3ae901"},
		{DomainGeneratedTokenIDsV1, "0000000300000002000001010000ffff", "057a76f605b3ba2fa26a92e379b5f0f802d97e379d4efc3a34e287f8e9e05efd"},
	} {
		raw, _ := hex.DecodeString(c.raw)
		digest, err := TokenIDsHash(c.domain, raw)
		if err != nil {
			t.Fatalf("%s: %v", c.domain, err)
		}
		if got := hex.EncodeToString(digest[:]); got != c.want {
			t.Fatalf("%s digest = %s, want %s", c.domain, got, c.want)
		}
	}
}

func TestTokenIDsHashRejectsBadFraming(t *testing.T) {
	for name, raw := range map[string]string{
		"empty":            "",
		"count only short": "000002",
		"count too large":  "00000003000000020000010100",
		"count too small":  "000000010000000200000101",
		"over bound":       "00800000",
	} {
		b, _ := hex.DecodeString(raw)
		if _, err := TokenIDsHash(DomainInputTokenIDsV1, b); err == nil {
			t.Fatalf("%s: framing must be rejected", name)
		}
	}
	if _, err := TokenIDsHash("TRUEOPEN_OTHER", []byte{0, 0, 0, 0}); err == nil {
		t.Fatal("unknown domain must be rejected")
	}
}

// TrueOpen/wire testdata/v1/task/worker_value_commitment_v2.json, compared byte-for-byte.
func TestGoldenWorkerValueCommitmentV2(t *testing.T) {
	h := func(s string) []byte {
		b, _ := hex.DecodeString(s)
		return b
	}
	commitment := WorkerValueCommitmentV2{
		ChainID:                    "trueopen-golden-1",
		TaskID:                     h("1111111111111111111111111111111111111111111111111111111111111111"),
		AcceptedTaskHash:           h("2222222222222222222222222222222222222222222222222222222222222222"),
		WorkerOperatorAddress:      "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz",
		GenerationParamsDigest:     h("3333333333333333333333333333333333333333333333333333333333333333"),
		EvidenceSchemaHash:         h("4444444444444444444444444444444444444444444444444444444444444444"),
		OutputHash:                 h("1d07690eb524833c073fe74787e52a25e426ed09013500d3dd43f7f363f65ec0"),
		OutputSizeBytes:            6,
		FinishReason:               1,
		TraceRoot:                  h("6666666666666666666666666666666666666666666666666666666666666666"),
		TraceEncodedSizeBytes:      5,
		CheckpointRoot:             h("7777777777777777777777777777777777777777777777777777777777777777"),
		CheckpointEncodedSizeBytes: 7,
		GeneratedTokenCount:        3,
		OutputLeafCount:            3,
		InputTokenIDsHash:          h("5ab982d47fc3c3b0a07e401f1c040c7fe2ef79ae93d0e44c50afe7d07a3ae901"),
		GeneratedTokenIDsHash:      h("057a76f605b3ba2fa26a92e379b5f0f802d97e379d4efc3a34e287f8e9e05efd"),
		InputTokenIDsSizeBytes:     12,
		GeneratedTokenIDsSizeBytes: 16,
	}
	digest, err := commitment.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(digest[:]), "fa05047203b16b229e016fc61d1572cf51ab75c87c4bc01ecd365d0656b1d16d"; got != want {
		t.Fatalf("digest = %s, want %s", got, want)
	}

	bad := commitment
	bad.TraceRoot = bad.TraceRoot[:31]
	if _, err := bad.Digest(); err == nil {
		t.Fatal("a short Hash32 must be rejected")
	}
}
