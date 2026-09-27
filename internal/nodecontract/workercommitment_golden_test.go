package nodecontract

import (
	"encoding/hex"
	"testing"

	"github.com/TrueOpen/nexus/internal/wirefixture"
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

// TestGoldenWorkerTokenCommitmentV1 compares with wire testdata/v1/task/worker_token_commitment_v1.json.
func TestGoldenWorkerTokenCommitmentV1(t *testing.T) {
	v := wirefixture.Load(t, "task/worker_token_commitment_v1.json").Vector(t, "worker_token_commitment_v1", 0)
	v.CheckPreimage(t)
	f := func(name string) wirefixture.Field { return v.Field(t, name) }
	digest, err := WorkerTokenCommitmentV1{
		ChainID:                    f("chain_id").UTF8,
		TaskID:                     f("task_id").Bytes(t),
		AcceptedTaskHash:           f("accepted_task_hash").Bytes(t),
		WorkerOperatorAddress:      f("worker_operator_address").Bech32,
		GenerationParamsDigest:     f("generation_params_digest").Bytes(t),
		EvidenceSchemaHash:         f("evidence_schema_hash").Bytes(t),
		OutputHash:                 f("output_hash").Bytes(t),
		OutputSizeBytes:            f("output_size_bytes").Uint64(t),
		OutputLeafCount:            f("output_leaf_count").Uint64(t),
		FinishReason:               uint32(f("finish_reason").Uint64(t)),
		GeneratedTokenCount:        f("generated_token_count").Uint64(t),
		InputTokenIDsHash:          f("input_token_ids_hash").Bytes(t),
		GeneratedTokenIDsHash:      f("generated_token_ids_hash").Bytes(t),
		InputTokenIDsSizeBytes:     f("input_token_ids_size_bytes").Uint64(t),
		GeneratedTokenIDsSizeBytes: f("generated_token_ids_size_bytes").Uint64(t),
	}.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if digest != v.Digest(t) {
		t.Fatalf("digest = %x, want %s", digest, v.DigestHex)
	}
}

// TestGoldenWorkerValueCommitmentV3 compares with wire testdata/v1/task/worker_value_commitment_v3.json.
func TestGoldenWorkerValueCommitmentV3(t *testing.T) {
	v := wirefixture.Load(t, "task/worker_value_commitment_v3.json").Vector(t, "worker_value_commitment_v3", 0)
	v.CheckPreimage(t)
	f := func(name string) wirefixture.Field { return v.Field(t, name) }
	digest, err := WorkerValueCommitmentV3{
		ChainID:                      f("chain_id").UTF8,
		TaskID:                       f("task_id").Bytes(t),
		AcceptedTaskHash:             f("accepted_task_hash").Bytes(t),
		WorkerOperatorAddress:        f("worker_operator_address").Bech32,
		EvidenceSchemaHash:           f("evidence_schema_hash").Bytes(t),
		WorkerValueRoot:              f("worker_value_root").Bytes(t),
		WorkerValuesEncodedSizeBytes: f("worker_values_encoded_size_bytes").Uint64(t),
	}.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if digest != v.Digest(t) {
		t.Fatalf("digest = %x, want %s", digest, v.DigestHex)
	}
}
