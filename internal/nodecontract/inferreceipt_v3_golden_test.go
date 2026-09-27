package nodecontract

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

// wireInferReceipt builds the InferReceiptV3 that wire testdata/v1/task/infer_receipt_v3.json describes,
// with the two evidence commitments of its commitment_list.
func wireInferReceipt(t *testing.T) (*taskv1.InferReceiptV3, wirefixture.Vector) {
	t.Helper()
	file := wirefixture.Load(t, "task/infer_receipt_v3.json")
	v := file.Vector(t, "infer_receipt_v3", 0)
	var list struct {
		CommitmentList struct {
			DigestHex string `json:"digest_hex"`
			Items     []struct {
				EncodedSizeBytes uint64 `json:"encoded_size_bytes"`
				HashOrRootHex    string `json:"evidence_hash_or_root_hex"`
				EvidenceKind     int32  `json:"evidence_kind"`
			} `json:"items"`
		} `json:"commitment_list"`
	}
	if err := json.Unmarshal(file.Raw, &list); err != nil {
		t.Fatalf("decode commitment_list: %v", err)
	}
	var commitments []*taskv1.EvidenceCommitmentV1
	for _, item := range list.CommitmentList.Items {
		root, err := hex.DecodeString(item.HashOrRootHex)
		if err != nil {
			t.Fatal(err)
		}
		commitments = append(commitments, &taskv1.EvidenceCommitmentV1{
			EvidenceKind: sharedv1.EvidenceKind(item.EvidenceKind), EvidenceHashOrRoot: root, EncodedSizeBytes: item.EncodedSizeBytes,
		})
	}
	if got := v.Field(t, "evidence_commitments_hash").Hex; got != list.CommitmentList.DigestHex {
		t.Fatalf("receipt evidence_commitments_hash %s is not the commitment_list digest %s", got, list.CommitmentList.DigestHex)
	}
	f := func(name string) wirefixture.Field { return v.Field(t, name) }
	return &taskv1.InferReceiptV3{
		SchemaVersion:               uint32(f("schema_version").Uint64(t)),
		ChainId:                     f("chain_id").UTF8,
		TaskId:                      f("task_id").Bytes(t),
		TaskHash:                    f("task_hash").Bytes(t),
		WorkerOperatorAddress:       f("worker_operator_address").Bech32,
		ServiceAuthorizationNonce:   f("service_authorization_nonce").Uint64(t),
		GenerationParamsDigest:      f("generation_params_digest").Bytes(t),
		OutputHash:                  f("output_hash").Bytes(t),
		OutputSizeBytes:             f("output_size_bytes").Uint64(t),
		RequiredEvidenceCommitments: commitments,
		ExpiryHeight:                f("expiry_height").Uint64(t),
		GeneratedTokenCount:         f("generated_token_count").Uint64(t),
		OutputLeafCount:             f("output_leaf_count").Uint64(t),
		OutputKeyCommitment:         f("output_key_commitment").Bytes(t),
		WorkerTokenKeyCommitment:    f("worker_token_key_commitment").Bytes(t),
		WorkerValueKeyCommitment:    f("worker_value_key_commitment").Bytes(t),
		CiphertextOutputRoot:        f("ciphertext_output_root").Bytes(t),
		ServiceSignature:            make([]byte, 64),
	}, v
}

// TestInferReceiptV3MatchesWireVector: the receipt digest, its evidence_commitments_hash and the link
// from the two commitments to the token and value commitment vectors all match the pinned wire release.
func TestInferReceiptV3MatchesWireVector(t *testing.T) {
	receipt, v := wireInferReceipt(t)
	v.CheckPreimage(t)
	if receipt.GetSchemaVersion() != InferReceiptSchemaVersionV3 {
		t.Fatalf("wire schema_version = %d, want %d", receipt.GetSchemaVersion(), InferReceiptSchemaVersionV3)
	}
	commitmentsHash, err := EvidenceCommitmentsHash(receipt.GetRequiredEvidenceCommitments())
	if err != nil {
		t.Fatalf("EvidenceCommitmentsHash: %v", err)
	}
	if hex.EncodeToString(commitmentsHash[:]) != v.Field(t, "evidence_commitments_hash").Hex {
		t.Fatalf("evidence_commitments_hash = %x", commitmentsHash)
	}
	digest, err := InferReceiptSigningDigest(receipt)
	if err != nil {
		t.Fatalf("InferReceiptSigningDigest: %v", err)
	}
	if digest != v.Digest(t) {
		t.Fatalf("receipt digest = %x, want %s", digest, v.DigestHex)
	}
	receipt.ServiceSignature = append(repeatByte(0xff, 63), 1)
	if again, _ := InferReceiptSigningDigest(receipt); again != digest {
		t.Fatal("service_signature must not enter the receipt preimage")
	}
	if err := ValidatePlaintextInferReceiptV3(receipt); err != nil {
		t.Fatalf("the wire plaintext receipt must pass admission: %v", err)
	}

	token := wirefixture.Load(t, "task/worker_token_commitment_v1.json").Vector(t, "worker_token_commitment_v1", 0)
	value := wirefixture.Load(t, "task/worker_value_commitment_v3.json").Vector(t, "worker_value_commitment_v3", 0)
	commitments := receipt.GetRequiredEvidenceCommitments()
	if hex.EncodeToString(commitments[0].GetEvidenceHashOrRoot()) != value.DigestHex ||
		hex.EncodeToString(commitments[1].GetEvidenceHashOrRoot()) != token.DigestHex {
		t.Fatal("the receipt's commitments must be the value and token commitment vectors, in EvidenceKind order")
	}
}

// TestInferReceiptV3Rejections covers the wire rejected_encodings of infer_receipt_v3: a single
// commitment, a text-encoded Hash32 and a nonzero (or empty) plaintext encryption field.
func TestInferReceiptV3Rejections(t *testing.T) {
	cases := map[string]struct {
		edit func(*taskv1.InferReceiptV3)
		// digest marks rejections by the derivation itself; the others are admission rejections.
		digest bool
	}{
		"one evidence commitment": {edit: func(r *taskv1.InferReceiptV3) {
			r.RequiredEvidenceCommitments = r.RequiredEvidenceCommitments[:1]
		}},
		"token before value": {digest: true, edit: func(r *taskv1.InferReceiptV3) {
			c := r.RequiredEvidenceCommitments
			c[0], c[1] = c[1], c[0]
		}},
		"text-encoded Hash32": {digest: true, edit: func(r *taskv1.InferReceiptV3) {
			r.TaskHash = []byte(hex.EncodeToString(r.TaskHash))
		}},
		"nonzero output_key_commitment":  {edit: func(r *taskv1.InferReceiptV3) { r.OutputKeyCommitment = repeatByte(1, 32) }},
		"empty worker_token_key":         {edit: func(r *taskv1.InferReceiptV3) { r.WorkerTokenKeyCommitment = nil }},
		"nonzero worker_value_key":       {edit: func(r *taskv1.InferReceiptV3) { r.WorkerValueKeyCommitment = repeatByte(2, 32) }},
		"nonzero ciphertext_output_root": {edit: func(r *taskv1.InferReceiptV3) { r.CiphertextOutputRoot = repeatByte(3, 32) }},
		"verifier kind": {edit: func(r *taskv1.InferReceiptV3) {
			r.RequiredEvidenceCommitments[1].EvidenceKind = sharedv1.EvidenceKind_EVIDENCE_KIND_VERIFIER_VALUE_OPENING
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			receipt, _ := wireInferReceipt(t)
			c.edit(receipt)
			_, digestErr := InferReceiptSigningDigest(receipt)
			admitErr := ValidatePlaintextInferReceiptV3(receipt)
			if c.digest && digestErr == nil {
				t.Fatal("the derivation must reject this receipt")
			}
			if digestErr == nil && admitErr == nil {
				t.Fatal("this receipt must be rejected")
			}
		})
	}
}

// TestInferReceiptSigningDigestRejectsMalformed pins the derivation's structural rejections:
// a short Hash32, a non-canonical address and an unregistered evidence kind must not produce a digest.
func TestInferReceiptSigningDigestRejectsMalformed(t *testing.T) {
	cases := map[string]func(*taskv1.InferReceiptV3){
		"nil receipt":   nil,
		"short task_id": func(r *taskv1.InferReceiptV3) { r.TaskId = make([]byte, 31) },
		"empty worker":  func(r *taskv1.InferReceiptV3) { r.WorkerOperatorAddress = "" },
		"padded worker": func(r *taskv1.InferReceiptV3) { r.WorkerOperatorAddress += " " },
		"unspecified kind": func(r *taskv1.InferReceiptV3) {
			r.RequiredEvidenceCommitments[0].EvidenceKind = 0
		},
		"unregistered kind":   func(r *taskv1.InferReceiptV3) { r.RequiredEvidenceCommitments[1].EvidenceKind = 99 },
		"nil commitment":      func(r *taskv1.InferReceiptV3) { r.RequiredEvidenceCommitments[0] = nil },
		"short evidence hash": func(r *taskv1.InferReceiptV3) { r.RequiredEvidenceCommitments[0].EvidenceHashOrRoot = nil },
		"duplicate kind": func(r *taskv1.InferReceiptV3) {
			r.RequiredEvidenceCommitments[1] = r.RequiredEvidenceCommitments[0]
		},
		"short output_hash":     func(r *taskv1.InferReceiptV3) { r.OutputHash = make([]byte, 16) },
		"short params digest":   func(r *taskv1.InferReceiptV3) { r.GenerationParamsDigest = nil },
		"invalid utf8 chain_id": func(r *taskv1.InferReceiptV3) { r.ChainId = string([]byte{0xff, 0xfe}) },
		"non bech32 worker":     func(r *taskv1.InferReceiptV3) { r.WorkerOperatorAddress = "not-an-address" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			var receipt *taskv1.InferReceiptV3
			if mutate != nil {
				receipt, _ = wireInferReceipt(t)
				mutate(receipt)
			}
			if _, err := InferReceiptSigningDigest(receipt); err == nil {
				t.Fatal("expected the derivation to reject this receipt")
			}
		})
	}
}

// generated_token_count sizes the Worker's value tree, so a plaintext receipt beyond the token id
// bound is refused at admission.
func TestInferReceiptV3RejectsUnboundedTokenCount(t *testing.T) {
	receipt, _ := wireInferReceipt(t)
	receipt.GeneratedTokenCount = MaxTokenIDCountV1 + 1
	if err := ValidatePlaintextInferReceiptV3(receipt); err == nil {
		t.Fatal("must be refused")
	}
}
