package nodecontract

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

// wireAnchorCommitmentVector is the wire conformance vector of the anchor commitment, relative to
// the wire module root.
const wireAnchorCommitmentVector = "testdata/v1/task/worker_anchor_commitment_v1.json"

// anchorCommitmentVector is the input of that wire vector and its digest, the value Cortex
// produces for the same input. It is kept here as well because the wire revision pinned in go.mod
// may predate the vector file; when the pinned wire carries the file,
// TestWorkerAnchorCommitmentV1Vector also checks this copy against it.
func anchorCommitmentVector() (WorkerAnchorCommitmentV1, string) {
	return WorkerAnchorCommitmentV1{
		ChainID:               "trueopen-localnet-1",
		TaskID:                bytes.Repeat([]byte{0x11}, 32),
		AcceptedTaskHash:      bytes.Repeat([]byte{0x22}, 32),
		WorkerOperatorAddress: "trueopen15zs69gay5kn2029f4246etdw47ctrv4ns6facc",
		EvidenceSchemaHash:    bytes.Repeat([]byte{0x33}, 32),
		AnchorCommitHash:      bytes.Repeat([]byte{0x44}, 32),
		AnchorCommitSizeBytes: 123456,
	}, "88373eed3d4b9d71e658c40a49026da66c03c83604f4eb0ea78ec04dc5620a14"
}

// TestWorkerAnchorCommitmentV1Vector pins the anchor commitment digest to the shared conformance
// vector, so Nexus, Cortex and wire agree on one value.
func TestWorkerAnchorCommitmentV1Vector(t *testing.T) {
	input, want := anchorCommitmentVector()
	digest, err := input.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(digest[:]); got != want {
		t.Fatalf("digest = %s, want %s", got, want)
	}

	if _, err := os.Stat(filepath.Join(wirefixture.Dir(t), wireAnchorCommitmentVector)); err != nil {
		t.Logf("the pinned wire has no %s; checked the local copy of the vector only", wireAnchorCommitmentVector)
		return
	}
	v := wirefixture.Load(t, "task/worker_anchor_commitment_v1.json").Vector(t, "worker_anchor_commitment_v1", 0)
	v.CheckPreimage(t)
	f := func(name string) wirefixture.Field { return v.Field(t, name) }
	fromWire, err := WorkerAnchorCommitmentV1{
		ChainID:               f("chain_id").UTF8,
		TaskID:                f("task_id").Bytes(t),
		AcceptedTaskHash:      f("accepted_task_hash").Bytes(t),
		WorkerOperatorAddress: f("worker_operator_address").Bech32,
		EvidenceSchemaHash:    f("evidence_schema_hash").Bytes(t),
		AnchorCommitHash:      f("anchor_commit_hash").Bytes(t),
		AnchorCommitSizeBytes: f("anchor_commit_size_bytes").Uint64(t),
	}.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if fromWire != v.Digest(t) {
		t.Fatalf("digest of the wire vector's fields = %x, want %s", fromWire, v.DigestHex)
	}
	if v.DigestHex != want || uint32(f("schema_version").Uint64(t)) != WorkerAnchorCommitmentSchemaV1 {
		t.Fatalf("the local copy differs from the wire vector: digest %s, schema_version %d", v.DigestHex, f("schema_version").Uint64(t))
	}
}

// Every field of the anchor commitment enters the digest, and malformed inputs produce none.
func TestWorkerAnchorCommitmentV1BindsEveryField(t *testing.T) {
	base, _ := anchorCommitmentVector()
	want, err := base.Digest()
	if err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*WorkerAnchorCommitmentV1){
		"chain_id":           func(c *WorkerAnchorCommitmentV1) { c.ChainID = "trueopen-localnet-2" },
		"task_id":            func(c *WorkerAnchorCommitmentV1) { c.TaskID = bytes.Repeat([]byte{0x12}, 32) },
		"accepted_task_hash": func(c *WorkerAnchorCommitmentV1) { c.AcceptedTaskHash = bytes.Repeat([]byte{0x23}, 32) },
		"worker_operator_address": func(c *WorkerAnchorCommitmentV1) {
			c.WorkerOperatorAddress = "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz"
		},
		"evidence_schema_hash":     func(c *WorkerAnchorCommitmentV1) { c.EvidenceSchemaHash = bytes.Repeat([]byte{0x34}, 32) },
		"anchor_commit_hash":       func(c *WorkerAnchorCommitmentV1) { c.AnchorCommitHash = bytes.Repeat([]byte{0x45}, 32) },
		"anchor_commit_size_bytes": func(c *WorkerAnchorCommitmentV1) { c.AnchorCommitSizeBytes++ },
	} {
		changed := base
		edit(&changed)
		got, err := changed.Digest()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got == want {
			t.Fatalf("changing %s must change the digest", name)
		}
	}
	for name, edit := range map[string]func(*WorkerAnchorCommitmentV1){
		"zero size":                func(c *WorkerAnchorCommitmentV1) { c.AnchorCommitSizeBytes = 0 },
		"short anchor_commit_hash": func(c *WorkerAnchorCommitmentV1) { c.AnchorCommitHash = make([]byte, 31) },
		"short task_id":            func(c *WorkerAnchorCommitmentV1) { c.TaskID = nil },
		"non bech32 worker":        func(c *WorkerAnchorCommitmentV1) { c.WorkerOperatorAddress = "not-an-address" },
		"invalid utf8 chain_id":    func(c *WorkerAnchorCommitmentV1) { c.ChainID = string([]byte{0xff, 0xfe}) },
	} {
		changed := base
		edit(&changed)
		if _, err := changed.Digest(); err == nil {
			t.Fatalf("%s must be refused", name)
		}
	}
}

// withThirdCommitment appends a commitment of the given kind to the wire receipt's two.
func withThirdCommitment(receipt *taskv1.InferReceiptV3, kind sharedv1.EvidenceKind) {
	receipt.RequiredEvidenceCommitments = append(receipt.RequiredEvidenceCommitments, &taskv1.EvidenceCommitmentV1{
		EvidenceKind: kind, EvidenceHashOrRoot: bytes.Repeat([]byte{0x5a}, 32), EncodedSizeBytes: 123456,
	})
}

// A receipt may carry WORKER_ANCHOR_OPENING as a third commitment after the value and token
// commitments; the list is then part of the receipt digest.
func TestInferReceiptV3AcceptsAnchorAsThirdCommitment(t *testing.T) {
	receipt, _ := wireInferReceipt(t)
	two, err := InferReceiptSigningDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	withThirdCommitment(receipt, sharedv1.EvidenceKind_EVIDENCE_KIND_WORKER_ANCHOR_OPENING)
	if err := ValidatePlaintextInferReceiptV3(receipt); err != nil {
		t.Fatalf("a receipt with value, token and anchor commitments must pass admission: %v", err)
	}
	three, err := InferReceiptSigningDigest(receipt)
	if err != nil {
		t.Fatalf("InferReceiptSigningDigest: %v", err)
	}
	if three == two {
		t.Fatal("the third commitment must enter the receipt digest")
	}
}

// The third commitment can only be WORKER_ANCHOR_OPENING, it cannot stand in for the value or token
// commitment, and nothing may follow it.
func TestInferReceiptV3RejectsOtherThirdCommitments(t *testing.T) {
	anchor := sharedv1.EvidenceKind_EVIDENCE_KIND_WORKER_ANCHOR_OPENING
	for name, edit := range map[string]func(*taskv1.InferReceiptV3){
		"third is a verifier kind": func(r *taskv1.InferReceiptV3) {
			withThirdCommitment(r, sharedv1.EvidenceKind_EVIDENCE_KIND_VERIFIER_VALUE_OPENING)
		},
		"third is the settlement root": func(r *taskv1.InferReceiptV3) {
			withThirdCommitment(r, sharedv1.EvidenceKind_EVIDENCE_KIND_SETTLEMENT_ROOT_OPENING)
		},
		"third repeats the token kind": func(r *taskv1.InferReceiptV3) {
			withThirdCommitment(r, sharedv1.EvidenceKind_EVIDENCE_KIND_WORKER_TOKEN_OPENING)
		},
		"third is unspecified": func(r *taskv1.InferReceiptV3) {
			withThirdCommitment(r, sharedv1.EvidenceKind_EVIDENCE_KIND_UNSPECIFIED)
		},
		"anchor replaces the token commitment": func(r *taskv1.InferReceiptV3) {
			r.RequiredEvidenceCommitments[1].EvidenceKind = anchor
		},
		"anchor before token": func(r *taskv1.InferReceiptV3) {
			withThirdCommitment(r, anchor)
			c := r.RequiredEvidenceCommitments
			c[1], c[2] = c[2], c[1]
		},
		"a fourth commitment": func(r *taskv1.InferReceiptV3) {
			withThirdCommitment(r, anchor)
			withThirdCommitment(r, anchor)
		},
	} {
		t.Run(name, func(t *testing.T) {
			receipt, _ := wireInferReceipt(t)
			edit(receipt)
			if err := ValidatePlaintextInferReceiptV3(receipt); err == nil {
				t.Fatal("this receipt must be refused at admission")
			}
		})
	}
}
