package taskdata

import (
	"context"
	"encoding/hex"
	"testing"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	"github.com/TrueOpen/nexus/internal/nodecontract"
)

// anchorCommitBody stands in for the engine's anchor commitment document. Finalize binds it by its
// SHA-256 and size only and does not parse it.
var anchorCommitBody = []byte(`{"anchor_commit_version":1,"roots":["00"]}`)

// storeAnchorBundle stores a WORKER_ANCHOR_OPENING bundle holding artifacts and appends the
// receipt's third commitment, computed over committed (the bytes the Worker signed for; the stored
// anchor_commit artifact may differ).
func (f *finalizeFixture) storeAnchorBundle(t *testing.T, artifacts map[string][]byte, committed []byte) Metadata {
	t.Helper()
	h := func(value string) []byte { return mustDecodeHex(t, value) }
	digest, err := nodecontract.WorkerAnchorCommitmentV1{
		ChainID: f.receipt.ChainID, TaskID: h(f.receipt.TaskID), AcceptedTaskHash: h(f.taskHash),
		WorkerOperatorAddress: f.receipt.WorkerOperatorAddress, EvidenceSchemaHash: h(finalizeSchemaHash),
		AnchorCommitHash: sha256Sum(committed), AnchorCommitSizeBytes: uint64(len(committed)),
	}.Digest()
	if err != nil {
		t.Fatal(err)
	}
	anchor := f.storeBundle(t, EvidenceKindWorkerAnchorOpening, artifacts, "", hex.EncodeToString(digest[:]))
	// Ordered by EvidenceKind value: value (1), token (4), anchor (5).
	f.receipt.EvidenceCommitments = append(f.receipt.EvidenceCommitments, EvidenceCommitment{
		Kind:       uint32(sharedv1.EvidenceKind_EVIDENCE_KIND_WORKER_ANCHOR_OPENING),
		HashOrRoot: anchor.Key.ContentHash, EncodedSizeBytes: anchor.ArtifactTotalSizeBytes,
	})
	f.resignReceipt(t)
	return anchor
}

// A receipt with a third, WORKER_ANCHOR_OPENING commitment finalizes all three bundles: the anchor
// bundle is confirmed like the other two once its commitment is recomputed from the stored
// anchor_commit bytes.
func TestFinalizeTaskResultCommitsAnchorBundle(t *testing.T) {
	f := newFinalizeFixture(t)
	anchor := f.storeAnchorBundle(t, map[string][]byte{artifactAnchorCommit: anchorCommitBody}, anchorCommitBody)

	outcome, err := f.service.FinalizeTaskResult(context.Background(), f.request(t, 8, EvidenceKindWorkerAnchorOpening))
	if err != nil {
		t.Fatalf("finalize anchor bundle: %v", err)
	}
	if outcome.Idempotent || len(outcome.EvidenceConfirmations) != 1 ||
		outcome.EvidenceConfirmations[0].Ref != anchor.Key ||
		outcome.EvidenceConfirmations[0].ArtifactTotalSizeBytes != uint64(len(anchorCommitBody)) {
		t.Fatalf("anchor bundle outcome = %#v", outcome)
	}
	if f.state(t, anchor.Key) != StateReady {
		t.Fatal("anchor manifest is not READY")
	}
	artifactRef := anchor.Key
	artifactRef.Kind, artifactRef.ContentHash = ObjectKindEvidenceArtifact, anchor.Artifacts[0].ContentHash
	if f.state(t, artifactRef) != StateReady {
		t.Fatal("anchor_commit artifact is not READY")
	}
	// The token and value bundles finalize under the same three-commitment receipt.
	f.finalizeBoth(t)
}

// The anchor commitment is recomputed from the stored bundle: other bytes than the committed ones,
// a different size, or an artifact set that is not exactly anchor_commit are all refused.
func TestFinalizeTaskResultRejectsAnchorBundle(t *testing.T) {
	sameSize := append([]byte(nil), anchorCommitBody...)
	sameSize[len(sameSize)-3] ^= 1
	for name, c := range map[string]struct {
		artifacts map[string][]byte
		committed []byte
		edit      func(*finalizeFixture)
		want      error
		contains  string
	}{
		"hash mismatch": {
			artifacts: map[string][]byte{artifactAnchorCommit: sameSize}, committed: anchorCommitBody,
			want: ErrHashMismatch, contains: "worker WORKER_ANCHOR_OPENING commitment recomputed",
		},
		"committed size differs from the stored artifact": {
			artifacts: map[string][]byte{artifactAnchorCommit: anchorCommitBody}, committed: append(append([]byte(nil), anchorCommitBody...), ' '),
			want: ErrHashMismatch, contains: "worker WORKER_ANCHOR_OPENING commitment recomputed",
		},
		"receipt encoded_size_bytes differs": {
			artifacts: map[string][]byte{artifactAnchorCommit: anchorCommitBody}, committed: anchorCommitBody,
			edit: func(f *finalizeFixture) { f.receipt.EvidenceCommitments[2].EncodedSizeBytes++ },
			want: ErrHashMismatch, contains: "receipt encoded_size_bytes",
		},
		"renamed artifact": {
			artifacts: map[string][]byte{"trace": anchorCommitBody}, committed: anchorCommitBody,
			want: ErrMalformed, contains: "artifact 0",
		},
		"extra artifact": {
			artifacts: map[string][]byte{artifactAnchorCommit: anchorCommitBody, "zzz": []byte("extra artifact")}, committed: anchorCommitBody,
			want: ErrMalformed, contains: "2 artifacts, want 1",
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFinalizeFixture(t)
			f.storeAnchorBundle(t, c.artifacts, c.committed)
			if c.edit != nil {
				c.edit(f)
				f.resignReceipt(t)
			}
			f.requireFinalizeRejected(t, EvidenceKindWorkerAnchorOpening, c.want, c.contains)
		})
	}
}

// A receipt without a third commitment has no anchor bundle to finalize.
func TestFinalizeTaskResultRejectsAnchorKindWithoutCommitment(t *testing.T) {
	f := newFinalizeFixture(t)
	f.requireFinalizeRejected(t, EvidenceKindWorkerAnchorOpening, ErrMalformed, "receipt has no WORKER_ANCHOR_OPENING commitment")
}

// WORKER_ANCHOR_OPENING is a Worker bundle kind only.
func TestWorkerAnchorOpeningBelongsToTheWorker(t *testing.T) {
	if !EvidenceKindWorkerAnchorOpening.belongsTo(EvidenceProducerWorker) || EvidenceKindWorkerAnchorOpening.belongsTo(EvidenceProducerVerifier) {
		t.Fatal("WORKER_ANCHOR_OPENING must be a Worker kind and not a Verifier kind")
	}
	if EvidenceKindWorkerAnchorOpening.String() != "WORKER_ANCHOR_OPENING" || evidenceKindNamed("WORKER_ANCHOR_OPENING") != EvidenceKindWorkerAnchorOpening {
		t.Fatal("the manifest name of kind 5 must be WORKER_ANCHOR_OPENING")
	}
	if uint32(EvidenceKindWorkerAnchorOpening) != uint32(sharedv1.EvidenceKind_EVIDENCE_KIND_WORKER_ANCHOR_OPENING) {
		t.Fatal("EvidenceKindWorkerAnchorOpening must equal the wire enum value")
	}
}
