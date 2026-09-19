package taskdata

import (
	"encoding/hex"
	"strings"
	"testing"
)

// Byte for byte against wire v0.4.1 `testdata/v1/task/task_data_auth_v1.json`. The five
// body domains and the outer TRUEOPEN_TASK_DATA_REQUEST_V1 are the only request authentication
// contract between Nexus and Cortex / SDK; one byte off and the two sides never verify, so
// this checks against wire's published vectors, not our own recomputation.
const (
	goldenTaskHash    = "2222222222222222222222222222222222222222222222222222222222222222"
	goldenSessionID   = "3333333333333333333333333333333333333333333333333333333333333333"
	goldenTaskID      = "1111111111111111111111111111111111111111111111111111111111111111"
	goldenContentHash = "4444444444444444444444444444444444444444444444444444444444444444"
	// Addresses enter the preimage as the 20 address codec bytes; bech32 is only the text
	// shell. The bech32 text of these two in the wire vector does not match the node/nexus
	// encoder (see comment below), so the canonical bech32 decoded from hex is used here and
	// the preimage bytes therefore match the vector.
	//   c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3
	goldenProducer = "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe"
	//   77d7bb07580b39fb949df09f7bb9f80a1d0641b8
	goldenBuilder = "trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man"
)

func goldenOutputRef() ObjectRef {
	return ObjectRef{
		TaskHash: goldenTaskHash, SessionID: goldenSessionID, TaskID: goldenTaskID,
		Kind: ObjectKindOutput, ContentHash: goldenContentHash,
	}
}

// A Verifier evidence manifest: all three producer fields non-zero, optional present.
func goldenEvidenceRef() ObjectRef {
	return ObjectRef{
		TaskHash: goldenTaskHash, SessionID: goldenSessionID, TaskID: goldenTaskID,
		Kind: ObjectKindEvidenceManifest, ContentHash: goldenContentHash,
		EvidenceProducerKind: EvidenceProducerVerifier, VerifyRound: 2,
		ProducerOperator: goldenProducer,
	}
}

func assertDigest(t *testing.T, name string, got [32]byte, want string) {
	t.Helper()
	if h := hex.EncodeToString(got[:]); h != want {
		t.Fatalf("%s = %s, want %s", name, h, want)
	}
}

func TestWireV041TaskDataBodyDigests(t *testing.T) {
	t.Run("metadata", func(t *testing.T) {
		got, err := TaskDataMetadataBodyDigest(goldenOutputRef())
		if err != nil {
			t.Fatal(err)
		}
		assertDigest(t, "metadata body", got, "6c228b37b0baa5bb0d92ca80579bf347bd3920ddc34e32f6add864cf8fc17f18")
	})

	t.Run("fetch with range", func(t *testing.T) {
		got, err := TaskDataFetchBodyDigest(goldenOutputRef(), &ByteRange{Offset: 64, Length: 128})
		if err != nil {
			t.Fatal(err)
		}
		assertDigest(t, "fetch body", got, "f079d3b5e89705f4b65ca30e3d982aa2a62a1fee2aed291b28f088ca386fc964")
	})

	t.Run("upload", func(t *testing.T) {
		got, err := TaskDataUploadBodyDigest(goldenEvidenceRef(), 556, "application/json")
		if err != nil {
			t.Fatal(err)
		}
		assertDigest(t, "upload body", got, "34dbf62abb8ccc24737908fe9219be53972942337a71f1a9e1a311ab7ddda32a")
	})

	t.Run("finalize result", func(t *testing.T) {
		got, err := TaskDataFinalizeResultBodyDigest(goldenTaskHash, goldenSessionID, goldenTaskID,
			strings.Repeat("55", 32), strings.Repeat("56", 32))
		if err != nil {
			t.Fatal(err)
		}
		assertDigest(t, "finalize result body", got, "bfc6626ea56873baea625da90a14fb23f27528ef2500c040f7d1bf71473474f7")
	})

	t.Run("finalize verifier", func(t *testing.T) {
		got, err := TaskDataFinalizeVerifierBodyDigest(goldenTaskHash, goldenSessionID, goldenTaskID,
			2, goldenProducer, strings.Repeat("66", 32), strings.Repeat("67", 32))
		if err != nil {
			t.Fatal(err)
		}
		assertDigest(t, "finalize verifier body", got, "fed02d8d12c406b16a13a58c35c146cd3a5f5ccaf9ada0cf5aac0263d521c913")
	})
}

func TestWireV041TaskDataRequestDigest(t *testing.T) {
	nonce, err := hex.DecodeString("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf")
	if err != nil {
		t.Fatal(err)
	}
	body, err := TaskDataUploadBodyDigest(goldenEvidenceRef(), 556, "application/json")
	if err != nil {
		t.Fatal(err)
	}
	auth := RequestAuthV1{
		SchemaVersion: 1, ChainID: "trueopen-golden-1",
		BuilderOperatorAddress:    goldenBuilder,
		RPCMethod:                 "/nexus.v1.IngressAPI/UploadTaskResultObject",
		BodyDigest:                hex.EncodeToString(body[:]),
		RequesterKind:             RequesterKindCortexService,
		RequesterAddress:          goldenProducer,
		ServiceAuthorizationNonce: 7,
		RequestNonce:              nonce,
		ExpiryHeight:              2000,
	}
	got, err := CortexTaskDataRequestDigest(auth)
	if err != nil {
		t.Fatal(err)
	}
	assertDigest(t, "request auth", got, "66b140f48e8b49c1c69eb8213334eb42db05db91630e7a496f64640ba70b94dc")

	// body_digest is preimage field 5: a different body must give a different digest,
	// otherwise one signature authorizes any body and authentication is pointless.
	other, err := TaskDataUploadBodyDigest(goldenEvidenceRef(), 557, "application/json")
	if err != nil {
		t.Fatal(err)
	}
	auth.BodyDigest = hex.EncodeToString(other[:])
	moved, err := CortexTaskDataRequestDigest(auth)
	if err != nil {
		t.Fatal(err)
	}
	if moved == got {
		t.Fatal("body_digest is not in the preimage")
	}
}

// A whole read signs range absent, not a present range with zero offset/length. Their
// preimages differ and the implementation must not rewrite the former into the latter.
func TestFetchBodyAbsentRangeIsNotZeroRange(t *testing.T) {
	whole, err := TaskDataFetchBodyDigest(goldenOutputRef(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := TaskDataFetchBodyDigest(goldenOutputRef(), &ByteRange{}); err == nil {
		t.Fatal("a present range with length 0 must be rejected")
	}
	ranged, err := TaskDataFetchBodyDigest(goldenOutputRef(), &ByteRange{Offset: 0, Length: 1})
	if err != nil {
		t.Fatal(err)
	}
	if whole == ranged {
		t.Fatal("absent range and present range must have different digests")
	}
}

// A non-evidence object carrying the three producer fields is rejected: otherwise one OUTPUT could yield multiple refs.
func TestObjectRefRejectsProducerFieldsOnNonEvidence(t *testing.T) {
	for name, mutate := range map[string]func(*ObjectRef){
		"producer kind":     func(r *ObjectRef) { r.EvidenceProducerKind = EvidenceProducerWorker },
		"verify round":      func(r *ObjectRef) { r.VerifyRound = 1 },
		"producer operator": func(r *ObjectRef) { r.ProducerOperator = goldenProducer },
	} {
		t.Run(name, func(t *testing.T) {
			ref := goldenOutputRef()
			mutate(&ref)
			if _, err := CanonicalObjectRefFrame(ref); err == nil {
				t.Fatal("must be rejected")
			}
		})
	}
	// The reverse for evidence objects: producer kind must not be unspecified.
	ref := goldenEvidenceRef()
	ref.EvidenceProducerKind = EvidenceProducerUnspecified
	if _, err := CanonicalObjectRefFrame(ref); err == nil {
		t.Fatal("evidence objects must carry a producer kind")
	}
}
