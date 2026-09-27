package taskdata

import (
	"encoding/hex"
	"testing"

	"github.com/cosmos/cosmos-sdk/types/bech32"

	"github.com/TrueOpen/nexus/internal/wirefixture"
)

// Byte for byte against the wire vectors of testdata/v1/task/task_data_auth_v1.json. The five body
// domains and the outer TRUEOPEN_TASK_DATA_REQUEST_V1 are the only request authentication contract
// between Nexus and Cortex / SDK; one byte off and the two sides never verify, so this checks
// against wire's published vectors, not our own recomputation.
const (
	goldenTaskHash    = "2222222222222222222222222222222222222222222222222222222222222222"
	goldenSessionID   = "3333333333333333333333333333333333333333333333333333333333333333"
	goldenTaskID      = "1111111111111111111111111111111111111111111111111111111111111111"
	goldenContentHash = "4444444444444444444444444444444444444444444444444444444444444444"
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

// A Verifier evidence manifest: all producer fields non-zero, optional present.
func goldenEvidenceRef() ObjectRef {
	return ObjectRef{
		TaskHash: goldenTaskHash, SessionID: goldenSessionID, TaskID: goldenTaskID,
		Kind: ObjectKindEvidenceManifest, ContentHash: goldenContentHash,
		EvidenceProducerKind: EvidenceProducerVerifier, VerifyRound: 2,
		ProducerOperator: goldenProducer, EvidenceKind: EvidenceKindVerifierValueOpening,
	}
}

// bech32Of encodes 20 address codec bytes: only the codec bytes enter a preimage, bech32 is the text shell.
func bech32Of(t *testing.T, raw []byte) string {
	t.Helper()
	encoded, err := bech32.ConvertAndEncode("trueopen", raw)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// wireObjectRef builds the ObjectRef a vector's object_ref frame describes.
func wireObjectRef(t *testing.T, frame wirefixture.Field) ObjectRef {
	t.Helper()
	sub := map[string]wirefixture.Field{}
	for _, f := range frame.Fields {
		sub[f.Name] = f
	}
	ref := ObjectRef{
		TaskHash: hex.EncodeToString(sub["task_hash"].Bytes(t)), SessionID: hex.EncodeToString(sub["session_id"].Bytes(t)),
		TaskID: hex.EncodeToString(sub["task_id"].Bytes(t)), Kind: ObjectKind(sub["object_kind"].Uint64(t)),
		ContentHash:          hex.EncodeToString(sub["content_hash"].Bytes(t)),
		EvidenceProducerKind: EvidenceProducerKind(sub["evidence_producer_kind"].Uint64(t)),
		VerifyRound:          uint32(sub["verify_round"].Uint64(t)),
		EvidenceKind:         EvidenceKind(sub["evidence_kind"].Uint64(t)),
	}
	if operator := sub["producer_operator"]; operator.Present {
		ref.ProducerOperator = bech32Of(t, operator.Fields[0].Bytes(t))
	}
	return ref
}

func assertDigest(t *testing.T, name string, got [32]byte, want string) {
	t.Helper()
	if h := hex.EncodeToString(got[:]); h != want {
		t.Fatalf("%s = %s, want %s", name, h, want)
	}
}

// TestTaskDataBodyDigestsMatchWireVectors checks each body domain against its wire vector.
func TestTaskDataBodyDigestsMatchWireVectors(t *testing.T) {
	file := wirefixture.Load(t, "task/task_data_auth_v1.json")
	hexOf := func(v wirefixture.Vector, name string) string { return hex.EncodeToString(v.Field(t, name).Bytes(t)) }
	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			v.CheckPreimage(t)
			var got [32]byte
			var err error
			switch v.Domain {
			case DomainTaskDataUploadBody:
				got, err = TaskDataUploadBodyDigest(wireObjectRef(t, v.Field(t, "object_ref")),
					v.Field(t, "size_bytes").Uint64(t), v.Field(t, "media_type").UTF8)
			case DomainTaskDataMetadataBody:
				got, err = TaskDataMetadataBodyDigest(wireObjectRef(t, v.Field(t, "object_ref")))
			case DomainTaskDataFetchBody:
				var rng *ByteRange
				if r := v.Field(t, "range"); r.Present {
					inner := r.Fields[0].Fields
					rng = &ByteRange{Offset: inner[0].Uint64(t), Length: inner[1].Uint64(t)}
				}
				got, err = TaskDataFetchBodyDigest(wireObjectRef(t, v.Field(t, "object_ref")), rng)
			case DomainTaskDataFinalizeResultBody:
				got, err = TaskDataFinalizeResultBodyDigest(hexOf(v, "task_hash"), hexOf(v, "session_id"), hexOf(v, "task_id"),
					hexOf(v, "infer_receipt_hash"), hexOf(v, "infer_receipt_signature_digest"),
					EvidenceKind(v.Field(t, "evidence_kind").Uint64(t)))
			case DomainTaskDataFinalizeVerifierBody:
				got, err = TaskDataFinalizeVerifierBodyDigest(hexOf(v, "task_hash"), hexOf(v, "session_id"), hexOf(v, "task_id"),
					uint32(v.Field(t, "verify_round").Uint64(t)), bech32Of(t, v.Field(t, "verifier_operator").Bytes(t)),
					hexOf(v, "result_receipt_signing_digest"), hexOf(v, "result_receipt_signature_digest"))
			case DomainTaskDataRequest:
				got, err = CortexTaskDataRequestDigest(RequestAuthV1{
					SchemaVersion: uint32(v.Field(t, "schema_version").Uint64(t)), ChainID: v.Field(t, "chain_id").UTF8,
					BuilderOperatorAddress:    bech32Of(t, v.Field(t, "builder_operator_address").Bytes(t)),
					RPCMethod:                 v.Field(t, "rpc_method").UTF8,
					BodyDigest:                hexOf(v, "body_digest"),
					RequesterKind:             RequesterKind(v.Field(t, "requester_kind").Uint64(t)),
					RequesterAddress:          bech32Of(t, v.Field(t, "requester_address").Bytes(t)),
					ServiceAuthorizationNonce: v.Field(t, "service_authorization_nonce").Uint64(t),
					RequestNonce:              v.Field(t, "request_nonce").Bytes(t),
					ExpiryHeight:              v.Field(t, "expiry_height").Uint64(t),
				})
			default:
				t.Fatalf("unexpected domain %s", v.Domain)
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != v.Digest(t) {
				t.Fatalf("digest = %x, want %s", got, v.DigestHex)
			}
		})
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

// A non-evidence object carrying producer fields or an evidence kind is rejected: otherwise one OUTPUT
// could yield multiple refs.
func TestObjectRefRejectsProducerFieldsOnNonEvidence(t *testing.T) {
	for name, mutate := range map[string]func(*ObjectRef){
		"producer kind":     func(r *ObjectRef) { r.EvidenceProducerKind = EvidenceProducerWorker },
		"verify round":      func(r *ObjectRef) { r.VerifyRound = 1 },
		"producer operator": func(r *ObjectRef) { r.ProducerOperator = goldenProducer },
		"evidence kind":     func(r *ObjectRef) { r.EvidenceKind = EvidenceKindWorkerTokenOpening },
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
	// And a bundle kind of that producer: a Verifier object cannot claim a Worker bundle, and none can omit it.
	for _, kind := range []EvidenceKind{EvidenceKindUnspecified, EvidenceKindWorkerTokenOpening, 3} {
		ref := goldenEvidenceRef()
		ref.EvidenceKind = kind
		if _, err := CanonicalObjectRefFrame(ref); err == nil {
			t.Fatalf("a Verifier object with evidence_kind %d must be rejected", kind)
		}
	}
}
