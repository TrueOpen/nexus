package nodecontract

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

// task_domains_v1.json is read from the wire module pinned in go.mod rather than from a copy in this
// repository: a copy once went stale while this repository's implementation and the stale copy
// confirmed each other, and receipts were then bound to be rejected on chain.
// Every vector carries the full preimage_hex, so aligning the framing needs no guessing at digests.
const taskDomainsFixture = "testdata/v1/task/task_domains_v1.json"

type goldenField struct {
	Name     string        `json:"name"`
	Type     string        `json:"type"`
	Value    uint64        `json:"value"`
	Hex      string        `json:"hex"`
	UTF8     string        `json:"utf8"`
	Bech32   string        `json:"bech32"`
	Signed   int32         `json:"signed"`
	Bool     bool          `json:"bool"`
	Present  bool          `json:"present"`
	FrameHex string        `json:"frame_hex"`
	Fields   []goldenField `json:"fields"`
}

type goldenTamper struct {
	Name      string `json:"name"`
	Field     int    `json:"field"`
	Byte      int    `json:"byte"`
	Bit       uint   `json:"bit"`
	DigestHex string `json:"digest_hex"`
}

type goldenOverride struct {
	Field int         `json:"field"`
	Value goldenField `json:"value"`
}

type goldenReplay struct {
	Name      string           `json:"name"`
	Reason    string           `json:"reason"`
	Overrides []goldenOverride `json:"overrides"`
	DigestHex string           `json:"digest_hex"`
}

type goldenVector struct {
	Name                 string         `json:"name"`
	Domain               string         `json:"domain"`
	Framing              string         `json:"framing"`
	RejectedByProduction string         `json:"rejected_by_production"`
	Fields               []goldenField  `json:"fields"`
	PreimageHex          string         `json:"preimage_hex"`
	DigestHex            string         `json:"digest_hex"`
	Tamper               []goldenTamper `json:"tamper"`
	Replay               []goldenReplay `json:"replay"`
}

type goldenFixture struct {
	Schema  string         `json:"schema"`
	Vectors []goldenVector `json:"vectors"`
}

func loadTaskDomainsFixture(t *testing.T) goldenFixture {
	t.Helper()
	raw := wirefixture.ReadFile(t, taskDomainsFixture)
	var fixture goldenFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if fixture.Schema != "trueopen.task.domains.v1" || len(fixture.Vectors) == 0 {
		t.Fatalf("unexpected fixture schema %q with %d vectors", fixture.Schema, len(fixture.Vectors))
	}
	return fixture
}

// encodeGoldenField encodes one fixture field description with this package's H_FIELDS_V1
// primitives. It deliberately uses only the exported primitives: aligning the vectors thereby
// also proves the primitives themselves.
func encodeGoldenField(t *testing.T, field goldenField) []byte {
	t.Helper()
	switch field.Type {
	case "uint32":
		return Uint32BE(uint32(field.Value))
	case "uint64":
		return Uint64BE(field.Value)
	case "enum":
		return EnumBE(uint32(field.Value))
	case "int32":
		// Signed integers use the two's-complement int32_be of H_FIELDS_V1, not decimal text.
		return Int32BE(field.Signed)
	case "bool":
		return BoolByte(field.Bool)
	case "bytes":
		raw, err := hex.DecodeString(field.Hex)
		if err != nil {
			t.Fatalf("field %s: decode hex: %v", field.Name, err)
		}
		return raw
	case "string":
		encoded, err := CanonicalUTF8Field(field.Name, field.UTF8)
		if err != nil {
			t.Fatalf("field %s: %v", field.Name, err)
		}
		return encoded
	case "address":
		// The fixture records both the bech32 text and the address codec bytes so cross-language
		// implementations can verify their own decoding. Only the codec bytes
		// enter the preimage.
		encoded, err := CanonicalOperatorAddressBytes(field.Name, field.Bech32)
		if err != nil {
			t.Fatalf("field %s: %v", field.Name, err)
		}
		if got := hex.EncodeToString(encoded); got != field.Hex {
			t.Fatalf("field %s: address codec bytes = %s, want %s", field.Name, got, field.Hex)
		}
		return encoded
	case "frame":
		nested := make([][]byte, 0, len(field.Fields))
		for _, sub := range field.Fields {
			nested = append(nested, encodeGoldenField(t, sub))
		}
		return CanonicalFrameBytes(nested...)
	case "optional":
		// OPTIONAL_V1: absent is the single byte 0x00; present is
		// 0x01 || FRAME(value). "Present but empty" and "absent" deliberately encode differently.
		if !field.Present {
			if len(field.Fields) != 0 {
				t.Fatalf("field %s: absent optional must carry no value", field.Name)
			}
			return []byte{0}
		}
		if len(field.Fields) != 1 {
			t.Fatalf("field %s: present optional must carry exactly one value", field.Name)
		}
		return append([]byte{1}, CanonicalFrameBytes(encodeGoldenField(t, field.Fields[0]))...)
	case "oneof":
		// ONEOF_V1: uint32_be(tag) || FRAME(fields of the selected branch). The tag keeps
		// different "present but empty" branches distinguishable from each other.
		branch := make([][]byte, 0, len(field.Fields))
		for _, sub := range field.Fields {
			branch = append(branch, encodeGoldenField(t, sub))
		}
		encoded := append(Uint32BE(uint32(field.Value)), CanonicalFrameBytes(branch...)...)
		if field.FrameHex != "" {
			if got := hex.EncodeToString(encoded); got != field.FrameHex {
				t.Fatalf("field %s: oneof frame = %s, want %s", field.Name, got, field.FrameHex)
			}
		}
		return encoded
	default:
		t.Fatalf("field %s: unsupported fixture type %q", field.Name, field.Type)
		return nil
	}
}

func encodeGoldenFields(t *testing.T, fields []goldenField) [][]byte {
	t.Helper()
	encoded := make([][]byte, 0, len(fields))
	for _, field := range fields {
		encoded = append(encoded, encodeGoldenField(t, field))
	}
	return encoded
}

// TestTaskDomainsGoldenPreimage aligns the preimage and digest of every vector byte for byte.
// It covers uint32/uint64 big-endian, raw bytes, strict UTF-8 strings (including multi-byte),
// enum uint32 big-endian, address codec bytes and nested frames.
func TestTaskDomainsGoldenPreimage(t *testing.T) {
	fixture := loadTaskDomainsFixture(t)
	for _, vector := range fixture.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			if vector.Framing != "H_FIELDS_V1" {
				t.Fatalf("framing = %q, want H_FIELDS_V1", vector.Framing)
			}
			fields := encodeGoldenFields(t, vector.Fields)
			preimage := CanonicalFramePreimage(vector.Domain, fields...)
			if got := hex.EncodeToString(preimage); got != vector.PreimageHex {
				t.Fatalf("preimage = %s, want %s", got, vector.PreimageHex)
			}
			digest := CanonicalHashBytes(vector.Domain, fields...)
			if got := hex.EncodeToString(digest[:]); got != vector.DigestHex {
				t.Fatalf("digest = %s, want %s", got, vector.DigestHex)
			}
		})
	}
}

// TestTaskDomainsGoldenTamper flips a single bit in each framed field and asserts the digest
// matches what the fixture records. Field-level framing misalignment surfaces here rather than
// when the Keeper rejects the signature.
func TestTaskDomainsGoldenTamper(t *testing.T) {
	fixture := loadTaskDomainsFixture(t)
	for _, vector := range fixture.Vectors {
		for _, tamper := range vector.Tamper {
			t.Run(vector.Name+"/"+tamper.Name, func(t *testing.T) {
				fields := encodeGoldenFields(t, vector.Fields)
				if tamper.Field < 0 || tamper.Field >= len(fields) {
					t.Fatalf("tamper field index %d out of range", tamper.Field)
				}
				target := append([]byte(nil), fields[tamper.Field]...)
				index := tamper.Byte
				if index < 0 {
					index += len(target)
				}
				if index < 0 || index >= len(target) {
					t.Fatalf("tamper byte index %d out of range for %d bytes", tamper.Byte, len(target))
				}
				target[index] ^= 1 << tamper.Bit
				fields[tamper.Field] = target
				digest := CanonicalHashBytes(vector.Domain, fields...)
				if got := hex.EncodeToString(digest[:]); got != tamper.DigestHex {
					t.Fatalf("tampered digest = %s, want %s", got, tamper.DigestHex)
				}
				if tamper.DigestHex == vector.DigestHex {
					t.Fatal("tampered digest must differ from the golden digest")
				}
			})
		}
	}
}

// TestTaskDomainsGoldenReplay covers cross-chain / cross-task / cross-operator /
// cross-duty / cross-round, stale nonce, extended expiry, schema_version=2, non-ASCII,
// zero-hash substitution, reorder and duplicate: each must produce the distinct digest the
// fixture records.
func TestTaskDomainsGoldenReplay(t *testing.T) {
	fixture := loadTaskDomainsFixture(t)
	for _, vector := range fixture.Vectors {
		for _, replay := range vector.Replay {
			t.Run(vector.Name+"/"+replay.Name, func(t *testing.T) {
				fields := encodeGoldenFields(t, vector.Fields)
				for _, override := range replay.Overrides {
					if override.Field < 0 || override.Field >= len(fields) {
						t.Fatalf("replay override field index %d out of range", override.Field)
					}
					fields[override.Field] = encodeGoldenField(t, override.Value)
				}
				digest := CanonicalHashBytes(vector.Domain, fields...)
				if got := hex.EncodeToString(digest[:]); got != replay.DigestHex {
					t.Fatalf("replay digest = %s, want %s (%s)", got, replay.DigestHex, replay.Reason)
				}
				if replay.DigestHex == vector.DigestHex {
					t.Fatalf("replay %s must not reproduce the golden digest", replay.Name)
				}
			})
		}
	}
}

// goldenEvidenceCommitments restores the field values of the infer_evidence_commitments_v1_*
// vectors into production types for value-level production binding (feeding real field values
// rather than copying the framing).
func goldenEvidenceCommitments(t *testing.T, vector goldenVector) []*taskv1.EvidenceCommitmentV1 {
	t.Helper()
	if len(vector.Fields) == 0 || vector.Fields[0].Name != "count" {
		t.Fatalf("vector %s: first field must be count", vector.Name)
	}
	count := int(vector.Fields[0].Value)
	// The top level is count plus one commitments nested frame; the elements live in the nested
	// frame, preceded by another element_count. This is the shape of a repeated value on chain.
	if len(vector.Fields) != 2 || vector.Fields[1].Type != "frame" {
		t.Fatalf("vector %s: top level must be count plus one commitments nested frame", vector.Name)
	}
	nested := vector.Fields[1].Fields
	if len(nested) == 0 || nested[0].Name != "element_count" || int(nested[0].Value) != count {
		t.Fatalf("vector %s: first field of the nested frame must be an element_count equal to count", vector.Name)
	}
	elements := nested[1:]
	if len(elements) != count {
		t.Fatalf("vector %s: count %d does not match %d element frames", vector.Name, count, len(elements))
	}
	items := make([]*taskv1.EvidenceCommitmentV1, 0, count)
	for _, field := range elements {
		if field.Type != "frame" || len(field.Fields) != 3 {
			t.Fatalf("vector %s: element %s must be a 3-field frame", vector.Name, field.Name)
		}
		hashOrRoot, err := hex.DecodeString(field.Fields[1].Hex)
		if err != nil {
			t.Fatalf("vector %s: decode evidence_hash_or_root: %v", vector.Name, err)
		}
		items = append(items, &taskv1.EvidenceCommitmentV1{
			EvidenceKind:       sharedv1.EvidenceKind(field.Fields[0].Value),
			EvidenceHashOrRoot: hashOrRoot,
			EncodedSizeBytes:   field.Fields[2].Value,
		})
	}
	return items
}

// TestEvidenceCommitmentsHashGoldenBinding is the value-level production binding: feed the
// fixture's field values to the production derivation and compare digests byte for byte; vectors
// marked rejected_by_production must return an error rather than silently reorder.
func TestEvidenceCommitmentsHashGoldenBinding(t *testing.T) {
	fixture := loadTaskDomainsFixture(t)
	covered := 0
	for _, vector := range fixture.Vectors {
		if vector.Domain != DomainInferEvidenceCommitmentsV1 {
			continue
		}
		covered++
		t.Run(vector.Name, func(t *testing.T) {
			items := goldenEvidenceCommitments(t, vector)
			digest, err := EvidenceCommitmentsHash(items)
			if vector.RejectedByProduction != "" {
				if err == nil {
					t.Fatalf("EvidenceCommitmentsHash must fail: %s", vector.RejectedByProduction)
				}
				return
			}
			if err != nil {
				t.Fatalf("EvidenceCommitmentsHash: %v", err)
			}
			if got := hex.EncodeToString(digest[:]); got != vector.DigestHex {
				t.Fatalf("digest = %s, want %s", got, vector.DigestHex)
			}
			for i, item := range items {
				frame, err := CanonicalEvidenceCommitmentFrameV1(item)
				if err != nil {
					t.Fatalf("element %d frame: %v", i, err)
				}
				if len(frame) != evidenceCommitmentFrameBytesV1 {
					t.Fatalf("element %d frame is %d bytes, want %d", i, len(frame), evidenceCommitmentFrameBytesV1)
				}
			}
		})
	}
	if covered != 4 {
		t.Fatalf("expected 4 evidence-commitment vectors, saw %d", covered)
	}
}

// TestEvidenceCommitmentsHashEmptyIsFullyDefined pins the two easiest pitfalls of evidence_commitments_hash:
// an empty list has a definite digest (not 32 zero bytes), and nil and [] share the same digest.
func TestEvidenceCommitmentsHashEmptyIsFullyDefined(t *testing.T) {
	const wantEmpty = "f029302b7f33dd77ad8e5217897a4e8386bf321dde9a510c1c6a287e408b9873"
	nilDigest, err := EvidenceCommitmentsHash(nil)
	if err != nil {
		t.Fatalf("nil list: %v", err)
	}
	emptyDigest, err := EvidenceCommitmentsHash([]*taskv1.EvidenceCommitmentV1{})
	if err != nil {
		t.Fatalf("empty list: %v", err)
	}
	if hex.EncodeToString(nilDigest[:]) != wantEmpty || nilDigest != emptyDigest {
		t.Fatalf("empty-list digest = %s / %s, want %s for both",
			hex.EncodeToString(nilDigest[:]), hex.EncodeToString(emptyDigest[:]), wantEmpty)
	}
	if nilDigest == [32]byte{} {
		t.Fatal("empty-list digest must never be 32 zero bytes")
	}
}
