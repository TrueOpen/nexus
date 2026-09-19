package taskdata

// Strict parsing and bundle hash of EvidenceBundleManifestV1 (Data Plane and Evidence
// Transport §2, §2.1).
//
// Nexus's stance on the manifest: it is just an EVIDENCE_MANIFEST data object. Nexus stores
// and returns the exact manifest bytes without re-serializing; it does not interpret
// artifact IDs, parse model evidence semantics or recompute model-internal roots. Only three
// things happen here: compute the bundle hash over the received bytes, confirm those bytes
// are canonical JSON, and extract artifact hash/size for Finalize to check one by one.

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/TrueOpen/nexus/internal/nodecontract"
)

// DomainEvidenceBundleManifest is the H_V1 signing domain of the manifest.
const DomainEvidenceBundleManifest = "TRUEOPEN_EVIDENCE_BUNDLE_MANIFEST_V1"

// EvidenceBundleManifestVersionV1 is the only valid manifest_version value.
const EvidenceBundleManifestVersionV1 uint32 = 1

// maxManifestStringBytes gives bounded strings a structural upper limit. The contract says
// bounded without a number, so a loose value is used: it guards against stuffing a whole
// artifact into an id, not defining a length on behalf of the protocol.
const maxManifestStringBytes = 256

// frameV1Prefix is the fixed H_V1 prefix (wire registry framing.json).
const frameV1Prefix = "TRUEOPEN_FRAME_V1"

// EvidenceBundleHash is H_V1(TRUEOPEN_EVIDENCE_BUNDLE_MANIFEST_V1, exact manifest bytes):
//
//	preimage = ascii("TRUEOPEN_FRAME_V1") || u32_be(len(domain)) || domain
//	           || u64_be(len(payload)) || payload
//
// payload is the **raw bytes as received**. Parsing and re-serializing would yield a
// different bundle; callers must pass the bytes through unchanged.
func EvidenceBundleHash(payload []byte) [32]byte {
	domain := []byte(DomainEvidenceBundleManifest)
	preimage := make([]byte, 0, len(frameV1Prefix)+4+len(domain)+8+len(payload))
	preimage = append(preimage, frameV1Prefix...)
	preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(domain)))
	preimage = append(preimage, domain...)
	preimage = binary.BigEndian.AppendUint64(preimage, uint64(len(payload)))
	preimage = append(preimage, payload...)
	return sha256.Sum256(preimage)
}

// EvidenceArtifact is one artifact entry in the manifest. artifact_id is only an opaque
// unique key within the manifest and must not be treated as a filesystem path.
type EvidenceArtifact struct {
	ArtifactID  string
	ContentHash string
	SizeBytes   uint64
}

// EvidenceBundleManifest is the parsed EvidenceBundleManifestV1.
type EvidenceBundleManifest struct {
	ManifestVersion    uint32
	ChainID            string
	TaskID             string
	TaskHash           string
	EvidenceSchemaHash string
	ProducerKind       EvidenceProducerKind
	ProducerOperator   string
	VerifyRound        uint32
	// EvidenceKind is optional; its values are defined by the profile adapter and not interpreted by Nexus.
	EvidenceKind string
	// SchemaMetadata is optional: the exact bytes of a canonical JSON object.
	SchemaMetadata string
	Artifacts      []EvidenceArtifact

	// ArtifactTotalSizeBytes is the checked sum of all artifact sizes; it goes into the storage confirmation.
	ArtifactTotalSizeBytes uint64
	// Raw is the exact bytes received: the bundle hash and forwarding must use it, never a re-serialized result.
	Raw string
}

// BundleHash is this manifest's evidence_bundle_hash (hex).
func (m EvidenceBundleManifest) BundleHash() string {
	digest := EvidenceBundleHash([]byte(m.Raw))
	return hex.EncodeToString(digest[:])
}

type manifestJSON struct {
	Artifacts          []artifactJSON  `json:"artifacts"`
	ChainID            *string         `json:"chain_id"`
	EvidenceKind       *string         `json:"evidence_kind"`
	EvidenceSchemaHash *string         `json:"evidence_schema_hash"`
	ManifestVersion    *json.Number    `json:"manifest_version"`
	ProducerKind       *string         `json:"producer_kind"`
	ProducerOperator   *string         `json:"producer_operator"`
	SchemaMetadata     json.RawMessage `json:"schema_metadata"`
	TaskHash           *string         `json:"task_hash"`
	TaskID             *string         `json:"task_id"`
	VerifyRound        *json.Number    `json:"verify_round"`
}

type artifactJSON struct {
	ArtifactID  *string `json:"artifact_id"`
	ContentHash *string `json:"content_hash"`
	SizeBytes   *string `json:"size_bytes"`
}

// ParseEvidenceBundleManifest strictly parses a canonical JSON manifest.
//
// There is a single strictness criterion: re-encoding the parse result under the canonical
// rules must equal the received bytes byte for byte. Whitespace, key order, non-shortest
// escapes, duplicate keys and number spellings are all caught by this one rule, so no
// per-variant check is needed; missing one would admit a manifest for which nobody else
// can compute the same hash.
func ParseEvidenceBundleManifest(payload []byte) (EvidenceBundleManifest, error) {
	if !utf8.Valid(payload) {
		return EvidenceBundleManifest{}, fmt.Errorf("%w: manifest is not valid UTF-8", ErrMalformed)
	}
	if strings.HasPrefix(string(payload), "\ufeff") {
		return EvidenceBundleManifest{}, fmt.Errorf("%w: manifest carries a BOM", ErrMalformed)
	}

	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	var raw manifestJSON
	if err := decoder.Decode(&raw); err != nil {
		return EvidenceBundleManifest{}, fmt.Errorf("%w: manifest json: %v", ErrMalformed, err)
	}
	if decoder.More() {
		return EvidenceBundleManifest{}, fmt.Errorf("%w: trailing document after manifest", ErrMalformed)
	}

	manifest, err := manifestFromJSON(raw)
	if err != nil {
		return EvidenceBundleManifest{}, err
	}
	canonical, err := manifest.canonicalBytes()
	if err != nil {
		return EvidenceBundleManifest{}, err
	}
	if canonical != string(payload) {
		return EvidenceBundleManifest{}, fmt.Errorf("%w: manifest is not canonical JSON", ErrMalformed)
	}
	manifest.Raw = string(payload)
	return manifest, nil
}

func manifestFromJSON(raw manifestJSON) (EvidenceBundleManifest, error) {
	var manifest EvidenceBundleManifest
	var err error

	if manifest.ManifestVersion, err = manifestUint32("manifest_version", raw.ManifestVersion); err != nil {
		return EvidenceBundleManifest{}, err
	}
	if manifest.ManifestVersion != EvidenceBundleManifestVersionV1 {
		return EvidenceBundleManifest{}, fmt.Errorf("%w: manifest_version %d", ErrMalformed, manifest.ManifestVersion)
	}
	if manifest.ChainID, err = manifestString("chain_id", raw.ChainID, false); err != nil {
		return EvidenceBundleManifest{}, err
	}
	if manifest.TaskID, err = manifestHash32("task_id", raw.TaskID); err != nil {
		return EvidenceBundleManifest{}, err
	}
	if manifest.TaskHash, err = manifestHash32("task_hash", raw.TaskHash); err != nil {
		return EvidenceBundleManifest{}, err
	}
	if manifest.EvidenceSchemaHash, err = manifestHash32("evidence_schema_hash", raw.EvidenceSchemaHash); err != nil {
		return EvidenceBundleManifest{}, err
	}

	producerKind, err := manifestString("producer_kind", raw.ProducerKind, false)
	if err != nil {
		return EvidenceBundleManifest{}, err
	}
	switch producerKind {
	case "WORKER":
		manifest.ProducerKind = EvidenceProducerWorker
	case "VERIFIER":
		manifest.ProducerKind = EvidenceProducerVerifier
	default:
		return EvidenceBundleManifest{}, fmt.Errorf("%w: producer_kind %q", ErrMalformed, producerKind)
	}

	// producer_operator must be the stable operator that produced the bundle, never a
	// service address. Only the address shape can be checked here; whether it is the
	// producer of this round is decided by Finalize against on-chain authorization.
	if manifest.ProducerOperator, err = manifestString("producer_operator", raw.ProducerOperator, false); err != nil {
		return EvidenceBundleManifest{}, err
	}
	if _, err := nodecontract.CanonicalOperatorAddressBytes("producer_operator", manifest.ProducerOperator); err != nil {
		return EvidenceBundleManifest{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	if manifest.VerifyRound, err = manifestUint32("verify_round", raw.VerifyRound); err != nil {
		return EvidenceBundleManifest{}, err
	}
	// normal=1, challenge=2: 0 is not a valid round, and a Worker manifest is always 1.
	if manifest.VerifyRound == 0 {
		return EvidenceBundleManifest{}, fmt.Errorf("%w: verify_round must be positive", ErrMalformed)
	}
	if manifest.ProducerKind == EvidenceProducerWorker && manifest.VerifyRound != 1 {
		return EvidenceBundleManifest{}, fmt.Errorf("%w: worker manifest verify_round %d", ErrMalformed, manifest.VerifyRound)
	}

	if raw.EvidenceKind != nil {
		if manifest.EvidenceKind, err = manifestString("evidence_kind", raw.EvidenceKind, false); err != nil {
			return EvidenceBundleManifest{}, err
		}
	}
	if raw.SchemaMetadata != nil {
		metadata, err := canonicalJSONValue(raw.SchemaMetadata)
		if err != nil {
			return EvidenceBundleManifest{}, fmt.Errorf("%w: schema_metadata: %v", ErrMalformed, err)
		}
		if !strings.HasPrefix(metadata, "{") {
			return EvidenceBundleManifest{}, fmt.Errorf("%w: schema_metadata must be a JSON object", ErrMalformed)
		}
		manifest.SchemaMetadata = metadata
	}

	if len(raw.Artifacts) == 0 {
		return EvidenceBundleManifest{}, fmt.Errorf("%w: manifest carries no artifacts", ErrMalformed)
	}
	previousID := ""
	for i, entry := range raw.Artifacts {
		artifact := EvidenceArtifact{}
		if artifact.ArtifactID, err = manifestString("artifact_id", entry.ArtifactID, false); err != nil {
			return EvidenceBundleManifest{}, err
		}
		if artifact.ContentHash, err = manifestHash32("content_hash", entry.ContentHash); err != nil {
			return EvidenceBundleManifest{}, err
		}
		if artifact.SizeBytes, err = manifestUint64String("size_bytes", entry.SizeBytes); err != nil {
			return EvidenceBundleManifest{}, err
		}
		if artifact.SizeBytes == 0 {
			return EvidenceBundleManifest{}, fmt.Errorf("%w: artifact %q size_bytes is zero", ErrMalformed, artifact.ArtifactID)
		}
		// artifact_id is unique and in ascending UTF-8 byte order: the order is part of the manifest and the parser does not reorder.
		if i > 0 && artifact.ArtifactID <= previousID {
			return EvidenceBundleManifest{}, fmt.Errorf("%w: artifacts must ascend by artifact_id, %q after %q",
				ErrMalformed, artifact.ArtifactID, previousID)
		}
		previousID = artifact.ArtifactID
		if manifest.ArtifactTotalSizeBytes > math.MaxUint64-artifact.SizeBytes {
			return EvidenceBundleManifest{}, fmt.Errorf("%w: artifact_total_size_bytes overflows", ErrMalformed)
		}
		manifest.ArtifactTotalSizeBytes += artifact.SizeBytes
		manifest.Artifacts = append(manifest.Artifacts, artifact)
	}
	return manifest, nil
}

// canonicalBytes re-encodes per §2.1: object keys in ascending UTF-8 byte order, no
// whitespace, uint64 as a decimal string without leading zeros, uint32 as a JSON integer,
// Hash32 as 64 lowercase hex digits.
func (m EvidenceBundleManifest) canonicalBytes() (string, error) {
	var b strings.Builder
	b.WriteString(`{"artifacts":[`)
	for i, artifact := range m.Artifacts {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"artifact_id":`)
		b.WriteString(canonicalJSONString(artifact.ArtifactID))
		b.WriteString(`,"content_hash":`)
		b.WriteString(canonicalJSONString(artifact.ContentHash))
		b.WriteString(`,"size_bytes":"`)
		b.WriteString(strconv.FormatUint(artifact.SizeBytes, 10))
		b.WriteString(`"}`)
	}
	b.WriteString(`],"chain_id":`)
	b.WriteString(canonicalJSONString(m.ChainID))
	if m.EvidenceKind != "" {
		b.WriteString(`,"evidence_kind":`)
		b.WriteString(canonicalJSONString(m.EvidenceKind))
	}
	b.WriteString(`,"evidence_schema_hash":`)
	b.WriteString(canonicalJSONString(m.EvidenceSchemaHash))
	b.WriteString(`,"manifest_version":`)
	b.WriteString(strconv.FormatUint(uint64(m.ManifestVersion), 10))
	b.WriteString(`,"producer_kind":`)
	switch m.ProducerKind {
	case EvidenceProducerWorker:
		b.WriteString(`"WORKER"`)
	case EvidenceProducerVerifier:
		b.WriteString(`"VERIFIER"`)
	default:
		return "", fmt.Errorf("%w: producer_kind", ErrMalformed)
	}
	b.WriteString(`,"producer_operator":`)
	b.WriteString(canonicalJSONString(m.ProducerOperator))
	if m.SchemaMetadata != "" {
		b.WriteString(`,"schema_metadata":`)
		b.WriteString(m.SchemaMetadata)
	}
	b.WriteString(`,"task_hash":`)
	b.WriteString(canonicalJSONString(m.TaskHash))
	b.WriteString(`,"task_id":`)
	b.WriteString(canonicalJSONString(m.TaskID))
	b.WriteString(`,"verify_round":`)
	b.WriteString(strconv.FormatUint(uint64(m.VerifyRound), 10))
	b.WriteByte('}')
	return b.String(), nil
}

// canonicalJSONValue re-encodes an arbitrary JSON value into canonical form. The content
// of schema_metadata is defined by the model schema and not interpreted by Nexus, but it
// must be canonical too; otherwise the same semantics could have several byte forms and
// therefore several bundle hashes.
func canonicalJSONValue(raw json.RawMessage) (string, error) {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", err
	}
	if decoder.More() {
		return "", fmt.Errorf("trailing document")
	}
	var b strings.Builder
	if err := writeCanonicalJSON(&b, value); err != nil {
		return "", err
	}
	return b.String(), nil
}

func writeCanonicalJSON(b *strings.Builder, value any) error {
	switch v := value.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if v {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case json.Number:
		// Numbers are kept as-is: Go's JSON parser already rejects invalid spellings such
		// as leading zeros, and remaining differences (1 vs 1.0) are caught by the final
		// byte-for-byte comparison.
		b.WriteString(v.String())
	case string:
		b.WriteString(canonicalJSONString(v))
	case []any:
		b.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonicalJSON(b, item); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys) // Go string comparison is UTF-8 byte order
		b.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(canonicalJSONString(key))
			b.WriteByte(':')
			if err := writeCanonicalJSON(b, v[key]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("unsupported json value %T", value)
	}
	return nil
}

// canonicalJSONString is the "shortest valid JSON escaping" of §2.1: only " and \ and C0
// control characters are escaped, control characters preferring the single-character
// escapes. encoding/json additionally escapes < > & and U+2028/U+2029, which is not the
// shortest form, hence the hand-written version.
func canonicalJSONString(value string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func manifestString(field string, value *string, allowEmpty bool) (string, error) {
	if value == nil {
		return "", fmt.Errorf("%w: manifest %s is missing", ErrMalformed, field)
	}
	if !allowEmpty && *value == "" {
		return "", fmt.Errorf("%w: manifest %s is empty", ErrMalformed, field)
	}
	if len(*value) > maxManifestStringBytes {
		return "", fmt.Errorf("%w: manifest %s exceeds %d bytes", ErrMalformed, field, maxManifestStringBytes)
	}
	return *value, nil
}

func manifestHash32(field string, value *string) (string, error) {
	text, err := manifestString(field, value, false)
	if err != nil {
		return "", err
	}
	if !canonicalSHA256(text) {
		return "", fmt.Errorf("%w: manifest %s is not 64 lowercase hex", ErrMalformed, field)
	}
	return text, nil
}

func manifestUint32(field string, value *json.Number) (uint32, error) {
	if value == nil {
		return 0, fmt.Errorf("%w: manifest %s is missing", ErrMalformed, field)
	}
	parsed, err := strconv.ParseUint(value.String(), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%w: manifest %s is not a uint32 integer: %v", ErrMalformed, field, err)
	}
	return uint32(parsed), nil
}

// manifestUint64String reads a §2.1 uint64: a decimal string without leading zeros, not a JSON number.
func manifestUint64String(field string, value *string) (uint64, error) {
	if value == nil {
		return 0, fmt.Errorf("%w: manifest %s is missing", ErrMalformed, field)
	}
	text := *value
	if text == "" {
		return 0, fmt.Errorf("%w: manifest %s is empty", ErrMalformed, field)
	}
	if len(text) > 1 && text[0] == '0' {
		return 0, fmt.Errorf("%w: manifest %s has a leading zero", ErrMalformed, field)
	}
	parsed, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: manifest %s is not a uint64 decimal string: %v", ErrMalformed, field, err)
	}
	return parsed, nil
}

// matchManifestToRef confirms the Task identity and producer the manifest claims match the
// object ref it is placed in. The two are signed and transported separately; not comparing
// them would allow the same manifest bytes to be attached to another Task or producer.
func matchManifestToRef(manifest EvidenceBundleManifest, ref ObjectRef) error {
	switch {
	case manifest.TaskHash != ref.TaskHash:
		return fmt.Errorf("%w: manifest task_hash %s, ref %s", ErrMalformed, manifest.TaskHash, ref.TaskHash)
	case manifest.TaskID != ref.TaskID:
		return fmt.Errorf("%w: manifest task_id %s, ref %s", ErrMalformed, manifest.TaskID, ref.TaskID)
	case manifest.ProducerKind != ref.EvidenceProducerKind:
		return fmt.Errorf("%w: manifest producer_kind %d, ref %d", ErrMalformed, manifest.ProducerKind, ref.EvidenceProducerKind)
	case manifest.VerifyRound != ref.VerifyRound:
		return fmt.Errorf("%w: manifest verify_round %d, ref %d", ErrMalformed, manifest.VerifyRound, ref.VerifyRound)
	case manifest.ProducerOperator != ref.ProducerOperator:
		return fmt.Errorf("%w: manifest producer_operator %s, ref %s", ErrMalformed, manifest.ProducerOperator, ref.ProducerOperator)
	}
	return nil
}
