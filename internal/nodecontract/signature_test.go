package nodecontract

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"
)

// task_data_plane_v1_golden.json covers only the pre-freeze domainHash(domain, fields ...string)
// helpers not registered in §1.4 (uint64 decimal-text framing). The infer_receipt vectors were
// deleted together with the old preimage; the vectors for the new form live in
// testdata/task_domains_v1.json (H_FIELDS_V1, see hfields_golden_test.go).
type taskDataPlaneGolden struct {
	SchemaVersion  string `json:"schema_version"`
	SigningVectors []struct {
		Name                    string   `json:"name"`
		Fields                  []string `json:"fields"`
		ExpectedSigningBytesHex string   `json:"expected_signing_bytes_hex"`
	} `json:"signing_vectors"`
}

func TestTaskDataPlaneV1SigningGolden(t *testing.T) {
	raw, err := os.ReadFile("testdata/task_data_plane_v1_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture taskDataPlaneGolden
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.SchemaVersion != "trueopen-task-data-plane-golden-v1" {
		t.Fatalf("schema version = %q", fixture.SchemaVersion)
	}
	for _, vector := range fixture.SigningVectors {
		vector := vector
		t.Run(vector.Name, func(t *testing.T) {
			got := signingBytesFromGolden(t, vector.Name, vector.Fields)
			if hex.EncodeToString(got) != vector.ExpectedSigningBytesHex {
				t.Fatalf("signing bytes = %x, want %s", got, vector.ExpectedSigningBytesHex)
			}
		})
	}
}

func signingBytesFromGolden(t *testing.T, name string, fields []string) []byte {
	t.Helper()
	switch name {
	case "order":
		return OrderSigningBytes(fields[0], fields[1], fields[2], goldenUint64(t, fields[3]), fields[4])
	case "assign_builder":
		return AssignBuilderSigningBytes(fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], goldenUint64(t, fields[6]))
	case "worker_handraise":
		return WorkerHandraiseSigningBytes(fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], goldenUint64(t, fields[6]), fields[7])
	case "open_verify_builder":
		return OpenVerifyBuilderSigningBytes(fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], goldenUint64(t, fields[6]))
	case "verifier_handraise":
		return VerifierHandraiseSigningBytes(fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6], goldenUint64(t, fields[7]))
	default:
		t.Fatalf("unsupported signing vector %q", name)
		return nil
	}
}

func goldenUint64(t *testing.T, value string) uint64 {
	t.Helper()
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

const testPrivateKeyHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

// The service key PoP golden moved to servicedescriptor_test.go: the frozen contract's domain is
// TRUEOPEN_SERVICE_REGISTRATION_V1 / H_FIELDS_V1, and the old TRUEOPEN_CURRENT_SERVICE_KEY_V2
// decimal-text framing was deleted together with its golden; keeping it would only tempt people
// into signing proofs that are bound to be rejected.

func TestCurrentOrderSigningBytesMatchesNodeGolden(t *testing.T) {
	got := CurrentOrderSigningBytes("chain-golden", "owner-golden", "session-golden", 42, "envelope-golden")
	if hex.EncodeToString(got) != "7b230f004647f95a8e39dd202b69378e6dcc47c77dfd7eb1195b5623d31eedef" {
		t.Fatalf("current order signing bytes = %x", got)
	}
}

func TestCanonicalDomainsBindEveryField(t *testing.T) {
	base := AssignBuilderSigningBytes("chain", "task", "order", "set", "handraises", "builder", 1)
	changed := AssignBuilderSigningBytes("chain", "task", "order", "set", "handraises", "builder", 2)
	if string(base) == string(changed) {
		t.Fatal("builder rank did not change canonical bytes")
	}

	settlement := SettlementSigningBytes("chain", "settlement", "task", "PASS", "SETTLED_PASS", "payout", "fault", "root", 99)
	if string(base) == string(settlement) {
		t.Fatal("different domains produced identical bytes")
	}
}

// TestLegacyDecimalFramingIsGoneFromReceiptPath is a gate: the old 11-field decimal-framing
// receipt helper must no longer exist in this package ("no aliases kept").
// The gate works at compile time: signingBytesFromGolden no longer has an
// infer_receipt branch, and the assertion below prevents anyone from wrapping the new digest
// back into a decimal-form hex string helper.
func TestLegacyDecimalFramingIsGoneFromReceiptPath(t *testing.T) {
	legacy := domainHash(
		DomainInferReceiptV2,
		"chain-golden", "task-golden", "worker-golden", "commit-golden", "output-golden", "4096",
		"trace-golden", "checkpoint-golden", "batch-golden", "101", "202",
	)
	if hex.EncodeToString(legacy) != "cdd0fa5e94924821cc20616322f40f11ad18f68541e4c10a1a2c3dce4c6f9142" {
		t.Fatalf("legacy decimal framing changed unexpectedly: %x", legacy)
	}
	// Under the same domain, the new typed framing and the old decimal framing must be two
	// different values: this is exactly what "keeping an alias would produce digests the Keeper
	// never accepts" looks like in practice.
	typed := CanonicalHashBytes(DomainInferReceiptV2, Uint32BE(InferReceiptSchemaVersionV2))
	if hex.EncodeToString(typed[:]) == hex.EncodeToString(legacy) {
		t.Fatal("typed H_FIELDS_V1 framing must not collide with the deleted decimal framing")
	}
}
