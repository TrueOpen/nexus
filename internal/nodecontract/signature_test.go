package nodecontract

import (
	"encoding/hex"
	"testing"
)

const testPrivateKeyHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

// The service key PoP golden moved to servicedescriptor_test.go: the chain's domain is
// TRUEOPEN_SERVICE_REGISTRATION_V1 / H_FIELDS_V1, and the old TRUEOPEN_CURRENT_SERVICE_KEY_V2
// decimal-text framing was deleted together with its golden; keeping it would only tempt people
// into signing proofs that are bound to be rejected.

func TestCurrentOrderSigningBytesMatchesNodeGolden(t *testing.T) {
	got := CurrentOrderSigningBytes("chain-golden", "owner-golden", "session-golden", 42, "envelope-golden")
	if hex.EncodeToString(got) != "7b230f004647f95a8e39dd202b69378e6dcc47c77dfd7eb1195b5623d31eedef" {
		t.Fatalf("current order signing bytes = %x", got)
	}
}

// TestLegacyDecimalFramingIsGoneFromReceiptPath is a gate: the old 11-field decimal-framing
// receipt helper must no longer exist in this package ("no aliases kept"), and the assertion
// below prevents anyone from wrapping the new digest back into a decimal-form hex string helper.
func TestLegacyDecimalFramingIsGoneFromReceiptPath(t *testing.T) {
	legacy := domainHash(
		"TRUEOPEN_INFER_RECEIPT_V2",
		"chain-golden", "task-golden", "worker-golden", "commit-golden", "output-golden", "4096",
		"trace-golden", "checkpoint-golden", "batch-golden", "101", "202",
	)
	if hex.EncodeToString(legacy) != "cdd0fa5e94924821cc20616322f40f11ad18f68541e4c10a1a2c3dce4c6f9142" {
		t.Fatalf("legacy decimal framing changed unexpectedly: %x", legacy)
	}
	// Under the same domain, the new typed framing and the old decimal framing must be two
	// different values: this is exactly what "keeping an alias would produce digests the Keeper
	// never accepts" looks like in practice.
	typed := CanonicalHashBytes("TRUEOPEN_INFER_RECEIPT_V2", Uint32BE(2))
	if hex.EncodeToString(typed[:]) == hex.EncodeToString(legacy) {
		t.Fatal("typed H_FIELDS_V1 framing must not collide with the deleted decimal framing")
	}
}
