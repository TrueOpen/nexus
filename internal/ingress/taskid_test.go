package ingress

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestDeriveTaskIDMatchesNodeNormativeVector(t *testing.T) {
	const sessionID = "abababababababababababababababababababababababababababababababab"
	got, err := deriveTaskID(sessionID, 42)
	if err != nil {
		t.Fatal(err)
	}
	const want = "0891a5c5704d4dff5671daab9b353f31c86f81ac53cf1b3c4ef5171322c19f50"
	if got != want {
		t.Fatalf("task id = %q, want %q", got, want)
	}
}

func TestDeriveTaskIDRejectsNonCanonicalSessionID(t *testing.T) {
	valid := "abababababababababababababababababababababababababababababababab"
	for _, sessionID := range []string{
		"session-golden-1",
		" " + valid,
		valid + " ",
		"AB" + valid[2:],
		"0x" + valid,
		valid[:62],
		valid + "ab",
	} {
		if _, err := deriveTaskID(sessionID, 42); err == nil {
			t.Fatalf("deriveTaskID accepted non-canonical session_id %q", sessionID)
		}
	}
}

func testSessionID(seed string) string {
	digest := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(digest[:])
}

func mustDeriveTaskID(t testing.TB, sessionID string, orderSequence uint64) string {
	t.Helper()
	taskID, err := deriveTaskID(sessionID, orderSequence)
	if err != nil {
		t.Fatal(err)
	}
	return taskID
}
