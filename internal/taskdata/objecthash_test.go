package taskdata

import (
	"strings"
	"testing"
)

// In a plaintext task every stored object's content hash is the protocol commitment itself.
func TestPlaintextContentHashesAreTheCommitments(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	if got := InputContentHash(hash); got != hash {
		t.Fatalf("InputContentHash = %s, want the input_hash", got)
	}
	if got := OutputContentHash(hash); got != hash {
		t.Fatalf("OutputContentHash = %s, want the output_hash", got)
	}
	if got := WorkerManifestContentHash(EvidenceCommitment{HashOrRoot: hash}); got != hash {
		t.Fatalf("WorkerManifestContentHash = %s, want the typed commitment", got)
	}
}
