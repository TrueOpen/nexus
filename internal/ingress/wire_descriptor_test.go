package ingress

import (
	"testing"

	"github.com/TrueOpen/nexus/internal/protofingerprint"
)

// TestNexusWireDescriptorFingerprint pins proto/nexus/v1 to the nexus.v1 package of
// the TrueOpen/wire version pinned in go.mod.
//
// proto/nexus/v1 is mirrored from wire by tools/mirror_wire.py like hub/shared/task, so the value
// below is the fingerprint of the wire definition after the mirror's go_package rewrite. Moving to a
// new wire release means re-running the mirror and updating this value.
func TestNexusWireDescriptorFingerprint(t *testing.T) {
	got, summary := protofingerprint.Descriptor("nexus/v1/")
	const want = "9a57cf608f7b76d9cb6728140628e266b179342d5506a31e3765f9761956d7a0"
	if got != want {
		t.Fatalf("nexus.v1 descriptor fingerprint = %s, want %s (messages=%d enums=%d methods=%d)", got, want, summary.Messages, summary.Enums, summary.Methods)
	}
}
