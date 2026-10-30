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
	const want = "50e3b8f3c2a1c49927334fc11dfb5b6cb7fba6e3d2955430c9c5cf0c0f03a26d"
	if got != want {
		t.Fatalf("nexus.v1 descriptor fingerprint = %s, want %s (messages=%d enums=%d methods=%d)", got, want, summary.Messages, summary.Enums, summary.Methods)
	}
}
