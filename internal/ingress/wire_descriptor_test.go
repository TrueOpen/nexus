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
	const want = "ce3d25b9881074e827e9db5496a6ff2890a662236e81b841fcba9eb16a7387c2"
	if got != want {
		t.Fatalf("nexus.v1 descriptor fingerprint = %s, want %s (messages=%d enums=%d methods=%d)", got, want, summary.Messages, summary.Enums, summary.Methods)
	}
}
