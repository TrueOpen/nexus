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
	const want = "29348c0302de81beb5e683e3d2e440c4cd92dc12ded1810fcdab5ac805a5f016"
	if got != want {
		t.Fatalf("nexus.v1 descriptor fingerprint = %s, want %s (messages=%d enums=%d methods=%d)", got, want, summary.Messages, summary.Enums, summary.Methods)
	}
}
