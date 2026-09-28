package ingress

import (
	"testing"

	"github.com/TrueOpen/nexus/internal/protofingerprint"
)

// TestNexusWireDescriptorFingerprint pins proto/nexus/v1 to the nexus.v1 package released in
// TrueOpen/wire v0.3.3 (release/packages.json lists it as frozen).
//
// Unlike hub/shared/task, proto/nexus/v1 is not produced by tools/mirror_wire.py: the wire copy is
// a comment-stripped stub and this repository keeps the documented IngressAPI contract. The two must
// still be field-for-field identical, so the value below is the fingerprint of the wire definition
// (computed by generating from the wire proto through tools/mirror_wire.py's rewrite), not of
// whatever this repository happens to contain. Moving to a new wire release means re-deriving it
// the same way and updating both this value and the proto.
func TestNexusWireDescriptorFingerprint(t *testing.T) {
	got, summary := protofingerprint.Descriptor("nexus/v1/")
	const want = "26633e10622327717a43e63d72f9618cfc2b1e01be1d82ab11c423212711e959"
	if got != want {
		t.Fatalf("nexus.v1 descriptor fingerprint = %s, want %s (messages=%d enums=%d methods=%d)", got, want, summary.Messages, summary.Enums, summary.Methods)
	}
}
