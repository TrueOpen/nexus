package ingress

import (
	"testing"

	"github.com/TrueOpen/nexus/internal/protofingerprint"
)

// TestNexusWireDescriptorFingerprint pins proto/nexus/v1 to the nexus.v1 package of
// the TrueOpen/wire version pinned in go.mod.
//
// Unlike hub/shared/task, proto/nexus/v1 is not produced by tools/mirror_wire.py: the wire copy is
// a comment-stripped stub and this repository keeps the documented IngressAPI contract. The two must
// still be field-for-field identical, so the value below is the fingerprint of the wire definition
// (computed by generating from the wire proto through tools/mirror_wire.py's rewrite), not of
// whatever this repository happens to contain. Moving to a new wire release means re-deriving it
// the same way and updating both this value and the proto.
func TestNexusWireDescriptorFingerprint(t *testing.T) {
	got, summary := protofingerprint.Descriptor("nexus/v1/")
	const want = "85f08b3ac31c253c52abe54e94b5371e043d315cd8c9b0e512c1c355383329e1"
	if got != want {
		t.Fatalf("nexus.v1 descriptor fingerprint = %s, want %s (messages=%d enums=%d methods=%d)", got, want, summary.Messages, summary.Enums, summary.Methods)
	}
}
