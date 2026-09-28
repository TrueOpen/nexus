package ingress

import (
	"context"
	"testing"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
)

// TestOpenTaskHeaderAcceptsSequenceZero covers the other half of the same check: the data-plane
// OpenTask header previously had an identical `== 0` check, and the two must stay in sync.
func TestOpenTaskHeaderAcceptsSequenceZero(t *testing.T) {
	sg := mustSigner(t, testKeyHex)
	s := &service{}
	header := &nexusv1.OpenTaskHeader{
		SessionId: testSessionID("sess-header-zero"), OrderSequence: 0,
		UserAddress: sg.Address(),
	}
	// Only assert "not rejected as malformed because of order_sequence=0": the other required fields are
	// deliberately left empty here, so it still fails -- but the reason must not be the sequence.
	_, _, err := s.validateOpenTaskHeader(context.Background(), header)
	if err == nil {
		t.Skip("header validation passed, so the other required fields are not needed either; this case is no longer meaningful")
	}
	// Swap order_sequence for an "obviously valid" non-zero value; the error must be exactly the same --
	// if it differs, 0 is still being singled out.
	header.OrderSequence = 7
	_, _, other := s.validateOpenTaskHeader(context.Background(), header)
	if other == nil || err.Error() != other.Error() {
		t.Fatalf("order_sequence=0 and =7 validate differently, so 0 is still treated as unset:\n 0 -> %v\n 7 -> %v", err, other)
	}
}
