package natsauth

import (
	"errors"
	"slices"
	"testing"
)

// §5.13 CORTEX row plus the three JetStream subject groups; changing this table means changing the protocol, so the test pins it down.
func TestCortexPermissionsMatchTopicList(t *testing.T) {
	p := CortexPermissions("TRUEOPEN_TASK")
	wantPub := []string{
		"trueopen.handraise.worker.*", "trueopen.handraise.verifier.*", "trueopen.verify-result.*", "trueopen.output-avail.*",
		"$JS.API.CONSUMER.>", "$JS.API.STREAM.INFO.TRUEOPEN_TASK", "$JS.ACK.TRUEOPEN_TASK.>",
	}
	wantSub := []string{
		"trueopen.task.open.*", "trueopen.verify.open.*", "trueopen.worker-assignment.*", "trueopen.verifier-assignment.*",
		"trueopen.output-avail.*", "_INBOX.>", "$JS.API.CONSUMER.>", "$JS.API.STREAM.INFO.TRUEOPEN_TASK",
	}
	if !slices.Equal(p.Pub.Allow, wantPub) {
		t.Fatalf("pub allow = %v", p.Pub.Allow)
	}
	if !slices.Equal(p.Sub.Allow, wantSub) {
		t.Fatalf("sub allow = %v", p.Sub.Allow)
	}
	if len(p.Pub.Deny) != 0 || len(p.Sub.Deny) != 0 {
		t.Fatal("deny lists must be empty; the allow list is the whole grant")
	}
}

func TestRejectErrorCarriesCodeAndMessage(t *testing.T) {
	err := Reject(CodeChainIDMismatch, "chain_id %q is not %q", "x", "c")
	var rej *RejectError
	if !errors.As(err, &rej) || rej.Code != CodeChainIDMismatch {
		t.Fatalf("want RejectError with CHAIN_ID_MISMATCH, got %v", err)
	}
	if got := rej.Error(); got != `CHAIN_ID_MISMATCH: chain_id "x" is not "c"` {
		t.Fatalf("message = %q", got)
	}
}

func TestAllCodesAreClosedSet(t *testing.T) {
	want := []Code{CodeBindingMalformed, CodeChainIDMismatch, CodeNkeyMismatch, CodeNonceSignatureInvalid,
		CodeServiceKeyNotActive, CodeServiceKeyNonceMismatch, CodeBindingSignatureInvalid, CodeCortexNotRegistered, CodeChainUnavailable}
	if !slices.Equal(AllCodes(), want) {
		t.Fatalf("closed set drifted: %v", AllCodes())
	}
}
