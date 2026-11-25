package dispatcher

import (
	"bytes"
	"testing"
)

// The input token attestation received with an order stays with it through the walk and a restart
// and is handed to the Recorder with the accepted order's entry.
func TestInputTokenAttestationReachesTheRecorder(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	o := e.order(s, 0, 1)
	o.InputTokensAttestation = []byte("attestation bytes as received")
	e.dispatch(o)
	e.restart()
	e.accept()
	b := e.onlyBundle()
	if !bytes.Equal(b.InputTokens, o.InputTokensAttestation) {
		t.Fatalf("bundle attestation = %q, want the bytes received with the order", b.InputTokens)
	}
	// An order without one hands over none.
	s2 := e.session(0xbb, 0)
	e.dispatch(e.order(s2, 0, 2))
	e.accept()
	for _, got := range e.recorder.recorded() {
		if got.SessionID == s2 && len(got.InputTokens) != 0 {
			t.Fatalf("an order without an attestation handed one over: %q", got.InputTokens)
		}
	}
}
