package natsauth

import (
	"errors"
	"strings"
	"testing"
)

func TestRejectHasNoCause(t *testing.T) {
	err := Reject(CodeBindingMalformed, "bad binding")
	var rej *RejectError
	if !errors.As(err, &rej) {
		t.Fatalf("want *RejectError, got %T", err)
	}
	if rej.Cause != nil {
		t.Fatalf("Reject must not set Cause, got %v", rej.Cause)
	}
	if rej.Unwrap() != nil {
		t.Fatalf("Unwrap of a plain Reject must be nil, got %v", rej.Unwrap())
	}
}

func TestRejectWithCauseUnwrapsAndHidesDetail(t *testing.T) {
	cause := errors.New("dial tcp 10.0.0.1:9090: connection refused")
	err := RejectWithCause(CodeChainUnavailable, cause, "chain query failed")

	var rej *RejectError
	if !errors.As(err, &rej) {
		t.Fatalf("want *RejectError, got %T", err)
	}
	if rej.Code != CodeChainUnavailable {
		t.Fatalf("want CodeChainUnavailable, got %v", rej.Code)
	}
	if rej.Cause != cause {
		t.Fatalf("Cause must be the original error, got %v", rej.Cause)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("errors.Is must see through Unwrap to cause, got false for %v", err)
	}
	if strings.Contains(err.Error(), "10.0.0.1") || strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("Error() must not leak cause text into the response, got %q", err.Error())
	}
}
