package chaincli

import (
	"math"
	"strconv"
	"strings"
	"testing"
)

// TestUint64ToInt64ErrorCarriesTheActualValue pins "the error must state the actual value".
//
// The shape hit in the field: an on-chain infer_deadline_height between the int64 and
// uint64 upper bounds (9.22e18 ~ 1.84e19); the Keeper's overflow guard only catches full
// uint64 overflow, so the chain considers it valid and persists it normally, and it only
// overflows when nexus reads it.
//
// Before the fix the error was just "infer deadline height exceeds int64": no amount, no
// hint that this is a misconfigured on-chain parameter rather than a local decode bug, so
// debugging meant reverse-engineering across three repos. This assertion keeps that
// information in the error.
func TestUint64ToInt64ErrorCarriesTheActualValue(t *testing.T) {
	const field = "infer deadline height"
	// A value between the int64 and uint64 upper bounds: valid on chain, out of range locally.
	value := uint64(math.MaxInt64) + 1

	_, err := uint64ToInt64(field, value)
	if err == nil {
		t.Fatalf("uint64ToInt64(%d) did not error although it exceeds the int64 upper bound", value)
	}
	message := err.Error()
	for _, want := range []string{
		field,
		strconv.FormatUint(value, 10), // the actual value
		strconv.FormatUint(uint64(math.MaxInt64), 10), // the upper bound, for comparing magnitude
		"parameter is misconfigured",                  // points at the responsible side
	} {
		if !strings.Contains(message, want) {
			t.Fatalf("error is missing %q:\n%s", want, message)
		}
	}
}

// TestUint64ToInt64AcceptsTheBoundary: the boundary itself must be accepted; the int64 upper bound is a valid height.
func TestUint64ToInt64AcceptsTheBoundary(t *testing.T) {
	got, err := uint64ToInt64("height", uint64(math.MaxInt64))
	if err != nil {
		t.Fatalf("int64 upper bound should be accepted: %v", err)
	}
	if got != math.MaxInt64 {
		t.Fatalf("got %d, want %d", got, int64(math.MaxInt64))
	}
}
