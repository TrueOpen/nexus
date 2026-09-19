package coordinator

import (
	"fmt"
	"testing"

	"github.com/TrueOpen/wire/bus"

	"github.com/TrueOpen/nexus/internal/busadapter"
)

// retryableBusError: only infrastructure failures are redelivered; invalid messages are not.
func TestRetryableBusError(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{fmt.Errorf("wrap: %w", busadapter.ErrAuthorityUnavailable), true},
		{fmt.Errorf("wrap: %w", bus.ErrStoreFailure), true},
		{fmt.Errorf("wrap: %w", bus.ErrReplay), false},
		{fmt.Errorf("wrap: %w", bus.ErrSignature), false},
		{fmt.Errorf("wrap: %w", bus.ErrPayload), false},
	}
	for _, c := range cases {
		if got := retryableBusError(c.err); got != c.want {
			t.Fatalf("retryableBusError(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}
