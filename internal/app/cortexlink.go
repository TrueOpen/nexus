package app

import (
	"context"
	"log/slog"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
)

// noCortexLink is the CortexLink used until the Cortex dispatch stream is served: it logs each
// Builder message and drops it. Nothing depends on delivery, since every fact a message announces
// is also on chain.
type noCortexLink struct {
	log *slog.Logger
}

func (l noCortexLink) Broadcast(_ context.Context, frame *nexusv1.DispatchStreamFrameV1) error {
	kind := "unknown"
	switch frame.GetMessage().(type) {
	case *nexusv1.DispatchStreamFrameV1_OpenVerify:
		kind = "open_verify"
	case *nexusv1.DispatchStreamFrameV1_VerifierAssignment:
		kind = "verifier_assignment"
	}
	l.log.Debug("cortex dispatch stream not served; dropping builder message", "message", kind)
	return nil
}
