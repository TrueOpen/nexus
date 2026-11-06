package dispatcher

import (
	"time"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
)

// OfferLive is the stream replay filter for dispatch offers: an offer stored for a reconnecting
// Cortex is sent again only while its ticket's accept deadline has not passed at now. Any other
// frame is kept.
func OfferLive(frame *nexusv1.DispatchStreamFrameV1, now time.Time) bool {
	offer := frame.GetOffer()
	if offer == nil {
		return true
	}
	return uint64(now.UnixMilli()) <= offer.GetTicket().GetAcceptDeadlineMs()
}
