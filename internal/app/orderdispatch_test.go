package app

import (
	"testing"
	"time"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
)

// A reconnecting Cortex is not given stored roots (it gets the latest one) nor offers whose accept
// deadline passed.
func TestReplayDropsExpiredOffers(t *testing.T) {
	now := time.UnixMilli(5_000)
	keep := keepOnReplayAt(func() time.Time { return now })
	offer := func(deadline uint64) *nexusv1.DispatchStreamFrameV1 {
		return &nexusv1.DispatchStreamFrameV1{Message: &nexusv1.DispatchStreamFrameV1_Offer{Offer: &nexusv1.DispatchOfferV1{
			Ticket: &taskv1.DispatchTicketV1{AcceptDeadlineMs: deadline}}}}
	}
	root := &nexusv1.DispatchStreamFrameV1{Message: &nexusv1.DispatchStreamFrameV1_HandraiseRoot{HandraiseRoot: &nexusv1.HandraiseRootNoticeV1{}}}
	if !keep("op", offer(5_000)) || keep("op", offer(4_999)) || keep("op", root) {
		t.Fatal("replay filter")
	}
}

type recordingStreamObserver struct{ calls []string }

func (r *recordingStreamObserver) SessionStreamUp(id string)   { r.calls = append(r.calls, "up "+id) }
func (r *recordingStreamObserver) SessionStreamDown(id string) { r.calls = append(r.calls, "down "+id) }
func (r *recordingStreamObserver) SessionStreamClosed(id string) {
	r.calls = append(r.calls, "closed "+id)
}
func (r *recordingStreamObserver) SessionKeyUpdated(id string) { r.calls = append(r.calls, "key "+id) }

// Before the order path exists, session streams still reach the registered key cache and chain
// events are dropped.
func TestOrderEventsBeforeTheOrderPath(t *testing.T) {
	keys := &recordingStreamObserver{}
	e := &orderEvents{keys: keys}
	var _ chaincli.SessionStreamObserver = e
	e.SessionStreamUp("s")
	e.SessionKeyUpdated("s")
	e.observe(chaincli.ChainEvent{Type: chaincli.EventNewBlock, Height: 3})
	if len(keys.calls) != 2 || keys.calls[0] != "up s" || keys.calls[1] != "key s" {
		t.Fatalf("calls = %v", keys.calls)
	}
}
