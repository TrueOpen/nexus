package ingress

import (
	"bytes"
	"encoding/hex"
	"testing"

	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/types"
)

// An event's detail reaches GetTaskEventsResponse with exactly the facts it has present; an event
// without one has no detail.
func TestEventDetailToPB(t *testing.T) {
	ticket := bytes.Repeat([]byte{0xab}, 32)
	task := bytes.Repeat([]byte{0x05}, 32)
	late := taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_RECORD_LATE
	str := func(s string) *string { return &s }
	height := uint64(70)
	for name, tc := range map[string]struct {
		in   *types.TaskEventDetail
		want *nexusv1.TaskEventDetailV1
	}{
		"none":  {nil, nil},
		"empty": {&types.TaskEventDetail{}, nil},
		"accepted": {&types.TaskEventDetail{DispatchTicketHash: hex.EncodeToString(ticket), WorkerOperatorAddress: "trueopen1worker"},
			&nexusv1.TaskEventDetailV1{DispatchTicketHash: ticket, WorkerOperatorAddress: str("trueopen1worker")}},
		"rejected": {&types.TaskEventDetail{DispatchTicketHash: hex.EncodeToString(ticket), RejectCode: int32(late)},
			&nexusv1.TaskEventDetailV1{DispatchTicketHash: ticket, RejectCode: &late}},
		"pending": {&types.TaskEventDetail{CandidateBuilder: "trueopen1self", TakeoverActivationHeight: 70},
			&nexusv1.TaskEventDetailV1{CandidateBuilder: str("trueopen1self"), TakeoverActivationHeight: &height}},
		"recorded elsewhere": {&types.TaskEventDetail{RecordingBuilder: "trueopen1other", RecordedTaskID: hex.EncodeToString(task)},
			&nexusv1.TaskEventDetailV1{RecordingBuilder: str("trueopen1other"), RecordedTaskId: task}},
		"bound": {&types.TaskEventDetail{BoundBuilder: "trueopen1self"}, &nexusv1.TaskEventDetailV1{BoundBuilder: str("trueopen1self")}},
	} {
		got := eventToPB(types.TaskEvent{Seq: 1, EventCode: "X", Detail: tc.in}).GetDetail()
		if !proto.Equal(got, tc.want) {
			t.Fatalf("%s: detail = %v, want %v", name, got, tc.want)
		}
	}
}
