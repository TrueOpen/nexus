package chaincli

import (
	"bytes"
	"testing"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"google.golang.org/protobuf/proto"
)

func TestSessionStateFromPB(t *testing.T) {
	id := bytes.Repeat([]byte{0x11}, 32)
	key := bytes.Repeat([]byte{0x33}, 20)
	pb := &taskv1.StreamState{
		SessionId: id, OwnerUserAddress: "trueopen1owner", Status: taskv1.SessionStatus_SESSION_STATUS_IDLE,
		SessionKey: key, SessionKeyExpiryHeight: 1100, SessionKeySetHeight: 980,
		SessionKeySpendCap: &sharedv1.Amount{AtomicUnits: "1150000"}, SessionKeySpent: &sharedv1.Amount{AtomicUnits: "1000000"},
	}
	got, err := sessionStateFromPB(id, pb)
	if err != nil {
		t.Fatal(err)
	}
	if got.Closed || got.Owner != "trueopen1owner" || !bytes.Equal(got.Key, key) || got.ExpiryHeight != 1100 ||
		got.SetHeight != 980 || got.SpendCap != "1150000" || got.Spent != "1000000" {
		t.Fatalf("state = %+v", got)
	}

	pb.Status = taskv1.SessionStatus_SESSION_STATUS_CLOSED
	pb.SessionKey = nil
	got, err = sessionStateFromPB(id, pb)
	if err != nil || !got.Closed || got.Key != nil {
		t.Fatalf("closed, no key: %+v, %v", got, err)
	}

	for name, edit := range map[string]func(*taskv1.StreamState){
		"other session": func(s *taskv1.StreamState) { s.SessionId = bytes.Repeat([]byte{0x22}, 32) },
		"no status":     func(s *taskv1.StreamState) { s.Status = taskv1.SessionStatus_SESSION_STATUS_UNSPECIFIED },
		"no owner":      func(s *taskv1.StreamState) { s.OwnerUserAddress = "" },
		"short key":     func(s *taskv1.StreamState) { s.SessionKey = key[:19] },
		"empty key":     func(s *taskv1.StreamState) { s.SessionKey = []byte{} },
	} {
		bad := proto.Clone(pb).(*taskv1.StreamState)
		bad.Status = taskv1.SessionStatus_SESSION_STATUS_ACTIVE
		bad.SessionKey = key
		edit(bad)
		if _, err := sessionStateFromPB(id, bad); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}
