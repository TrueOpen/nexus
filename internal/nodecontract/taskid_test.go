package nodecontract

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"
)

func TestDeriveTaskIDFromRawSessionMatchesNodeNormativeVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/task_data_plane_v1_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		TaskID struct {
			SessionIDRawHex string `json:"session_id_raw_hex"`
			OrderSequence   string `json:"order_sequence"`
			PreimageHex     string `json:"preimage_hex"`
			ExpectedHex     string `json:"expected_hex"`
		} `json:"task_id"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	sessionID, err := hex.DecodeString(fixture.TaskID.SessionIDRawHex)
	if err != nil {
		t.Fatal(err)
	}
	orderSequence, err := strconv.ParseUint(fixture.TaskID.OrderSequence, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	preimage := CanonicalFramePreimage(DomainTaskIDV1, sessionID, Uint64BE(orderSequence))
	if got := hex.EncodeToString(preimage); got != fixture.TaskID.PreimageHex {
		t.Fatalf("preimage = %q, want %q", got, fixture.TaskID.PreimageHex)
	}

	taskID, err := DeriveTaskIDFromRawSession(sessionID, orderSequence)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(taskID[:]); got != fixture.TaskID.ExpectedHex {
		t.Fatalf("task id = %q, want %q", got, fixture.TaskID.ExpectedHex)
	}

	next, err := DeriveTaskIDFromRawSession(sessionID, orderSequence+1)
	if err != nil {
		t.Fatal(err)
	}
	if taskID == next {
		t.Fatal("task id must change when order_sequence changes")
	}
}

func TestDeriveTaskIDFromRawSessionRejectsNonHash32(t *testing.T) {
	valid := make([]byte, 32)
	for _, sessionID := range [][]byte{nil, valid[:31], append(valid, 0)} {
		if _, err := DeriveTaskIDFromRawSession(sessionID, 42); err == nil {
			t.Fatalf("DeriveTaskIDFromRawSession accepted %d-byte session_id", len(sessionID))
		}
	}
}
