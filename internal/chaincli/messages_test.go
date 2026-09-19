package chaincli

import "testing"

func TestTaskKeyValidate(t *testing.T) {
	if err := (TaskKey{SessionID: "s", TaskID: "t"}).Validate(); err != nil {
		t.Fatalf("valid key returned error: %v", err)
	}
	for _, tc := range []TaskKey{
		{SessionID: "", TaskID: "t"},
		{SessionID: "s", TaskID: ""},
		{},
	} {
		if err := tc.Validate(); err == nil {
			t.Fatalf("key %+v should be invalid", tc)
		}
	}
}
