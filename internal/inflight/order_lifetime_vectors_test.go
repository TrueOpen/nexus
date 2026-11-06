package inflight

import (
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"github.com/TrueOpen/wire/dispatch"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

// CheckOrderLifetime agrees with every case of wire's order lifetime vectors, the protocol
// ceiling among them. A record deadline of one block keeps the recording span from deciding any
// case: every allowed expiry strictly follows its earliest height.
func TestCheckOrderLifetimeFollowsTheWireVectors(t *testing.T) {
	var file struct {
		Maximum string `json:"maximum_protocol_blocks"`
		Cases   []struct {
			Name     string `json:"name"`
			Earliest string `json:"earliest_submit_height"`
			Expiry   string `json:"order_expire_height"`
			Lifetime string `json:"max_order_lifetime_blocks"`
			Allowed  bool   `json:"allowed"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(wirefixture.ReadFile(t, "testdata/v1/task/order_lifetime_v1.json"), &file); err != nil {
		t.Fatal(err)
	}
	if file.Maximum != strconv.FormatUint(dispatch.MaxOrderLifetimeBlocksV1, 10) {
		t.Fatalf("vectors name maximum %s, dispatch.MaxOrderLifetimeBlocksV1 is %d", file.Maximum, dispatch.MaxOrderLifetimeBlocksV1)
	}
	if len(file.Cases) == 0 {
		t.Fatal("no order lifetime cases")
	}
	parse := func(name, s string) uint64 {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return v
	}
	for _, c := range file.Cases {
		frozen := &taskv1.DispatchParamsV1{RecordDeadlineBlocks: 1, MaxOrderLifetimeBlocks: parse(c.Name, c.Lifetime)}
		err := CheckOrderLifetime(parse(c.Name, c.Earliest), parse(c.Name, c.Expiry), frozen)
		switch {
		case c.Allowed && err != nil:
			t.Errorf("%s: refused: %v", c.Name, err)
		case !c.Allowed && !errors.Is(err, ErrOrderExpired):
			t.Errorf("%s: = %v, want %v", c.Name, err, ErrOrderExpired)
		}
	}
}
