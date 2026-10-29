package chaincli

import (
	"testing"

	"github.com/TrueOpen/wire/dispatch"
	"github.com/cosmos/cosmos-sdk/types/bech32"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

// The takeover entry key is the wire takeover_entry_digest over (chain, session, sequence,
// task_hash, candidate, bound_change_height at registration): the three wire vectors pin it, and
// the entry's task_hash is the task hash of the order it carries.
func TestTakeoverEntryObjectIDUsesTheWireTakeoverDigest(t *testing.T) {
	file := wirefixture.Load(t, "task/dispatch_v1.json")
	for _, name := range []string{"takeover_entry_candidate_a", "takeover_entry_rebound", "takeover_entry_candidate_b"} {
		v := file.Vector(t, name, 0)
		v.CheckPreimage(t)
		candidate, err := bech32.ConvertAndEncode("trueopen", v.Field(t, "candidate_operator").Bytes(t))
		if err != nil {
			t.Fatal(err)
		}
		got, err := dispatch.TakeoverEntryDigest(v.Field(t, "chain_id").UTF8, [32]byte(v.Field(t, "session_id").Bytes(t)),
			v.Field(t, "order_sequence").Uint64(t), [32]byte(v.Field(t, "task_hash").Bytes(t)), candidate,
			v.Field(t, "bound_change_height_at_registration").Uint64(t))
		if err != nil || got != v.Digest(t) {
			t.Fatalf("%s: takeover entry digest = %x, %v; want %s", name, got, err, v.DigestHex)
		}
	}

	orderVector := wirefixture.Load(t, "task/task_order_v3.json").Vector(t, "task_order_v3_core", 0)
	order := wirefixture.TaskOrderV3(t, orderVector)
	const chainID, candidate = "trueopen-phase1-vector-1", "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz"
	entry := &taskv1.TakeoverEntryV1{SignedOrder: &taskv1.SignedOrderV2{Order: order}}
	got, err := TakeoverEntryObjectID(chainID, candidate, entry, 100)
	if err != nil {
		t.Fatal(err)
	}
	want, err := dispatch.TakeoverEntryDigest(chainID, [32]byte(order.GetSessionId()), order.GetOrderSequence(), orderVector.Digest(t), candidate, 100)
	if err != nil || got != want {
		t.Fatalf("takeover entry object id = %x, want %x (%v)", got, want, err)
	}
	if again, _ := TakeoverEntryObjectID(chainID, candidate, entry, 101); again == got {
		t.Fatal("a new binding generation kept the takeover entry key")
	}
}
