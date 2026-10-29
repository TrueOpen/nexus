package chaincli

import (
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/TrueOpen/wire/dispatch"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	"google.golang.org/protobuf/proto"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
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

// DecodeRecordDispatchResults lists the results whose object_id is not the key of their entry
// instead of refusing the whole response, so the other entries keep their results; structural
// faults still refuse it.
func TestRecordDispatchResultsListKeyMismatches(t *testing.T) {
	const chainID = "trueopen-localnet-1"
	objectIDs := [][32]byte{[32]byte(mustHash32("01")), [32]byte(mustHash32("02")), [32]byte(mustHash32("03"))}
	response := &taskv1.MsgRecordDispatchResponse{Results: []*taskv1.BatchItemResultV1{
		{ItemIndex: 0, ObjectId: mustHash32("01"), Status: sharedv1.MutationStatusV1_MUTATION_STATUS_V1_APPLIED},
		{ItemIndex: 1, ObjectId: mustHash32("09"), Status: sharedv1.MutationStatusV1_MUTATION_STATUS_V1_APPLIED},
		{ItemIndex: 2, ObjectId: mustHash32("03"), Status: sharedv1.MutationStatusV1_MUTATION_STATUS_V1_NOOP},
	}}
	digest := RecordDispatchBatchDigest(chainID, response.GetResults())
	response.BatchDigest = digest[:]
	data, _ := hex.DecodeString(txMsgDataHex(t, response))
	result := TxResult{Data: data}
	got, mismatched, err := DecodeRecordDispatchResults(result, 0, chainID, objectIDs)
	if err != nil || !proto.Equal(got, response) || !reflect.DeepEqual(mismatched, []int{1}) {
		t.Fatalf("results = %v, mismatched %v, %v", got, mismatched, err)
	}
	if _, err := DecodeRecordDispatchResponse(result, 0, chainID, objectIDs); err == nil {
		t.Fatal("DecodeRecordDispatchResponse kept a result that does not echo its entry's key")
	}
	if _, _, err := DecodeRecordDispatchResults(result, 0, chainID, objectIDs[:2]); err == nil {
		t.Fatal("a result count that differs from the entry count was accepted")
	}
}
