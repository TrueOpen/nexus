package coordinator

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/attempt"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

// testWinner is an accepted ticket of task (session, task, worker) built from the wire
// DispatchResultHeaderV1 vector; rank tells attempts apart. It returns the ticket hash.
func testWinner(t *testing.T, sessionID, taskID, worker string, rank uint32) (attempt.Winner, [32]byte) {
	t.Helper()
	v := wirefixture.Load(t, "task/dispatch_v1.json").Vector(t, "nexus_v1_dispatchresultheaderv1", 0)
	var sv struct {
		ProtobufHex string `json:"protobuf_hex"`
	}
	if err := json.Unmarshal(v.Raw, &sv); err != nil {
		t.Fatal(err)
	}
	raw, _ := hex.DecodeString(sv.ProtobufHex)
	var h nexusv1.DispatchResultHeaderV1
	if err := proto.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	session, _ := hex.DecodeString(sessionID)
	task, _ := hex.DecodeString(taskID)
	ticket := proto.Clone(h.GetWinnerTicket()).(*taskv1.DispatchTicketV1)
	ticket.SessionId, ticket.TaskId, ticket.Rank = session, task, rank
	ticket.Target.OperatorAddress = worker
	tb, _ := proto.MarshalOptions{Deterministic: true}.Marshal(ticket)
	hash, err := dispatch.SigningDigest("task.v1.DispatchTicketV1", tb)
	if err != nil {
		t.Fatal(err)
	}
	accept := proto.Clone(h.GetAccept()).(*taskv1.DispatchAcceptV1)
	accept.TaskId, accept.TaskHash, accept.DispatchTicketHash = task, ticket.GetTaskHash(), hash[:]
	return attempt.Winner{SessionID: sessionID, Sequence: ticket.GetOrderSequence(), Ticket: ticket, Accept: accept}, hash
}

func newTestBook(t *testing.T, store kv.Store) *attempt.Book {
	t.Helper()
	s, err := signer.NewFromBytes(bytes.Repeat([]byte{0x01}, 32), "trueopen")
	if err != nil {
		t.Fatal(err)
	}
	b, err := attempt.New(store, servicekey.Static(s, 1), nil)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
