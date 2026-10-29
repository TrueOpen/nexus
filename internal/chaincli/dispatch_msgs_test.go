package chaincli

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	abciv1beta1 "cosmossdk.io/api/cosmos/base/abci/v1beta1"
	txv1beta1 "cosmossdk.io/api/cosmos/tx/v1beta1"
	"github.com/TrueOpen/wire/dispatch"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

// dispatchVector is one signed message of wire testdata/v1/task/dispatch_v1.json.
type dispatchVector struct {
	Name        string `json:"name"`
	MessageName string `json:"message_name"`
	ProtobufHex string `json:"protobuf_hex"`
	DigestHex   string `json:"digest_hex"`
}

// loadDispatchVector decodes the named wire vector into msg and returns its encoding.
func loadDispatchVector(t *testing.T, name string, msg proto.Message) dispatchVector {
	t.Helper()
	var file struct {
		Vectors []dispatchVector `json:"vectors"`
	}
	if err := json.Unmarshal(wirefixture.ReadFile(t, "testdata/v1/task/dispatch_v1.json"), &file); err != nil {
		t.Fatalf("decode dispatch vectors: %v", err)
	}
	for _, vector := range file.Vectors {
		if vector.Name != name {
			continue
		}
		raw, err := hex.DecodeString(vector.ProtobufHex)
		if err != nil {
			t.Fatal(err)
		}
		if err := proto.Unmarshal(raw, msg); err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		return vector
	}
	t.Fatalf("dispatch vector %q not found", name)
	return dispatchVector{}
}

func testTxSigner(t *testing.T) signer.Signer {
	t.Helper()
	s, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// decodeSingleMsg unpacks the one message of a built transaction.
func decodeSingleMsg(t *testing.T, raw []byte, typeURL string, out proto.Message) {
	t.Helper()
	var txRaw txv1beta1.TxRaw
	if err := proto.Unmarshal(raw, &txRaw); err != nil {
		t.Fatal(err)
	}
	var body txv1beta1.TxBody
	if err := proto.Unmarshal(txRaw.GetBodyBytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.GetMessages()) != 1 || body.GetMessages()[0].GetTypeUrl() != typeURL {
		t.Fatalf("messages = %v, want one %s", body.GetMessages(), typeURL)
	}
	if err := proto.Unmarshal(body.GetMessages()[0].GetValue(), out); err != nil {
		t.Fatal(err)
	}
}

// assertVectorBytes checks that a signed message carried through a transaction still has the
// wire vector's encoding and signing digest: the chain verifies the signature over those bytes.
func assertVectorBytes(t *testing.T, vector dispatchVector, msg proto.Message) {
	t.Helper()
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(raw) != vector.ProtobufHex {
		t.Fatalf("%s re-encoded as %x, want %s", vector.Name, raw, vector.ProtobufHex)
	}
	digest, err := dispatch.SigningDigest(vector.MessageName, raw)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(digest[:]) != vector.DigestHex {
		t.Fatalf("%s digest %x, want %s", vector.Name, digest, vector.DigestHex)
	}
}

func TestBuildRecordDispatchTxCarriesSignedWireMessages(t *testing.T) {
	s := testTxSigner(t)
	record, ticket, accept := &taskv1.DispatchRecordV1{}, &taskv1.DispatchTicketV1{}, &taskv1.DispatchAcceptV1{}
	recordVector := loadDispatchVector(t, "task_v1_dispatchrecordv1", record)
	ticketVector := loadDispatchVector(t, "task_v1_dispatchticketv1", ticket)
	acceptVector := loadDispatchVector(t, "task_v1_dispatchacceptv1", accept)
	order := &taskv1.SignedOrderV2{}
	msg := &taskv1.MsgRecordDispatch{
		SubmitterAddress: s.Address(),
		Entries: []*taskv1.DispatchRecordEntryV1{
			{Entry: &taskv1.DispatchRecordEntryV1_Dispatch{Dispatch: &taskv1.DispatchEntryV1{
				SignedOrder: order, Record: record, WinnerTicket: ticket, Accept: accept,
			}}},
			{Entry: &taskv1.DispatchRecordEntryV1_Takeover{Takeover: &taskv1.TakeoverEntryV1{SignedOrder: order}}},
		},
	}
	raw, err := BuildRecordDispatchTx(s, TxParams{ChainID: "trueopen-localnet-1", AccountNumber: 3, Sequence: 9, GasLimit: 1_000_000}, msg)
	if err != nil {
		t.Fatal(err)
	}
	var got taskv1.MsgRecordDispatch
	decodeSingleMsg(t, raw, TypeURLMsgRecordDispatch, &got)
	if !proto.Equal(&got, msg) {
		t.Fatalf("decoded msg differs:\n%v\n%v", &got, msg)
	}
	entry := got.GetEntries()[0].GetDispatch()
	assertVectorBytes(t, recordVector, entry.GetRecord())
	assertVectorBytes(t, ticketVector, entry.GetWinnerTicket())
	assertVectorBytes(t, acceptVector, entry.GetAccept())

	for name, edit := range map[string]func(*taskv1.MsgRecordDispatch){
		"other submitter": func(m *taskv1.MsgRecordDispatch) { m.SubmitterAddress = "trueopen1other" },
		"no entries":      func(m *taskv1.MsgRecordDispatch) { m.Entries = nil },
		"empty entry":     func(m *taskv1.MsgRecordDispatch) { m.Entries[1] = &taskv1.DispatchRecordEntryV1{} },
		"dispatch without accept": func(m *taskv1.MsgRecordDispatch) {
			m.Entries[0].GetDispatch().Accept = nil
		},
		"takeover without order": func(m *taskv1.MsgRecordDispatch) {
			m.Entries[1].GetTakeover().SignedOrder = nil
		},
	} {
		bad := proto.Clone(msg).(*taskv1.MsgRecordDispatch)
		edit(bad)
		if _, err := BuildRecordDispatchTx(s, TxParams{ChainID: "trueopen-localnet-1"}, bad); err == nil {
			t.Fatalf("%s: built", name)
		}
	}
}

func TestBuildRebutAndRespondTxs(t *testing.T) {
	s := testTxSigner(t)
	record, reject := &taskv1.DispatchRecordV1{}, &taskv1.DispatchRejectV1{}
	recordVector := loadDispatchVector(t, "task_v1_dispatchrecordv1", record)
	rejectVector := loadDispatchVector(t, "task_v1_dispatchrejectv1", reject)
	params := TxParams{ChainID: "trueopen-localnet-1", GasLimit: 500_000}

	rebut := &taskv1.MsgRebutDispatchCompensation{
		DispatchTicketHash: mustHash32("a1"), ResponderAddress: s.Address(), Record: record, Reject: reject,
	}
	raw, err := BuildRebutDispatchCompensationTx(s, params, rebut)
	if err != nil {
		t.Fatal(err)
	}
	var gotRebut taskv1.MsgRebutDispatchCompensation
	decodeSingleMsg(t, raw, TypeURLMsgRebutDispatchCompensation, &gotRebut)
	assertVectorBytes(t, recordVector, gotRebut.GetRecord())
	assertVectorBytes(t, rejectVector, gotRebut.GetReject())
	if !bytes.Equal(gotRebut.GetDispatchTicketHash(), mustHash32("a1")) {
		t.Fatalf("rebut = %v", &gotRebut)
	}
	for name, edit := range map[string]func(*taskv1.MsgRebutDispatchCompensation){
		"short ticket":    func(m *taskv1.MsgRebutDispatchCompensation) { m.DispatchTicketHash = []byte{1} },
		"other responder": func(m *taskv1.MsgRebutDispatchCompensation) { m.ResponderAddress = "trueopen1other" },
		"no record":       func(m *taskv1.MsgRebutDispatchCompensation) { m.Record = nil },
	} {
		bad := proto.Clone(rebut).(*taskv1.MsgRebutDispatchCompensation)
		edit(bad)
		if _, err := BuildRebutDispatchCompensationTx(s, params, bad); err == nil {
			t.Fatalf("rebut %s: built", name)
		}
	}

	respond := &taskv1.MsgRespondDispatchChallenge{
		ChallengeId: mustHash32("c1"), ResponderAddress: s.Address(),
		Response: &taskv1.MsgRespondDispatchChallenge_Reject{Reject: reject},
	}
	raw, err = BuildRespondDispatchChallengeTx(s, params, respond)
	if err != nil {
		t.Fatal(err)
	}
	var gotRespond taskv1.MsgRespondDispatchChallenge
	decodeSingleMsg(t, raw, TypeURLMsgRespondDispatchChallenge, &gotRespond)
	assertVectorBytes(t, rejectVector, gotRespond.GetReject())
	roster := &taskv1.MsgRespondDispatchChallenge{
		ChallengeId: mustHash32("c1"), ResponderAddress: s.Address(),
		Response: &taskv1.MsgRespondDispatchChallenge_Roster{Roster: &taskv1.DispatchRosterV1{TaskId: testTaskIDBytes}},
	}
	if _, err := BuildRespondDispatchChallengeTx(s, params, roster); err != nil {
		t.Fatalf("roster response: %v", err)
	}
	for name, edit := range map[string]func(*taskv1.MsgRespondDispatchChallenge){
		"short challenge": func(m *taskv1.MsgRespondDispatchChallenge) { m.ChallengeId = nil },
		"other responder": func(m *taskv1.MsgRespondDispatchChallenge) { m.ResponderAddress = "trueopen1other" },
		"no response":     func(m *taskv1.MsgRespondDispatchChallenge) { m.Response = nil },
		"empty reject": func(m *taskv1.MsgRespondDispatchChallenge) {
			m.Response = &taskv1.MsgRespondDispatchChallenge_Reject{}
		},
	} {
		bad := proto.Clone(respond).(*taskv1.MsgRespondDispatchChallenge)
		edit(bad)
		if _, err := BuildRespondDispatchChallengeTx(s, params, bad); err == nil {
			t.Fatalf("respond %s: built", name)
		}
	}
}

// txMsgDataHex is how the node reports a transaction's Msg responses: TxResponse.data is the
// uppercase hex of TxMsgData.
func txMsgDataHex(t *testing.T, responses ...proto.Message) string {
	t.Helper()
	data := &abciv1beta1.TxMsgData{}
	for _, response := range responses {
		value, err := proto.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		typeURL := "/" + string(response.ProtoReflect().Descriptor().FullName())
		data.MsgResponses = append(data.MsgResponses, &anypb.Any{TypeUrl: typeURL, Value: value})
	}
	raw, err := proto.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	return strings.ToUpper(hex.EncodeToString(raw))
}

func TestRecordDispatchResultsComeFromTheExecutedTx(t *testing.T) {
	const chainID = "trueopen-localnet-1"
	objectIDs := [][32]byte{[32]byte(mustHash32("01")), [32]byte(mustHash32("02")), [32]byte(mustHash32("03"))}
	response := &taskv1.MsgRecordDispatchResponse{
		Results: []*taskv1.BatchItemResultV1{
			{ItemIndex: 0, ObjectId: mustHash32("01"), Status: sharedv1.MutationStatusV1_MUTATION_STATUS_V1_APPLIED},
			{ItemIndex: 1, ObjectId: mustHash32("02"), Status: sharedv1.MutationStatusV1_MUTATION_STATUS_V1_REJECTED,
				RejectCode: taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_RECORD_LATE},
			{ItemIndex: 2, ObjectId: mustHash32("03"), Status: sharedv1.MutationStatusV1_MUTATION_STATUS_V1_NOOP},
		},
	}
	digest := RecordDispatchBatchDigest(chainID, response.GetResults())
	response.BatchDigest = digest[:]
	fake := &recordTxService{getResp: &txv1beta1.GetTxResponse{TxResponse: &abciv1beta1.TxResponse{
		Height: 50, Txhash: "0A0B", Data: txMsgDataHex(t, response),
	}}}
	result, err := (&client{tx: fake}).QueryTx(context.Background(), []byte{0x0a, 0x0b})
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeRecordDispatchResponse(result, 0, chainID, objectIDs)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(got, response) {
		t.Fatalf("response = %v", got)
	}
	if got.GetResults()[1].GetRejectCode() != taskv1.DispatchRejectCodeV1_DISPATCH_REJECT_CODE_V1_RECORD_LATE {
		t.Fatalf("reject code = %v", got.GetResults()[1].GetRejectCode())
	}

	if _, err := DecodeRecordDispatchResponse(result, 0, chainID, objectIDs[:2]); err == nil {
		t.Fatal("a result count that differs from the entry count was accepted")
	}
	swapped := [][32]byte{objectIDs[1], objectIDs[0], objectIDs[2]}
	if _, err := DecodeRecordDispatchResponse(result, 0, chainID, swapped); err == nil {
		t.Fatal("results were attributed to entries whose keys they do not echo")
	}
	// A batch_digest that does not commit to the results refuses them all.
	if got, err := DecodeRecordDispatchResponse(result, 0, "other-chain", objectIDs); !errors.Is(err, ErrBatchDigestMismatch) || got != nil {
		t.Fatalf("batch digest of another chain = %v, %v", got, err)
	}
	if _, err := DecodeRecordDispatchResponse(result, 1, chainID, objectIDs); err == nil {
		t.Fatal("a missing message index was accepted")
	}
	failed := result
	failed.Code = 5
	if _, err := DecodeRecordDispatchResponse(failed, 0, chainID, objectIDs); err == nil {
		t.Fatal("a failed transaction's responses were read")
	}
	for name, edit := range map[string]func(*taskv1.MsgRecordDispatchResponse){
		"index gap":           func(r *taskv1.MsgRecordDispatchResponse) { r.Results[2].ItemIndex = 3 },
		"rejected, no code":   func(r *taskv1.MsgRecordDispatchResponse) { r.Results[1].RejectCode = 0 },
		"applied with a code": func(r *taskv1.MsgRecordDispatchResponse) { r.Results[0].RejectCode = 1 },
		"no status":           func(r *taskv1.MsgRecordDispatchResponse) { r.Results[2].Status = 0 },
		"status changed": func(r *taskv1.MsgRecordDispatchResponse) {
			r.Results[2].Status = sharedv1.MutationStatusV1_MUTATION_STATUS_V1_APPLIED
		},
	} {
		bad := proto.Clone(response).(*taskv1.MsgRecordDispatchResponse)
		edit(bad)
		if name != "status changed" {
			d := RecordDispatchBatchDigest(chainID, bad.GetResults())
			bad.BatchDigest = d[:]
		}
		raw, _ := hex.DecodeString(txMsgDataHex(t, bad))
		got, err := DecodeRecordDispatchResponse(TxResult{Data: raw}, 0, chainID, objectIDs)
		if name == "status changed" {
			if !errors.Is(err, ErrBatchDigestMismatch) || got != nil {
				t.Fatalf("%s: %v, %v", name, got, err)
			}
			continue
		}
		if err == nil || got != nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	other, _ := hex.DecodeString(txMsgDataHex(t, &taskv1.MsgSettleTaskResponse{}))
	if _, err := DecodeRecordDispatchResponse(TxResult{Data: other}, 0, chainID, objectIDs); err == nil {
		t.Fatal("another message's response was read as a record response")
	}
}

// The batch digest follows the wire TRUEOPEN_BATCH_RESULT_V1 vector.
func TestBatchResultDigestMatchesWireVector(t *testing.T) {
	v := wirefixture.Load(t, "shared/shared_domains_v1.json").Vector(t, "batch_result_v1_model_support", 0)
	results := []*taskv1.BatchItemResultV1{
		{ObjectId: bytes.Repeat([]byte{0x31}, 32), Status: 1},
		{ObjectId: bytes.Repeat([]byte{0x32}, 32), Status: 2},
	}
	if got := batchResultDigest(v.Field(t, "chain_id").UTF8, v.Field(t, "batch_kind").UTF8, results); got != v.Digest(t) {
		t.Fatalf("batch digest = %x, want %s", got, v.DigestHex)
	}
}

// The entry keys are the wire entry digests over the messages' own signing digests.
func TestEntryObjectIDsUseTheWireEntryDigests(t *testing.T) {
	file := wirefixture.Load(t, "task/dispatch_v1.json")
	decode := func(name string, m proto.Message) [32]byte {
		v := file.Vector(t, name, 0)
		var raw struct {
			Protobuf string `json:"protobuf_hex"`
		}
		if err := json.Unmarshal(v.Raw, &raw); err != nil {
			t.Fatal(err)
		}
		b, err := hex.DecodeString(raw.Protobuf)
		if err != nil {
			t.Fatal(err)
		}
		if err := proto.Unmarshal(b, m); err != nil {
			t.Fatal(err)
		}
		return v.Digest(t)
	}
	record, accept, ticket := &taskv1.DispatchRecordV1{}, &taskv1.DispatchAcceptV1{}, &taskv1.DispatchTicketV1{}
	recordDigest := decode("task_v1_dispatchrecordv1", record)
	acceptDigest := decode("task_v1_dispatchacceptv1", accept)
	decode("task_v1_dispatchticketv1", ticket)
	got, err := DispatchEntryObjectID("trueopen-phase1-vector-1", &taskv1.DispatchEntryV1{Record: record, WinnerTicket: ticket, Accept: accept})
	if err != nil {
		t.Fatal(err)
	}
	want := dispatch.DispatchEntryDigest("trueopen-phase1-vector-1", [32]byte(ticket.GetTaskId()), [32]byte(ticket.GetTaskHash()), recordDigest, acceptDigest)
	if got != want {
		t.Fatalf("dispatch entry object id = %x, want %x", got, want)
	}
	if _, err := DispatchEntryObjectID("c", &taskv1.DispatchEntryV1{Record: record, Accept: accept, WinnerTicket: &taskv1.DispatchTicketV1{}}); err == nil {
		t.Fatal("an entry without a task id was keyed")
	}
}

// The wire batch result vectors: one dispatch entry built from the real signed record and accept
// and one takeover entry, with mixed, exact-replay and independently rejected results. Each
// result's object_id is its entry's digest (never the record or ticket hash), NOOP echoes the same
// identity, and batch_digest commits to (object_id, status) in input order under DISPATCH_RECORD.
func TestRecordDispatchResultsMatchTheWireBatchVectors(t *testing.T) {
	const chainID = "trueopen-phase1-vector-1"
	file := wirefixture.Load(t, "task/dispatch_v1.json")
	var doc struct {
		BatchResults []struct {
			Name          string `json:"name"`
			BatchDigest   string `json:"batch_digest_hex"`
			DispatchEntry string `json:"dispatch_entry_vector"`
			TakeoverEntry string `json:"takeover_entry_vector"`
			Record        string `json:"record_vector"`
			Accept        string `json:"accept_vector"`
			Response      string `json:"response_protobuf_hex"`
			Results       []struct {
				ItemIndex  uint32 `json:"item_index"`
				ObjectID   string `json:"object_id_hex"`
				Status     int32  `json:"status"`
				RejectCode int32  `json:"reject_code"`
			} `json:"results"`
		} `json:"batch_results"`
	}
	if err := json.Unmarshal(file.Raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.BatchResults) == 0 {
		t.Fatal("no batch result vectors")
	}
	decode := func(name string, m proto.Message) {
		var raw struct {
			Protobuf string `json:"protobuf_hex"`
		}
		if err := json.Unmarshal(file.Vector(t, name, 0).Raw, &raw); err != nil {
			t.Fatal(err)
		}
		b, _ := hex.DecodeString(raw.Protobuf)
		if err := proto.Unmarshal(b, m); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range doc.BatchResults {
		t.Run(row.Name, func(t *testing.T) {
			record, accept := &taskv1.DispatchRecordV1{}, &taskv1.DispatchAcceptV1{}
			decode(row.Record, record)
			decode(row.Accept, accept)
			entryVector := file.Vector(t, row.DispatchEntry, 0)
			entryVector.CheckPreimage(t)
			ticket := &taskv1.DispatchTicketV1{TaskId: entryVector.Field(t, "task_id").Bytes(t), TaskHash: entryVector.Field(t, "task_hash").Bytes(t)}
			dispatchID, err := DispatchEntryObjectID(chainID, &taskv1.DispatchEntryV1{Record: record, WinnerTicket: ticket, Accept: accept})
			if err != nil || dispatchID != entryVector.Digest(t) {
				t.Fatalf("dispatch entry object id = %x, %v; want %s", dispatchID, err, entryVector.DigestHex)
			}
			objectIDs := [][32]byte{dispatchID, file.Vector(t, row.TakeoverEntry, 0).Digest(t)}

			raw, _ := hex.DecodeString(row.Response)
			response := &taskv1.MsgRecordDispatchResponse{}
			if err := proto.Unmarshal(raw, response); err != nil {
				t.Fatal(err)
			}
			data, _ := hex.DecodeString(txMsgDataHex(t, response))
			got, mismatched, err := DecodeRecordDispatchResults(TxResult{Data: data}, 0, chainID, objectIDs)
			if err != nil || len(mismatched) != 0 {
				t.Fatalf("results: mismatched %v, %v", mismatched, err)
			}
			if hex.EncodeToString(got.GetBatchDigest()) != row.BatchDigest || len(got.GetResults()) != len(row.Results) {
				t.Fatalf("response = %v", got)
			}
			for i, want := range row.Results {
				r := got.GetResults()[i]
				if r.GetItemIndex() != want.ItemIndex || hex.EncodeToString(r.GetObjectId()) != want.ObjectID ||
					int32(r.GetStatus()) != want.Status || int32(r.GetRejectCode()) != want.RejectCode {
					t.Fatalf("result %d = %v, want %+v", i, r, want)
				}
			}
			if RecordDispatchBatchDigest(chainID, got.GetResults()) != [32]byte(got.GetBatchDigest()) {
				t.Fatal("recomputed batch digest differs")
			}
		})
	}
}

// presignedVrfTx builds the transaction an operator signs offline to register the Builder VRF key.
func presignedVrfTx(t *testing.T, msgs ...proto.Message) []byte {
	t.Helper()
	s := testTxSigner(t)
	anys := make([]*anypb.Any, 0, len(msgs))
	for _, msg := range msgs {
		packed, err := PackAny("/"+string(msg.ProtoReflect().Descriptor().FullName()), msg)
		if err != nil {
			t.Fatal(err)
		}
		anys = append(anys, packed)
	}
	raw, err := BuildSignedTx(s, TxParams{ChainID: "trueopen-localnet-1", GasLimit: 200_000}, anys...)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestBroadcastRegisterVrfKeyTxRelaysTheOperatorSignedBytes(t *testing.T) {
	const builder = "trueopen1builder"
	register := &hubv1.MsgRegisterVrfKey{
		VrfPubkey: bytes.Repeat([]byte{0x07}, 32), VrfKeyPop: bytes.Repeat([]byte{0x08}, 64), VrfAuthorizationNonce: 1,
		OperatorAddress: builder, ParticipantType: sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER,
	}
	raw := presignedVrfTx(t, register)
	fake := &recordTxService{resp: &txv1beta1.BroadcastTxResponse{TxResponse: &abciv1beta1.TxResponse{Txhash: "0A0B"}}}
	result, err := BroadcastRegisterVrfKeyTx(context.Background(), &client{tx: fake}, raw, builder)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fake.req.GetTxBytes(), raw) || string(result.TxHash) != "\x0a\x0b" {
		t.Fatalf("broadcast %x, result %+v", fake.req.GetTxBytes(), result)
	}

	for name, tx := range map[string][]byte{
		"not a tx":       {0xff, 0x01},
		"other operator": presignedVrfTx(t, withVrf(register, func(m *hubv1.MsgRegisterVrfKey) { m.OperatorAddress = "trueopen1other" })),
		"validator key": presignedVrfTx(t, withVrf(register, func(m *hubv1.MsgRegisterVrfKey) {
			m.ParticipantType = sharedv1.ParticipantType_PARTICIPANT_TYPE_VALIDATOR
		})),
		"short vrf key":   presignedVrfTx(t, withVrf(register, func(m *hubv1.MsgRegisterVrfKey) { m.VrfPubkey = m.VrfPubkey[:31] })),
		"no pop":          presignedVrfTx(t, withVrf(register, func(m *hubv1.MsgRegisterVrfKey) { m.VrfKeyPop = nil })),
		"second message":  presignedVrfTx(t, register, &taskv1.MsgSettleTask{TaskId: testTaskIDBytes}),
		"another message": presignedVrfTx(t, &taskv1.MsgSettleTask{TaskId: testTaskIDBytes}),
	} {
		fake := &recordTxService{}
		if _, err := BroadcastRegisterVrfKeyTx(context.Background(), &client{tx: fake}, tx, builder); err == nil || fake.calls != 0 {
			t.Fatalf("%s: broadcast (calls %d, err %v)", name, fake.calls, err)
		}
	}
	unsigned := &txv1beta1.TxRaw{}
	if err := proto.Unmarshal(raw, unsigned); err != nil {
		t.Fatal(err)
	}
	unsigned.Signatures = nil
	unsignedRaw, _ := proto.Marshal(unsigned)
	if _, err := CheckRegisterVrfKeyTx(unsignedRaw, builder); err == nil {
		t.Fatal("an unsigned transaction was accepted")
	}
}

func withVrf(msg *hubv1.MsgRegisterVrfKey, edit func(*hubv1.MsgRegisterVrfKey)) *hubv1.MsgRegisterVrfKey {
	clone := proto.Clone(msg).(*hubv1.MsgRegisterVrfKey)
	edit(clone)
	return clone
}
