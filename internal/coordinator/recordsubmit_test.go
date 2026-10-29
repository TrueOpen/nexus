package coordinator

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/signer"
)

const otherKeyHex = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"

func recordMsg(submitter string) *taskv1.MsgRecordDispatch {
	return &taskv1.MsgRecordDispatch{SubmitterAddress: submitter, Entries: []*taskv1.DispatchRecordEntryV1{{
		Entry: &taskv1.DispatchRecordEntryV1_Dispatch{Dispatch: &taskv1.DispatchEntryV1{
			SignedOrder: &taskv1.SignedOrderV2{}, Record: &taskv1.DispatchRecordV1{OrderSequence: 3},
			WinnerTicket: &taskv1.DispatchTicketV1{}, Accept: &taskv1.DispatchAcceptV1{},
		}},
	}}}
}

func newRecordSubmitter(t *testing.T, chain chaincli.Client, keyHex string, shared Submitter) (RecordSubmitter, signer.Signer) {
	t.Helper()
	sg, err := signer.NewFromHex(keyHex, "trueopen")
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewRecordSubmitter(log, chain, sg, config.ChainConfig{ChainID: "trueopen-localnet", GasLimit: 200000}, shared), sg
}

type persisted struct {
	raws          [][]byte
	broadcastsAt  []int // broadcasts already made when each raw was persisted
	chain         *seqChain
	fail          error
	broadcastRaws [][]byte
}

func (p *persisted) persist(raw []byte) error {
	if p.fail != nil {
		return p.fail
	}
	p.raws = append(p.raws, bytes.Clone(raw))
	p.broadcastsAt = append(p.broadcastsAt, len(p.chain.broadcasts))
	return nil
}

// The signed record transaction is persisted before it is broadcast, and the bytes broadcast are
// the bytes persisted: the service account signs it as submitter_address.
func TestRecordSubmitterPersistsBeforeBroadcast(t *testing.T) {
	chain := &seqChain{accSeq: 42}
	sub, sg := newRecordSubmitter(t, chain, testKeyHex, nil)
	p := &persisted{chain: chain}
	res, err := sub.SubmitRecordDispatch(context.Background(), recordMsg(sg.Address()), 650_000, p.persist)
	if err != nil || res.Code != 0 {
		t.Fatalf("submit = %+v, %v", res, err)
	}
	if len(p.raws) != 1 || p.broadcastsAt[0] != 0 || len(chain.broadcasts) != 1 || chain.broadcasts[0] != 42 {
		t.Fatalf("persisted %d (at %v), broadcast sequences %v", len(p.raws), p.broadcastsAt, chain.broadcasts)
	}
	body, auth := decodeBuilderTx(t, p.raws[0])
	if body.Messages[0].TypeUrl != chaincli.TypeURLMsgRecordDispatch || !bytes.Equal(auth.SignerInfos[0].PublicKey.Value[2:], sg.PubKeyCompressed()) {
		t.Fatalf("tx = %s signed by %x", body.Messages[0].TypeUrl, auth.SignerInfos[0].PublicKey.Value)
	}
	if auth.Fee.GasLimit != 650_000 {
		t.Fatalf("gas limit = %d, want the record's own", auth.Fee.GasLimit)
	}
	var msg taskv1.MsgRecordDispatch
	if err := proto.Unmarshal(body.Messages[0].Value, &msg); err != nil || !proto.Equal(&msg, recordMsg(sg.Address())) {
		t.Fatalf("message = %v, %v", &msg, err)
	}
	// The broadcast bytes can be sent again unchanged.
	if _, err := sub.BroadcastTx(context.Background(), p.raws[0]); err != nil || len(chain.broadcasts) != 2 || chain.broadcasts[1] != 42 {
		t.Fatalf("rebroadcast = %v, sequences %v", err, chain.broadcasts)
	}
}

// accountsChain answers AccountInfo with seqs in turn, the last one repeating.
type accountsChain struct {
	*seqChain
	seqs []uint64
}

func (c *accountsChain) AccountInfo(context.Context, string) (chaincli.AccountInfo, error) {
	c.accQueries++
	seq := c.seqs[0]
	if len(c.seqs) > 1 {
		c.seqs = c.seqs[1:]
	}
	return chaincli.AccountInfo{AccountNumber: 7, Sequence: seq}, nil
}

// A sequence mismatch re-signs at the chain's sequence; the re-signed bytes are persisted before
// they are broadcast.
func TestRecordSubmitterPersistsTheResignedTx(t *testing.T) {
	chain := &seqChain{}
	chain.push(chaincli.TxResult{Code: 32, RawLog: "account sequence mismatch, expected 50, got 42"}, nil)
	sub, sg := newRecordSubmitter(t, &accountsChain{seqChain: chain, seqs: []uint64{42, 50}}, testKeyHex, nil)
	p := &persisted{chain: chain}
	if _, err := sub.SubmitRecordDispatch(context.Background(), recordMsg(sg.Address()), 650_000, p.persist); err != nil {
		t.Fatal(err)
	}
	if len(p.raws) != 2 || p.broadcastsAt[0] != 0 || p.broadcastsAt[1] != 1 {
		t.Fatalf("persisted %d at %v", len(p.raws), p.broadcastsAt)
	}
	if len(chain.broadcasts) != 2 || chain.broadcasts[0] != 42 || chain.broadcasts[1] != 50 {
		t.Fatalf("broadcast sequences = %v", chain.broadcasts)
	}
}

// Bytes that could not be persisted are not broadcast, and their sequence stays free.
func TestRecordSubmitterPersistFailureBroadcastsNothing(t *testing.T) {
	chain := &seqChain{accSeq: 42}
	sub, sg := newRecordSubmitter(t, chain, testKeyHex, nil)
	p := &persisted{chain: chain, fail: errors.New("disk full")}
	if _, err := sub.SubmitRecordDispatch(context.Background(), recordMsg(sg.Address()), 650_000, p.persist); err == nil {
		t.Fatal("submitted without persisting")
	}
	if len(chain.broadcasts) != 0 {
		t.Fatalf("broadcast %v", chain.broadcasts)
	}
	p.fail = nil
	if _, err := sub.SubmitRecordDispatch(context.Background(), recordMsg(sg.Address()), 650_000, p.persist); err != nil || chain.broadcasts[0] != 42 {
		t.Fatalf("retry = %v, sequences %v", err, chain.broadcasts)
	}
	// A submitter_address other than the service account is refused before anything is signed.
	if _, err := sub.SubmitRecordDispatch(context.Background(), recordMsg("trueopen1other"), 0, p.persist); err == nil || len(p.raws) != 1 {
		t.Fatalf("foreign submitter = %v, persisted %d", err, len(p.raws))
	}
}

// When the service key is the account key, record transactions share the account's sequence
// with the other task transactions; a separate service key has its own.
func TestRecordSubmitterSharesTheAccountSequence(t *testing.T) {
	chain := &seqChain{accSeq: 42}
	tasks, address := newSeqSubmitter(t, chain)
	records, sg := newRecordSubmitter(t, chain, testKeyHex, tasks)
	p := &persisted{chain: chain}
	if _, err := tasks.SubmitSettle(context.Background(), sequenceSettle(address, "t")); err != nil {
		t.Fatal(err)
	}
	if _, err := records.SubmitRecordDispatch(context.Background(), recordMsg(sg.Address()), 0, p.persist); err != nil {
		t.Fatal(err)
	}
	if chain.accQueries != 1 || chain.broadcasts[1] != 43 {
		t.Fatalf("queries %d, sequences %v", chain.accQueries, chain.broadcasts)
	}
	separate, other := newRecordSubmitter(t, chain, otherKeyHex, tasks)
	if _, err := separate.SubmitRecordDispatch(context.Background(), recordMsg(other.Address()), 0, p.persist); err != nil {
		t.Fatal(err)
	}
	if chain.accQueries != 2 {
		t.Fatalf("a separate service account did not read its own sequence (%d queries)", chain.accQueries)
	}
}

// Rebuttals and challenge responses go from the service account on the record transactions'
// sequence: the responder_address must be that account.
func TestRecordSubmitterSendsRebuttalsAndChallengeResponses(t *testing.T) {
	chain := &seqChain{accSeq: 42}
	sub, sg := newRecordSubmitter(t, chain, testKeyHex, nil)
	rebut := &taskv1.MsgRebutDispatchCompensation{
		DispatchTicketHash: bytes.Repeat([]byte{1}, 32), ResponderAddress: sg.Address(), Record: &taskv1.DispatchRecordV1{OrderSequence: 3},
	}
	if res, err := sub.SubmitRebutDispatchCompensation(context.Background(), rebut, 777_000); err != nil || res.Code != 0 {
		t.Fatalf("rebut = %+v, %v", res, err)
	}
	respond := &taskv1.MsgRespondDispatchChallenge{
		ChallengeId: bytes.Repeat([]byte{2}, 32), ResponderAddress: sg.Address(),
		Response: &taskv1.MsgRespondDispatchChallenge_Roster{Roster: &taskv1.DispatchRosterV1{ReferenceHeight: 9}},
	}
	if res, err := sub.SubmitRespondDispatchChallenge(context.Background(), respond, 888_000); err != nil || res.Code != 0 {
		t.Fatalf("respond = %+v, %v", res, err)
	}
	if len(chain.raws) != 2 || chain.broadcasts[0] != 42 || chain.broadcasts[1] != 43 {
		t.Fatalf("broadcast sequences %v", chain.broadcasts)
	}
	for i, want := range []struct {
		typeURL string
		msg     proto.Message
		out     proto.Message
	}{
		{chaincli.TypeURLMsgRebutDispatchCompensation, rebut, &taskv1.MsgRebutDispatchCompensation{}},
		{chaincli.TypeURLMsgRespondDispatchChallenge, respond, &taskv1.MsgRespondDispatchChallenge{}},
	} {
		body, auth := decodeBuilderTx(t, chain.raws[i])
		if gas := auth.Fee.GasLimit; gas != []uint64{777_000, 888_000}[i] {
			t.Fatalf("tx %d gas limit %d, want its own", i, gas)
		}
		if body.Messages[0].TypeUrl != want.typeURL || proto.Unmarshal(body.Messages[0].Value, want.out) != nil || !proto.Equal(want.out, want.msg) {
			t.Fatalf("tx %d = %s %v", i, body.Messages[0].TypeUrl, want.out)
		}
	}
	rebut.ResponderAddress = "trueopen1other"
	if _, err := sub.SubmitRebutDispatchCompensation(context.Background(), rebut, 777_000); err == nil || len(chain.broadcasts) != 2 {
		t.Fatalf("foreign responder = %v", err)
	}
	respond.ResponderAddress = "trueopen1other"
	if _, err := sub.SubmitRespondDispatchChallenge(context.Background(), respond, 888_000); err == nil || len(chain.broadcasts) != 2 {
		t.Fatalf("foreign responder = %v", err)
	}
}
