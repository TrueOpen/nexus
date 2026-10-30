package buildersync

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

// syncVectors are wire's Builder sync transport vectors: a full batch, a Fin-only retry, a round
// only and an unfinished record with a ZERO32 winner ticket.
type syncVectors struct {
	ChainID  string `json:"chain_id"`
	Sender   string `json:"sender_operator_address"`
	Receiver string `json:"receiver_operator_address"`
	Vectors  []struct {
		Name       string `json:"name"`
		Protobuf   string `json:"protobuf_hex"`
		Equivalent string `json:"equivalent_protobuf_hex"`
		Digest     string `json:"digest_hex"`
		PublicKey  string `json:"public_key_hex"`
		Signature  string `json:"signature_hex"`
	} `json:"vectors"`
}

func readSyncVectors(t *testing.T) syncVectors {
	t.Helper()
	var v syncVectors
	if err := json.Unmarshal(wirefixture.ReadFile(t, "testdata/v1/task/builder_sync_v1.json"), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Vectors) != 4 {
		t.Fatalf("builder sync vectors = %d, want 4", len(v.Vectors))
	}
	return v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// vectorKey is the test-only service key of the vectors (0x01 repeated).
func vectorKey(t *testing.T) signer.Signer { return newSigner(t, 0x01) }

// The sender signs a batch exactly as wire's vectors do: the canonical typed batch, not its bytes.
func TestSignRequestReproducesTheWireVectors(t *testing.T) {
	v := readSyncVectors(t)
	key := vectorKey(t)
	for _, row := range v.Vectors {
		t.Run(row.Name, func(t *testing.T) {
			if hex.EncodeToString(key.PubKeyCompressed()) != row.PublicKey {
				t.Fatalf("vector key = %s", row.PublicKey)
			}
			var req nexusv1.SyncRequest
			if err := proto.Unmarshal(unhex(t, row.Protobuf), &req); err != nil {
				t.Fatal(err)
			}
			signed, err := SignRequest(key, req.GetBatch())
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(signed.GetSenderSignature()); got != row.Signature {
				t.Fatalf("signature = %s, want %s", got, row.Signature)
			}
			digest, err := dispatch.SigningDigest(requestName, mustMarshal(t, signed))
			if err != nil || hex.EncodeToString(digest[:]) != row.Digest {
				t.Fatalf("digest = %x, %v", digest, err)
			}
		})
	}
	var req nexusv1.SyncRequest
	if err := proto.Unmarshal(unhex(t, v.Vectors[3].Protobuf), &req); err != nil {
		t.Fatal(err)
	}
	var record []byte
	for _, item := range req.GetBatch().GetItems() {
		if r := item.GetRecord(); r != nil {
			record = r.GetRecord().GetDispatchTicketHash()
		}
	}
	if !bytes.Equal(record, make([]byte, 32)) {
		t.Fatalf("unfinished record winner ticket = %x, want ZERO32", record)
	}
}

// vectorReceiver is a receiver that is the vectors' receiver, with their sender's current key.
func vectorReceiver(t *testing.T, v syncVectors) (*Receiver, *fakeKeys) {
	t.Helper()
	keys := &fakeKeys{keys: map[string]signer.Signer{}}
	keys.set("BUILDER", party{op: v.Sender, key: vectorKey(t)})
	r, err := NewReceiver(ReceiverConfig{
		ChainID: v.ChainID, Builder: v.Receiver, AddressPrefix: prefix, Keys: keys, Groups: &fakeGroups{}, Store: kv.NewMemStore(),
		Evidence: nopEvidence{}, Inputs: StoredInputs{}, Outputs: nopReplicas{}, Chain: &fakeRecords{}, Retention: evidenceParams.RetainUntil,
		MaxInputBytes: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r, keys
}

// A receiver authenticates every vector in either encoding under the sender's current key, and
// nothing else: another key, chain or receiver, or a key the chain cannot answer.
func TestReceiverAuthenticatesTheWireVectors(t *testing.T) {
	v := readSyncVectors(t)
	for _, row := range v.Vectors {
		t.Run(row.Name, func(t *testing.T) {
			r, keys := vectorReceiver(t, v)
			for _, encoded := range []string{row.Protobuf, row.Equivalent} {
				if _, err := r.authenticate(context.Background(), v.Sender, unhex(t, encoded)); err != nil {
					t.Fatalf("vector: %v", err)
				}
			}
			keys.set("BUILDER", party{op: v.Sender, key: newSigner(t, 0x02)})
			if _, err := r.authenticate(context.Background(), v.Sender, unhex(t, row.Protobuf)); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("retired key: %v", err)
			}
			keys.fails = true
			if _, err := r.authenticate(context.Background(), v.Sender, unhex(t, row.Protobuf)); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("unreadable key: %v", err)
			}
			keys.fails = false
			keys.set("BUILDER", party{op: v.Sender, key: vectorKey(t)})
			r.cfg.ChainID = v.ChainID + "-other"
			if _, err := r.authenticate(context.Background(), v.Sender, unhex(t, row.Protobuf)); err == nil {
				t.Fatal("authenticated on another chain")
			}
		})
	}
}

// The request bytes are checked before they are decoded: a duplicate singular field or an unknown
// field, both of which a generated decoder would silently accept, refuses the request.
func TestReceiverValidatesTheRawRequest(t *testing.T) {
	e := newEnv(t)
	raw := e.signed(e.firstBatch())
	duplicate := protowire.AppendTag(append([]byte(nil), raw...), 2, protowire.BytesType)
	duplicate = protowire.AppendBytes(duplicate, bytes.Repeat([]byte{1}, 64))
	unknown := protowire.AppendTag(append([]byte(nil), raw...), 15, protowire.VarintType)
	unknown = protowire.AppendVarint(unknown, 1)
	for name, req := range map[string][]byte{"duplicate field": duplicate, "unknown field": unknown, "oversized": make([]byte, MaxRequestBytes+1)} {
		if _, err := e.member.r.Sync(context.Background(), req); !errors.Is(err, ErrMalformed) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if e.copyOf() != nil || len(e.keys.lookups) != 0 {
		t.Fatal("a malformed request was looked at")
	}
	if resp, err := e.member.r.Sync(context.Background(), raw); err != nil || resp.GetRefused() != "" {
		t.Fatalf("the genuine request = %v, %v", resp, err)
	}
}

// An item sent again must be the item applied at its sequence: an exact duplicate is skipped, a
// different payload at an applied sequence is refused.
func TestConflictingItemAtAnAppliedSequenceIsRefused(t *testing.T) {
	e := newEnv(t)
	batch := e.firstBatch()
	if resp, err := e.member.r.Sync(context.Background(), e.signed(batch)); err != nil || resp.GetRefused() != "" {
		t.Fatalf("first batch = %v, %v", resp, err)
	}
	applied := uint64(len(batch.Items))
	if resp, err := e.member.r.Sync(context.Background(), e.signed(batch)); err != nil || resp.GetRefused() != "" || resp.GetAppliedThrough() != applied {
		t.Fatalf("exact duplicate = %v, %v", resp, err)
	}
	changed := proto.Clone(batch).(*nexusv1.BuilderSyncBatchV1)
	changed.Items[0].GetRound().EarliestSubmitHeight++
	resp, err := e.member.r.Sync(context.Background(), e.signed(changed))
	if err != nil || !strings.Contains(resp.GetRefused(), "conflicts") || resp.GetAppliedThrough() != applied {
		t.Fatalf("conflicting duplicate = %v, %v", resp, err)
	}
}

// Every batch stays within the contract's bounds: at most 128 items and output chunks, and the
// complete request within the configured size; the member still gets everything.
func TestBatchesStayWithinTheRequestBounds(t *testing.T) {
	for _, limit := range []int{0, 4096} {
		e := newEnv(t)
		e.s.cfg.InputChunkBytes = 1
		if limit > 0 {
			e.s.cfg.MaxBatchBytes = limit
		}
		f := e.fx
		f.putAccepted()
		f.recordOnChain()
		texts := make([]string, 200)
		for i := range texts {
			texts[i] = "token"
		}
		f.writeOutput(e.dData, e.worker, texts, true)
		e.s.OrderChanged(f.accepted())
		e.s.Recorded(f.recordedAttempt())
		e.s.drain()
		for range 40 {
			e.s.deliverPeer(context.Background(), e.m.op)
		}
		reqs := e.peers.requests[e.m.op]
		var fullItems, fullChunks bool
		for i, req := range reqs {
			items, chunks := len(req.GetBatch().GetItems()), len(req.GetBatch().GetOutput().GetChunks())
			if n := len(e.raw(req)); n > e.s.cfg.MaxBatchBytes || items > dispatch.MaxBuilderSyncEntries || chunks > dispatch.MaxBuilderSyncEntries {
				t.Fatalf("limit %d, request %d: %d bytes, %d items, %d chunks", limit, i, n, items, chunks)
			}
			fullItems = fullItems || items == dispatch.MaxBuilderSyncEntries
			fullChunks = fullChunks || chunks == dispatch.MaxBuilderSyncEntries
		}
		if limit == 0 && (!fullItems || !fullChunks) {
			t.Fatalf("no batch reached the entry bound: items %v, chunks %v", fullItems, fullChunks)
		}
		st := e.s.streams[streamKey(f.sessionHex(), f.sequence)]
		if st.Acked[e.m.op] != st.Last || !st.Output[e.m.op].Sealed {
			t.Fatalf("limit %d: member progress = %d of %d, output %+v", limit, st.Acked[e.m.op], st.Last, st.Output[e.m.op])
		}
	}
}

// A frame or item that cannot fit the request cap even alone is never sent: the member is backed
// off with a warning naming the cap, and nothing it holds changes.
func TestOversizedEntriesAreNotSent(t *testing.T) {
	t.Run("output frame", func(t *testing.T) {
		e := newEnv(t)
		var logs bytes.Buffer
		e.s.log = slog.New(slog.NewTextHandler(&logs, nil))
		f := e.fx
		f.putAccepted()
		f.recordOnChain()
		e.s.OrderChanged(f.accepted())
		e.s.Recorded(f.recordedAttempt())
		e.sync()
		st := e.s.streams[streamKey(f.sessionHex(), f.sequence)]
		if st.Acked[e.m.op] != st.Last {
			t.Fatalf("items not delivered: %d of %d", st.Acked[e.m.op], st.Last)
		}
		sent := len(e.peers.requests[e.m.op])
		f.writeOutput(e.dData, e.worker, []string{strings.Repeat("x", 60)}, true)
		e.s.cfg.MaxBatchBytes = 300
		e.clock.advance(time.Hour)
		e.s.deliverPeer(context.Background(), e.m.op)
		if got := len(e.peers.requests[e.m.op]); got != sent {
			t.Fatalf("%d requests sent with a frame over the cap", got-sent)
		}
		if !strings.Contains(logs.String(), "larger than the builder sync request cap") {
			t.Fatalf("no warning about the oversized frame: %s", logs.String())
		}
	})
	t.Run("first item", func(t *testing.T) {
		e := newEnv(t)
		var logs bytes.Buffer
		e.s.log = slog.New(slog.NewTextHandler(&logs, nil))
		e.s.cfg.MaxBatchBytes = 300
		e.s.OrderChanged(e.fx.issued())
		e.sync()
		if n := len(e.peers.requests[e.m.op]); n != 0 {
			t.Fatalf("%d requests sent with an item over the cap", n)
		}
		if !strings.Contains(logs.String(), "larger than the builder sync request cap") {
			t.Fatalf("no warning about the oversized item: %s", logs.String())
		}
	})
}

// The largest output chunk text the configuration admits fits one request with a full header
// and winner ticket.
func TestLargestConfiguredFrameFitsTheRequestCap(t *testing.T) {
	e := newEnv(t)
	batch := e.recordedBatch([]string{"hello, "})
	batch.Items = nil
	chunk := batch.Output.Chunks[0]
	chunk.Text = make([]byte, config.MaxBuilderSyncFrameBytes)
	chunk.CumulativeGeneratedTokens = math.MaxUint64
	chunk.Seq = math.MaxUint64 - 1
	batch.Output.Chunks = []*nexusv1.OutputChunkV1{chunk}
	batch.Output.Fin = nil
	batch.BuilderSetId = strings.Repeat("s", 256)
	batch.OrderSequence = math.MaxUint64
	req := &nexusv1.SyncRequest{Batch: batch, SenderSignature: make([]byte, 64)}
	if n := proto.Size(req); n > MaxRequestBytes {
		t.Fatalf("largest frame request = %d bytes, cap %d", n, MaxRequestBytes)
	}
}
