package supportrelay

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/hash32text"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/servicekey"
)

// vectorOperator registers the wire relay vector's operator with fixture key 1 at nonce 7.
func vectorOperator(t *testing.T, chain *fakeChain) operator {
	t.Helper()
	return newOperator(t, chain, mustHex(t, "a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4"),
		"0000000000000000000000000000000000000000000000000000000000000001", 7)
}

// The wire vector's confirmation is accepted at its epoch and answered with its signing digest; an
// exact retry, in either published encoding, is idempotent and holds one entry.
func TestSubmitAcceptsTheWireVectorAndRetriesIdempotently(t *testing.T) {
	v := loadRelayVector(t)
	chain := newFakeChain()
	vectorOperator(t, chain)
	r := newTestRelay(t, chain, &fakeSubmitter{chain: chain}, nil)
	ack, err := r.Submit(context.Background(), testEpoch, mustHex(t, v.ConfirmationProtobufHex))
	if err != nil {
		t.Fatal(err)
	}
	if hash32text.Encode(ack.Digest[:]) != v.ConfirmationSigningDigest || ack.Idempotent {
		t.Fatalf("ack = %s idempotent=%v", hash32text.Encode(ack.Digest[:]), ack.Idempotent)
	}
	for _, encoding := range []string{v.ConfirmationProtobufHex, v.EquivalentConfirmationHex} {
		again, err := r.Submit(context.Background(), testEpoch, mustHex(t, encoding))
		if err != nil || !again.Idempotent || again.Digest != ack.Digest {
			t.Fatalf("retry = %+v, %v", again, err)
		}
	}
	if r.Held() != 1 {
		t.Fatalf("held %d", r.Held())
	}
}

func TestSubmitRefusals(t *testing.T) {
	ctx := context.Background()
	type setup struct {
		chain *fakeChain
		op    operator
	}
	fresh := func(t *testing.T) setup {
		chain := newFakeChain()
		return setup{chain: chain, op: vectorOperator(t, chain)}
	}
	other := func(t *testing.T) operator {
		return newOperator(t, newFakeChain(), mustHex(t, "a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4"),
			"0000000000000000000000000000000000000000000000000000000000000002", 7)
	}
	cases := []struct {
		name string
		want error
		run  func(t *testing.T, s setup) (uint64, []byte)
	}{
		{"malformed", ErrMalformed, func(t *testing.T, s setup) (uint64, []byte) { return testEpoch, []byte{0x08} }},
		{"tampered signature", ErrInvalidSignature, func(t *testing.T, s setup) (uint64, []byte) {
			raw := s.op.confirm(t, testEpoch, 1750)
			var m hubv1.ModelSupportConfirmationV1
			_ = proto.Unmarshal(raw, &m)
			m.ServiceSignature[10] ^= 1
			out, _ := proto.Marshal(&m)
			return testEpoch, out
		}},
		{"signed for another epoch", ErrInvalidSignature, func(t *testing.T, s setup) (uint64, []byte) {
			raw := s.op.confirm(t, testEpoch+1, 1750)
			return testEpoch, raw
		}},
		{"signed by a key that is not current", ErrInvalidSignature, func(t *testing.T, s setup) (uint64, []byte) {
			return testEpoch, other(t).confirm(t, testEpoch, 1750)
		}},
		{"signed by the previous key", ErrInvalidSignature, func(t *testing.T, s setup) (uint64, []byte) {
			old := other(t)
			s.chain.set(func(c *fakeChain) {
				key := c.keys[s.op.address]
				key.Previous = &chaincli.PreviousServiceKey{ServicePubKey: hex.EncodeToString(old.key.PubKeyCompressed()), AuthorizationNonce: 7}
				c.keys[s.op.address] = key
			})
			return testEpoch, old.confirm(t, testEpoch, 1750)
		}},
		{"past epoch", ErrStale, func(t *testing.T, s setup) (uint64, []byte) {
			return testEpoch - 1, s.op.confirm(t, testEpoch-1, 1750)
		}},
		{"future epoch", ErrStale, func(t *testing.T, s setup) (uint64, []byte) {
			return testEpoch + 1, s.op.confirm(t, testEpoch+1, 1750)
		}},
		{"old nonce", ErrStale, func(t *testing.T, s setup) (uint64, []byte) {
			raw := s.op.confirm(t, testEpoch, 1750)
			s.op.nonce = 8
			s.op.register(s.chain)
			return testEpoch, raw
		}},
		{"revoked key", ErrStale, func(t *testing.T, s setup) (uint64, []byte) {
			s.chain.set(func(c *fakeChain) {
				key := c.keys[s.op.address]
				key.Status = servicekey.StatusRevoked
				c.keys[s.op.address] = key
			})
			return testEpoch, s.op.confirm(t, testEpoch, 1750)
		}},
		{"unregistered operator", ErrStale, func(t *testing.T, s setup) (uint64, []byte) {
			s.chain.set(func(c *fakeChain) { delete(c.nodes, s.op.address) })
			return testEpoch, s.op.confirm(t, testEpoch, 1750)
		}},
		{"expired", ErrStale, func(t *testing.T, s setup) (uint64, []byte) {
			return testEpoch, s.op.confirm(t, testEpoch, testHeight)
		}},
		{"expiry within the inclusion margin", ErrStale, func(t *testing.T, s setup) (uint64, []byte) {
			return testEpoch, s.op.confirm(t, testEpoch, testHeight+2)
		}},
		{"expiry beyond the service material window", ErrStale, func(t *testing.T, s setup) (uint64, []byte) {
			return testEpoch, s.op.confirm(t, testEpoch, testHeight+1+601)
		}},
		{"epoch ends within the inclusion margin", ErrStale, func(t *testing.T, s setup) (uint64, []byte) {
			s.chain.set(func(c *fakeChain) { c.height = 1717 })
			return testEpoch, s.op.confirm(t, testEpoch, 1750)
		}},
		{"tombstoned", ErrStale, func(t *testing.T, s setup) (uint64, []byte) {
			s.chain.set(func(c *fakeChain) {
				c.bonds[s.op.address].Status = hubv1.ServiceBondStatus_SERVICE_BOND_STATUS_TOMBSTONED
			})
			return testEpoch, s.op.confirm(t, testEpoch, 1750)
		}},
		{"unbonding", ErrStale, func(t *testing.T, s setup) (uint64, []byte) {
			s.chain.set(func(c *fakeChain) {
				c.bonds[s.op.address].Status = hubv1.ServiceBondStatus_SERVICE_BOND_STATUS_UNBONDING
			})
			return testEpoch, s.op.confirm(t, testEpoch, 1750)
		}},
		{"exited", ErrStale, func(t *testing.T, s setup) (uint64, []byte) {
			s.chain.set(func(c *fakeChain) { c.bonds[s.op.address].Status = hubv1.ServiceBondStatus_SERVICE_BOND_STATUS_EXITED })
			return testEpoch, s.op.confirm(t, testEpoch, 1750)
		}},
		{"no bond", ErrStale, func(t *testing.T, s setup) (uint64, []byte) {
			s.chain.set(func(c *fakeChain) { delete(c.bonds, s.op.address) })
			return testEpoch, s.op.confirm(t, testEpoch, 1750)
		}},
		{"more models than an operator may support", ErrLimit, func(t *testing.T, s setup) (uint64, []byte) {
			s.chain.set(func(c *fakeChain) { c.params.MaxSupportedModelsPerOperator = 1 })
			return testEpoch, s.op.confirm(t, testEpoch, 1750)
		}},
		{"more models than a batch may carry", ErrLimit, func(t *testing.T, s setup) (uint64, []byte) {
			s.chain.set(func(c *fakeChain) { c.params.MaxItemsPerBatch = 1 })
			return testEpoch, s.op.confirm(t, testEpoch, 1750)
		}},
		{"a batch of it alone is too large", ErrLimit, func(t *testing.T, s setup) (uint64, []byte) {
			s.chain.set(func(c *fakeChain) { c.params.MaxBatchBytes = 150 })
			return testEpoch, s.op.confirm(t, testEpoch, 1750)
		}},
		{"height unavailable", ErrUnavailable, func(t *testing.T, s setup) (uint64, []byte) {
			s.chain.set(func(c *fakeChain) { c.heightErr = errors.New("down") })
			return testEpoch, s.op.confirm(t, testEpoch, 1750)
		}},
		{"params unavailable", ErrUnavailable, func(t *testing.T, s setup) (uint64, []byte) {
			s.chain.set(func(c *fakeChain) { c.paramsErr = errors.New("down") })
			return testEpoch, s.op.confirm(t, testEpoch, 1750)
		}},
		{"node unavailable", ErrUnavailable, func(t *testing.T, s setup) (uint64, []byte) {
			s.chain.set(func(c *fakeChain) { c.nodeErr = errors.New("down") })
			return testEpoch, s.op.confirm(t, testEpoch, 1750)
		}},
		{"service key unavailable", ErrUnavailable, func(t *testing.T, s setup) (uint64, []byte) {
			s.chain.set(func(c *fakeChain) { c.keyErr = errors.New("down") })
			return testEpoch, s.op.confirm(t, testEpoch, 1750)
		}},
		{"bond unavailable", ErrUnavailable, func(t *testing.T, s setup) (uint64, []byte) {
			s.chain.set(func(c *fakeChain) { c.bondErr = errors.New("down") })
			return testEpoch, s.op.confirm(t, testEpoch, 1750)
		}},
		{"daily support unavailable", ErrUnavailable, func(t *testing.T, s setup) (uint64, []byte) {
			s.chain.set(func(c *fakeChain) { c.dailyErr = errors.New("down") })
			return testEpoch, s.op.confirm(t, testEpoch, 1750)
		}},
	}
	for _, tc := range cases {
		s := fresh(t)
		r := newTestRelay(t, s.chain, &fakeSubmitter{chain: s.chain}, nil)
		epoch, raw := tc.run(t, s)
		ack, err := r.Submit(ctx, epoch, raw)
		wantErr(t, tc.name, err, tc.want)
		if err == nil || ack != (Ack{}) || r.Held() != 0 {
			t.Errorf("%s: acknowledged %+v, held %d", tc.name, ack, r.Held())
		}
	}
}

// Stale support rows and ordinary jail do not stop a refresh.
func TestSubmitAcceptsJailedOperators(t *testing.T) {
	chain := newFakeChain()
	op := vectorOperator(t, chain)
	chain.set(func(c *fakeChain) {
		c.bonds[op.address].Status, c.bonds[op.address].JailCount = hubv1.ServiceBondStatus_SERVICE_BOND_STATUS_JAILED, 1
	})
	r := newTestRelay(t, chain, &fakeSubmitter{chain: chain}, nil)
	if _, err := r.Submit(context.Background(), testEpoch, op.confirm(t, testEpoch, 1750)); err != nil {
		t.Fatal(err)
	}
}

// Other material for an occupied (operator, epoch) slot conflicts, whether the slot is held here
// or on chain; the chain's own row of the same material is an idempotent retry.
func TestSubmitConflictsWithOtherMaterialForTheSlot(t *testing.T) {
	ctx := context.Background()
	chain := newFakeChain()
	op := vectorOperator(t, chain)
	r := newTestRelay(t, chain, &fakeSubmitter{chain: chain}, nil)
	if _, err := r.Submit(ctx, testEpoch, op.confirm(t, testEpoch, 1750)); err != nil {
		t.Fatal(err)
	}
	_, err := r.Submit(ctx, testEpoch, op.confirm(t, testEpoch, 1760))
	wantErr(t, "queued conflict", err, ErrConflict)
	_, err = r.Submit(ctx, testEpoch, op.confirm(t, testEpoch, 1750, testModel(1)))
	wantErr(t, "queued conflict, other models", err, ErrConflict)

	onChain := newFakeChain()
	op = vectorOperator(t, onChain)
	accepted := op.confirm(t, testEpoch, 1750)
	var conf hubv1.ModelSupportConfirmationV1
	if err := proto.Unmarshal(accepted, &conf); err != nil {
		t.Fatal(err)
	}
	onChain.set(func(c *fakeChain) { c.accept(&conf, testEpoch) })
	r = newTestRelay(t, onChain, &fakeSubmitter{chain: onChain}, nil)
	ack, err := r.Submit(ctx, testEpoch, accepted)
	if err != nil || !ack.Idempotent {
		t.Fatalf("chain-accepted retry = %+v, %v", ack, err)
	}
	_, err = r.Submit(ctx, testEpoch, op.confirm(t, testEpoch, 1760))
	wantErr(t, "chain conflict", err, ErrConflict)
	if r.Held() != 0 {
		t.Fatalf("held %d", r.Held())
	}
}

// A held acknowledgement authorizes nothing by itself: a retry after the key moved on is refused.
func TestSubmitRetryStillPassesLiveValidation(t *testing.T) {
	ctx := context.Background()
	chain := newFakeChain()
	op := vectorOperator(t, chain)
	r := newTestRelay(t, chain, &fakeSubmitter{chain: chain}, nil)
	raw := op.confirm(t, testEpoch, 1750)
	if _, err := r.Submit(ctx, testEpoch, raw); err != nil {
		t.Fatal(err)
	}
	op.nonce = 8
	op.register(chain)
	_, err := r.Submit(ctx, testEpoch, raw)
	wantErr(t, "retry after rotation", err, ErrStale)
}

func TestSubmitRefusesWhenTheQueueIsFull(t *testing.T) {
	ctx := context.Background()
	chain := newFakeChain()
	a := newOperator(t, chain, testModel(1)[:20], "0000000000000000000000000000000000000000000000000000000000000011", 1)
	b := newOperator(t, chain, testModel(2)[:20], "0000000000000000000000000000000000000000000000000000000000000012", 1)
	cfg := testConfig()
	cfg.MaxQueued = 1
	r, err := New(cfg, nil, chain, &fakeSubmitter{chain: chain}, kv.NewMemStore())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Submit(ctx, testEpoch, a.confirm(t, testEpoch, 1750)); err != nil {
		t.Fatal(err)
	}
	_, err = r.Submit(ctx, testEpoch, b.confirm(t, testEpoch, 1750))
	wantErr(t, "full queue", err, ErrLimit)
	if again, err := r.Submit(ctx, testEpoch, a.confirm(t, testEpoch, 1750)); err != nil || !again.Idempotent {
		t.Fatalf("a held retry on a full queue = %+v, %v", again, err)
	}
}
