package dispatchstream

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

// vectorKeys answers with one fixed key, as the chain would for the wire vector's Cortex.
type vectorKeys struct {
	operator string
	key      CortexKey
}

func (v vectorKeys) CurrentCortexKey(_ context.Context, operator string) (CortexKey, error) {
	if operator != v.operator {
		return CortexKey{}, errors.New("unknown operator")
	}
	return v.key, nil
}

// The binding check reproduces the wire vector: its exact protobuf decodes, and verifies under the
// vector's key, chain, Builder and nonce.
func TestBindingAcceptsTheWireVector(t *testing.T) {
	var file struct {
		Vectors []struct {
			Name         string `json:"name"`
			ProtobufHex  string `json:"protobuf_hex"`
			DigestHex    string `json:"digest_hex"`
			PublicKeyHex string `json:"public_key_hex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(wirefixture.ReadFile(t, "testdata/v1/task/dispatch_v1.json"), &file); err != nil {
		t.Fatal(err)
	}
	for _, vector := range file.Vectors {
		if vector.Name != "nexus_v1_dispatchstreambindingv1" {
			continue
		}
		raw, _ := hex.DecodeString(vector.ProtobufHex)
		binding := &nexusv1.DispatchStreamBindingV1{}
		if err := proto.Unmarshal(raw, binding); err != nil {
			t.Fatal(err)
		}
		pub, _ := hex.DecodeString(vector.PublicKeyHex)
		keys := vectorKeys{binding.GetCortexOperator(), CortexKey{PubKey: pub, AuthorizationNonce: binding.GetServiceAuthorizationNonce()}}
		hub, err := New(nil, Config{ChainID: binding.GetChainId(), BuilderOperator: binding.GetBuilderOperator()}, keys, kv.NewMemStore())
		if err != nil {
			t.Fatal(err)
		}
		frame := &nexusv1.DispatchStreamFrameV1{StreamNonce: binding.GetStreamNonce(),
			Message: &nexusv1.DispatchStreamFrameV1_Binding{Binding: binding}}
		if _, err := hub.verifyBinding(context.Background(), frame); err != nil {
			t.Fatalf("wire vector binding refused: %v", err)
		}
		keys.key.AuthorizationNonce++
		hub.keys = keys
		if _, err := hub.verifyBinding(context.Background(), frame); !errors.Is(err, ErrBindingInvalid) {
			t.Fatalf("vector binding under another nonce = %v, want ErrBindingInvalid", err)
		}
		return
	}
	t.Fatal("binding vector not found")
}

func TestBindingRefusals(t *testing.T) {
	cases := []struct {
		name  string
		frame func(h *harness) *nexusv1.DispatchStreamFrameV1
		want  error
	}{
		{"not a binding", func(h *harness) *nexusv1.DispatchStreamFrameV1 {
			return &nexusv1.DispatchStreamFrameV1{StreamNonce: hash32("n"),
				Message: &nexusv1.DispatchStreamFrameV1_Ack{Ack: &nexusv1.StreamAckV1{}}}
		}, ErrBindingInvalid},
		{"bad signature", func(h *harness) *nexusv1.DispatchStreamFrameV1 {
			b := h.keys.binding(h.t, cortexA, hash32("n"))
			b.ServiceSignature = h.keys.binding(h.t, cortexB, hash32("n")).GetServiceSignature()
			return bindingFrame(b)
		}, ErrBindingInvalid},
		{"wrong builder", func(h *harness) *nexusv1.DispatchStreamFrameV1 {
			b := h.keys.binding(h.t, cortexA, hash32("n"))
			b.BuilderOperator = cortexB
			h.keys.signBinding(h.t, b)
			return bindingFrame(b)
		}, ErrBindingInvalid},
		{"wrong chain", func(h *harness) *nexusv1.DispatchStreamFrameV1 {
			b := h.keys.binding(h.t, cortexA, hash32("n"))
			b.ChainId = "other-chain"
			h.keys.signBinding(h.t, b)
			return bindingFrame(b)
		}, ErrBindingInvalid},
		{"stale nonce", func(h *harness) *nexusv1.DispatchStreamFrameV1 {
			h.keys.nonce[cortexA] = testNonce + 1
			return bindingFrame(h.keys.binding(h.t, cortexA, hash32("n")))
		}, ErrBindingInvalid},
		{"no current key", func(h *harness) *nexusv1.DispatchStreamFrameV1 {
			h.keys.missing[cortexA] = true
			return bindingFrame(h.keys.binding(h.t, cortexA, hash32("n")))
		}, ErrBindingInvalid},
		{"frame stream_nonce differs", func(h *harness) *nexusv1.DispatchStreamFrameV1 {
			f := bindingFrame(h.keys.binding(h.t, cortexA, hash32("n")))
			f.StreamNonce = hash32("other")
			return f
		}, ErrBindingInvalid},
		{"chain unreadable", func(h *harness) *nexusv1.DispatchStreamFrameV1 {
			h.keys.setTransient(true)
			return bindingFrame(h.keys.binding(h.t, cortexA, hash32("n")))
		}, ErrTransient},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			s := h.open(tc.frame(h))
			if err := s.wait(t); !errors.Is(err, tc.want) {
				t.Fatalf("Serve = %v, want %v", err, tc.want)
			}
			if h.hub.Connected(cortexA) {
				t.Fatal("a refused stream is connected")
			}
		})
	}
}

func bindingFrame(b *nexusv1.DispatchStreamBindingV1) *nexusv1.DispatchStreamFrameV1 {
	return &nexusv1.DispatchStreamFrameV1{StreamNonce: b.GetStreamNonce(),
		Message: &nexusv1.DispatchStreamFrameV1_Binding{Binding: b}}
}

// A binding opens one stream only: the same (operator, nonce, stream_nonce) is refused afterwards,
// also after a restart.
func TestBindingCannotBeReplayed(t *testing.T) {
	store := kv.NewMemStore()
	keys := newTestKeys()
	h := newHarnessOn(t, store, keys)
	first := h.connect(cortexA, "once")
	first.stream.close()
	if err := first.wait(t); err == nil {
		t.Fatal("closed stream ended without an error")
	}
	h.waitConn(cortexA, false)

	replay := h.open(bindingFrame(keys.binding(t, cortexA, hash32("stream|once"))))
	if err := replay.wait(t); !errors.Is(err, ErrBindingInvalid) {
		t.Fatalf("replayed binding = %v, want ErrBindingInvalid", err)
	}
	restarted := newHarnessOn(t, store, keys)
	again := restarted.open(bindingFrame(keys.binding(t, cortexA, hash32("stream|once"))))
	if err := again.wait(t); !errors.Is(err, ErrBindingInvalid) {
		t.Fatalf("replayed binding after restart = %v, want ErrBindingInvalid", err)
	}
	restarted.connect(cortexA, "fresh")
}

// A new valid stream of the same Cortex replaces the old one, which ends with ErrReplaced; the
// Cortex never looks disconnected in between.
func TestNewStreamReplacesTheOld(t *testing.T) {
	h := newHarness(t)
	old := h.connect(cortexA, "1")
	h.connect(cortexA, "2")
	if err := old.wait(t); !errors.Is(err, ErrReplaced) {
		t.Fatalf("old stream ended with %v, want ErrReplaced", err)
	}
	select {
	case ev := <-h.conn:
		t.Fatalf("unexpected connection event %+v", ev)
	default:
	}
	if !h.hub.Connected(cortexA) || len(h.hub.Operators()) != 1 {
		t.Fatalf("operators = %v", h.hub.Operators())
	}
}

// A stream that ends leaves its Cortex not dispatchable, and the observer hears about it.
func TestDisconnectMarksTheCortexUnavailable(t *testing.T) {
	h := newHarness(t)
	a := h.connect(cortexA, "1")
	h.connect(cortexB, "1")
	if got := h.hub.Operators(); len(got) != 2 {
		t.Fatalf("operators = %v", got)
	}
	a.stream.close()
	a.wait(t)
	h.waitConn(cortexA, false)
	if h.hub.Connected(cortexA) || !h.hub.Connected(cortexB) {
		t.Fatalf("connected A=%v B=%v", h.hub.Connected(cortexA), h.hub.Connected(cortexB))
	}
	if err := h.hub.Send(context.Background(), cortexA, offer("x")); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("send to a disconnected Cortex = %v, want ErrNotConnected", err)
	}
}

func TestStopEndsStreamsAndRefusesNewOnes(t *testing.T) {
	h := newHarness(t)
	a := h.connect(cortexA, "1")
	if err := h.hub.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.wait(t); !errors.Is(err, ErrStopped) {
		t.Fatalf("stream ended with %v, want ErrStopped", err)
	}
	late := h.open(bindingFrame(h.keys.binding(t, cortexB, hash32("late"))))
	if err := late.wait(t); !errors.Is(err, ErrStopped) {
		t.Fatalf("new stream after stop = %v, want ErrStopped", err)
	}
}
