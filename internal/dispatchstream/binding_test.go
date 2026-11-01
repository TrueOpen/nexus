package dispatchstream

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/wirefixture"
	"github.com/TrueOpen/wire/dispatch"
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

func (v vectorKeys) ProofOptions(_ context.Context, earliestSubmitHeight *uint64) dispatch.ProofKeyOptions {
	return dispatch.ProofKeyOptions{OrderEarliestSubmitHeight: earliestSubmitHeight, LookupProofKey: func(s dispatch.ServiceProofSigner) (dispatch.ProofKeyBinding, error) {
		if s.OperatorAddress != v.operator {
			return dispatch.ProofKeyBinding{}, errors.New("unknown operator")
		}
		return dispatch.ProofKeyBinding{PublicKey: v.key.PubKey, ServiceAuthorizationNonce: v.key.AuthorizationNonce, Status: dispatch.ProofKeyActive}, nil
	}}
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
		{"previous key", func(h *harness) *nexusv1.DispatchStreamFrameV1 {
			h.keys.nonce[cortexA] = testNonce + 1
			h.keys.previous[cortexA] = previousKey{key: h.keys.signer(cortexA), nonce: testNonce, retired: 100}
			return bindingFrame(h.keys.binding(h.t, cortexA, hash32("n")))
		}, ErrBindingInvalid},
		{"revoked current key", func(h *harness) *nexusv1.DispatchStreamFrameV1 {
			h.keys.revoked[cortexA] = true
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
		// Wire computes no signing digest for these, so they carry an arbitrary signature.
		{"stream_nonce shorter than 32 bytes", func(h *harness) *nexusv1.DispatchStreamFrameV1 {
			return bindingFrame(unsignedBinding(cortexA, 1, hash32("n")[:31]))
		}, ErrBindingInvalid},
		{"stream_nonce longer than 32 bytes", func(h *harness) *nexusv1.DispatchStreamFrameV1 {
			return bindingFrame(unsignedBinding(cortexA, 1, append(hash32("n"), 0)))
		}, ErrBindingInvalid},
		{"schema_version 2", func(h *harness) *nexusv1.DispatchStreamFrameV1 {
			return bindingFrame(unsignedBinding(cortexA, 2, hash32("n")))
		}, ErrBindingInvalid},
		{"binding frame with a cursor", func(h *harness) *nexusv1.DispatchStreamFrameV1 {
			f := bindingFrame(h.keys.binding(h.t, cortexA, hash32("n")))
			f.Cursor = 1
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

// unsignedBinding is a binding with an arbitrary 64-byte signature.
func unsignedBinding(operator string, schemaVersion uint32, streamNonce []byte) *nexusv1.DispatchStreamBindingV1 {
	return &nexusv1.DispatchStreamBindingV1{
		SchemaVersion: schemaVersion, ChainId: testChainID, BuilderOperator: testBuilder, CortexOperator: operator,
		ServiceAuthorizationNonce: testNonce, StreamNonce: streamNonce, ServiceSignature: make([]byte, 64),
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

// The Builder ends a Cortex's stream as soon as it sees that the key that authenticated the
// binding is no longer that Cortex's current ACTIVE key: the Cortex rotated (a new generation became
// current) or its key was revoked. Another Cortex's streams, a stream already bound under the new
// generation and this Builder's own rotation end nothing.
func TestCortexKeyEventsEndTheStreamsTheyRetire(t *testing.T) {
	h := newHarness(t)
	a, b := h.connect(cortexA, "1"), h.connect(cortexB, "2")
	rotated := func(participant sharedv1.ParticipantType, operator string, nonce uint64) chaincli.ChainEvent {
		return chaincli.ChainEvent{Type: chaincli.EventHubOperational, EventCode: "SERVICE_KEY_ROTATED",
			Typed: chaincli.ServiceKeyRotated{ParticipantType: participant, Operator: operator, AuthorizationNonce: nonce}}
	}
	h.hub.ObserveEvent(rotated(sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER, testBuilder, testNonce+1))
	h.hub.ObserveEvent(rotated(sharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX, cortexA, testNonce))
	if !h.hub.Connected(cortexA) || !h.hub.Connected(cortexB) {
		t.Fatal("a stream ended on a rotation that did not retire its binding key")
	}
	h.hub.ObserveEvent(rotated(sharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX, cortexA, testNonce+1))
	if err := a.wait(t); !errors.Is(err, ErrBindingKeyRetired) {
		t.Fatalf("stream after its Cortex rotated ended with %v, want ErrBindingKeyRetired", err)
	}
	if !h.hub.Connected(cortexB) {
		t.Fatal("another Cortex's stream ended")
	}
	h.hub.ObserveEvent(chaincli.ChainEvent{Type: chaincli.EventHubOperational, EventCode: "SERVICE_KEY_REVOKED",
		Typed: chaincli.ServiceKeyRevoked{ParticipantType: sharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX, Operator: cortexB, AuthorizationNonce: testNonce}})
	if err := b.wait(t); !errors.Is(err, ErrBindingKeyRetired) {
		t.Fatalf("stream after its Cortex key was revoked ended with %v, want ErrBindingKeyRetired", err)
	}
	// The Cortex binds again under its new current key.
	h.keys.nonce[cortexA] = testNonce + 1
	nonce := hash32("stream|3")
	binding := h.keys.binding(t, cortexA, nonce)
	binding.ServiceAuthorizationNonce = testNonce + 1
	h.keys.signBinding(t, binding)
	h.open(bindingFrame(binding))
	h.waitConn(cortexA, true)
}

// A Cortex that registered a key rotation keeps its stream until the rotation activates: the
// Builder only stops admitting its standing handraises (in the roots it signs), while the messages
// of tasks already dispatched to it (accepts, input requests) still go through.
func TestCortexRotationRegistrationKeepsTheStream(t *testing.T) {
	h := newHarness(t)
	s := h.connect(cortexA, "1")
	h.hub.ObserveEvent(chaincli.ChainEvent{Type: chaincli.EventHubOperational, EventCode: "SERVICE_KEY_ROTATION_REGISTERED",
		Typed: chaincli.ServiceKeyRotationRegistered{ParticipantType: sharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX, Operator: cortexA,
			CurrentAuthorizationNonce: testNonce, NextAuthorizationNonce: testNonce + 1, EffectiveHeight: 400}})
	if !h.hub.Connected(cortexA) {
		t.Fatal("a registered rotation ended the stream")
	}
	for _, f := range []*nexusv1.DispatchStreamFrameV1{
		acceptFrame(h.keys.accept(t, cortexA, "t1")), inputRequestFrame(h.keys.inputRequest(t, cortexA, "t1")),
	} {
		if cursor := s.send(f); s.stream.nextAck(t) != cursor {
			t.Fatal("an in-flight task message was not acknowledged")
		}
	}
	if got := h.sinks.kinds(); !slices.Equal(got, []string{"accept", "input_request"}) {
		t.Fatalf("routed %v", got)
	}
}

// A key event the Builder missed is caught on the next keepalive tick: a stream whose binding key
// is no longer its Cortex's current one, or whose Cortex has no current key, ends; a chain that
// cannot answer ends nothing.
func TestKeepaliveTickEndsAStreamWhoseBindingKeyIsGone(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(k *testKeys)
		ended  bool
	}{
		{"rotated", func(k *testKeys) { k.nonce[cortexA] = testNonce + 1 }, true},
		{"revoked", func(k *testKeys) { k.revoked[cortexA] = true }, true},
		{"chain unreadable", func(k *testKeys) { k.transient = true }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			s := h.connect(cortexA, "1")
			h.keys.mu.Lock()
			tc.change(h.keys)
			h.keys.mu.Unlock()
			h.ticks <- time.Time{}
			if !tc.ended {
				h.ticks <- time.Time{} // the first tick was taken, so the check ran
				if !h.hub.Connected(cortexA) {
					t.Fatal("stream ended while the chain could not answer")
				}
				return
			}
			if err := s.wait(t); !errors.Is(err, ErrBindingKeyRetired) {
				t.Fatalf("stream ended with %v, want ErrBindingKeyRetired", err)
			}
		})
	}
}
