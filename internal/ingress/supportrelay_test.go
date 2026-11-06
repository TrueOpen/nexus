package ingress

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/internal/supportrelay"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

type fakeSupportRelay struct {
	epoch        uint64
	confirmation []byte
	ack          supportrelay.Ack
	err          error
}

func (f *fakeSupportRelay) Submit(_ context.Context, epoch uint64, confirmation []byte) (supportrelay.Ack, error) {
	f.epoch, f.confirmation = epoch, append([]byte(nil), confirmation...)
	return f.ack, f.err
}

// The wire relay vector's request reaches the relay with its confirmation bytes untouched, and the
// newly accepted answer encodes to the vector's response bytes.
func TestSubmitModelSupportConfirmationMatchesTheWireVector(t *testing.T) {
	var v struct {
		ConfirmationProtobufHex   string `json:"confirmation_protobuf_hex"`
		RequestProtobufHex        string `json:"request_protobuf_hex"`
		ConfirmationSigningDigest string `json:"confirmation_signing_digest"`
		ResponseProtobufHex       string `json:"response_protobuf_hex"`
	}
	if err := json.Unmarshal(wirefixture.ReadFile(t, "testdata/v1/hub/model_support_relay_v1.json"), &v); err != nil {
		t.Fatal(err)
	}
	rawRequest, _ := hex.DecodeString(v.RequestProtobufHex)
	var req nexusv1.SubmitModelSupportConfirmationRequest
	if err := proto.Unmarshal(rawRequest, &req); err != nil {
		t.Fatal(err)
	}
	digest, _ := hex.DecodeString(v.ConfirmationSigningDigest[2:])
	relay := &fakeSupportRelay{ack: supportrelay.Ack{Digest: [32]byte(digest)}}
	s := newService(&fakeHandler{}, AuthParams{}, withSupportRelay(relay))
	resp, err := s.SubmitModelSupportConfirmation(context.Background(), connect.NewRequest(&req))
	if err != nil {
		t.Fatal(err)
	}
	confirmation, _ := hex.DecodeString(v.ConfirmationProtobufHex)
	if relay.epoch != 42 || !bytes.Equal(relay.confirmation, confirmation) {
		t.Fatalf("relay got epoch %d confirmation %x", relay.epoch, relay.confirmation)
	}
	raw, err := proto.Marshal(resp.Msg)
	if err != nil || hex.EncodeToString(raw) != v.ResponseProtobufHex {
		t.Fatalf("response = %x, %v", raw, err)
	}

	relay.ack.Idempotent = true
	resp, err = s.SubmitModelSupportConfirmation(context.Background(), connect.NewRequest(&req))
	if err != nil || !resp.Msg.GetRelayAccepted() || !resp.Msg.GetIdempotent() || resp.Msg.GetConfirmationSigningDigest() != v.ConfirmationSigningDigest {
		t.Fatalf("idempotent response = %v, %v", resp.Msg, err)
	}
}

// Every refusal is an RPC error with its documented code, never an accepted response.
func TestSubmitModelSupportConfirmationErrorCodes(t *testing.T) {
	for want, err := range map[connect.Code]error{
		connect.CodeInvalidArgument:    supportrelay.ErrMalformed,
		connect.CodeUnauthenticated:    supportrelay.ErrInvalidSignature,
		connect.CodeFailedPrecondition: supportrelay.ErrStale,
		connect.CodeAlreadyExists:      supportrelay.ErrConflict,
		connect.CodeResourceExhausted:  supportrelay.ErrLimit,
		connect.CodeUnavailable:        supportrelay.ErrUnavailable,
		connect.CodeInternal:           errors.New("unclassified"),
	} {
		s := newService(&fakeHandler{}, AuthParams{}, withSupportRelay(&fakeSupportRelay{err: fmt.Errorf("detail: %w", err)}))
		resp, got := s.SubmitModelSupportConfirmation(context.Background(), connect.NewRequest(&nexusv1.SubmitModelSupportConfirmationRequest{
			EpochIndex: 1, Confirmation: []byte{1},
		}))
		if connect.CodeOf(got) != want || resp != nil {
			t.Errorf("%v: code %v, response %v", err, connect.CodeOf(got), resp)
		}
	}
}

func TestSubmitModelSupportConfirmationUnimplementedWithoutARelay(t *testing.T) {
	s := newService(&fakeHandler{}, AuthParams{})
	_, err := s.SubmitModelSupportConfirmation(context.Background(), connect.NewRequest(&nexusv1.SubmitModelSupportConfirmationRequest{}))
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("code %v", connect.CodeOf(err))
	}
}
