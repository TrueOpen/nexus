// End-to-end wire test for the current service key query (Implementation Design §4.2).
//
// The external test package chaincli_test is deliberate: only here can both chaincli and
// servicekey be imported at once (the latter depends on the former, so an in-package test would
// form a cycle), and what this test has to guard is exactly the semantics **across those two layers** --
// the request side sends the hub.v1.ParticipantType enum, the response side decodes
// CurrentServiceKeyViewV1, and "the query could not be made" must be reported as chain lookup
// unavailable rather than as unauthorized.
//
// The test drives a real chaincli.New client (h2c + connect.WithGRPC()) against a real Connect
// QueryService handler, so the wire type difference between enum and string really is caught by
// encoding/decoding; a fake resolver would not exercise this layer.
package chaincli_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/hub/v1/hubv1connect"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/signer"
)

const wireTestPrefix = "trueopen"

// hubQueryStub implements only CurrentServiceKey; UnimplementedQueryHandler is the fallback for the rest.
type hubQueryStub struct {
	hubv1connect.UnimplementedQueryHandler
	got      *hubv1.QueryCurrentServiceKeyRequest
	calls    int
	response *hubv1.QueryCurrentServiceKeyResponse
	err      error
}

func (s *hubQueryStub) CurrentServiceKey(
	_ context.Context, req *connect.Request[hubv1.QueryCurrentServiceKeyRequest],
) (*connect.Response[hubv1.QueryCurrentServiceKeyResponse], error) {
	s.calls++
	s.got = req.Msg
	if s.err != nil {
		return nil, s.err
	}
	return connect.NewResponse(s.response), nil
}

// newWiredResolver starts an h2c Connect server and returns a real chaincli client pointed at it.
func newWiredResolver(t *testing.T, stub *hubQueryStub) chaincli.Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(hubv1connect.NewQueryHandler(stub))
	srv := httptest.NewUnstartedServer(h2c.NewHandler(mux, &http2.Server{}))
	srv.EnableHTTP2 = true
	srv.Start()
	t.Cleanup(srv.Close)

	return chaincli.New(slog.New(slog.NewTextHandler(io.Discard, nil)), config.ChainConfig{
		GRPCAddr: srv.Listener.Addr().String(), ChainID: "trueopen-localnet",
	})
}

func wireTestSigner(t *testing.T, value byte) signer.Signer {
	t.Helper()
	raw := make([]byte, 32)
	raw[31] = value
	s, err := signer.NewFromBytes(raw, wireTestPrefix)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// activeCortexBinding builds a self-consistent CORTEX-domain binding: service_pubkey is bytes and
// the status goes through the cortex_service_key_status branch.
func activeCortexBinding(operator string, service signer.Signer) *hubv1.CurrentServiceKeyViewV1 {
	return &hubv1.CurrentServiceKeyViewV1{
		ParticipantType: sharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX,
		OperatorAddress: operator, ServiceAddress: service.Address(),
		ServicePubkey:             service.PubKeyCompressed(),
		ServiceAuthorizationNonce: 7,
		ParticipantStatus: &hubv1.CurrentServiceKeyViewV1_CortexServiceKeyStatus{
			CortexServiceKeyStatus: hubv1.ServiceKeyStatus_SERVICE_KEY_STATUS_ACTIVE,
		},
	}
}

// The request side must send the enum: on chain participant_type is ParticipantType (varint), so a
// Go string (length-delimited) request would not decode at all. The response side must decode
// CurrentServiceKeyViewV1.
func TestCurrentSendsParticipantTypeEnumAndDecodesViewV1(t *testing.T) {
	service := wireTestSigner(t, 11)
	const operator = "trueopen1operator"
	stub := &hubQueryStub{response: &hubv1.QueryCurrentServiceKeyResponse{
		Binding: activeCortexBinding(operator, service),
	}}
	resolver := newWiredResolver(t, stub)

	publicKey, state, err := servicekey.Current(
		context.Background(), resolver, wireTestPrefix, servicekey.ParticipantCortex, operator)
	if err != nil {
		t.Fatalf("current: %v", err)
	}
	if stub.got.GetParticipantType() != sharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX {
		t.Fatalf("participant_type on the wire = %v, want PARTICIPANT_TYPE_CORTEX", stub.got.GetParticipantType())
	}
	if stub.got.GetOperatorAddress() != operator {
		t.Fatalf("operator_address on the wire = %q, want %q", stub.got.GetOperatorAddress(), operator)
	}
	// The inputs to the triple check must come from CurrentServiceKeyViewV1: the bytes pubkey
	// lowercase hex-encoded, service_authorization_nonce replacing the old authorization_nonce, and
	// the status taken from the cortex_service_key_status branch.
	if !bytes.Equal(publicKey, service.PubKeyCompressed()) {
		t.Fatalf("public key = %x, want %x", publicKey, service.PubKeyCompressed())
	}
	if state.ParticipantType != servicekey.ParticipantCortex || state.Status != servicekey.StatusActive {
		t.Fatalf("state domain/status = %q/%q", state.ParticipantType, state.Status)
	}
	if state.ServicePubKey != hex.EncodeToString(service.PubKeyCompressed()) || state.ServiceAddress != service.Address() {
		t.Fatalf("decoded identity = %#v", state)
	}
	if state.AuthorizationNonce != 7 {
		t.Fatalf("authorization nonce = %d, want 7", state.AuthorizationNonce)
	}
}

// A malformed participant type domain must be reported as chain lookup unavailable.
//
// Values of this kind ("CORTEX_NODE" as currently sent by Cortex, sender_role's WORKER/VERIFIER,
// the empty string) have no matching enum value in hub.v1.ParticipantType, so the request
// cannot be sent at all -- that is "cannot determine", not "determined to be unauthorized".
// Downgrading it to unauthorized would send operators through a whole round of authorization
// debugging while the real fault is a wrongly written query domain.
func TestCurrentReportsAuthorityUnavailableForNonEnumParticipantType(t *testing.T) {
	service := wireTestSigner(t, 12)
	const operator = "trueopen1operator"

	for _, domain := range []string{"CORTEX_NODE", "WORKER", "VERIFIER", "", "cortex", "UNSPECIFIED"} {
		t.Run(domain, func(t *testing.T) {
			stub := &hubQueryStub{response: &hubv1.QueryCurrentServiceKeyResponse{
				Binding: activeCortexBinding(operator, service),
			}}
			resolver := newWiredResolver(t, stub)

			_, _, err := servicekey.Current(context.Background(), resolver, wireTestPrefix, domain, operator)
			if !errors.Is(err, servicekey.ErrAuthority) {
				t.Fatalf("error = %v, want ErrAuthority", err)
			}
			if errors.Is(err, servicekey.ErrUnavailable) {
				t.Fatalf("error = %v, must not be downgraded to ErrUnavailable", err)
			}
			// If no valid enum can be built, UNSPECIFIED must not be sent on chain to try its luck.
			if stub.calls != 0 {
				t.Fatalf("query was issued %d times for an unconstructible domain", stub.calls)
			}
		})
	}
}

// "Not found" and "could not query" must stay separate, and neither does a historical-key fallback.
func TestCurrentSeparatesMissingBindingFromQueryFailure(t *testing.T) {
	const operator = "trueopen1operator"

	missing := &hubQueryStub{response: &hubv1.QueryCurrentServiceKeyResponse{}}
	if _, _, err := servicekey.Current(context.Background(), newWiredResolver(t, missing),
		wireTestPrefix, servicekey.ParticipantCortex, operator); !errors.Is(err, servicekey.ErrUnavailable) {
		t.Fatalf("empty binding error = %v, want ErrUnavailable", err)
	}

	notFound := &hubQueryStub{err: connect.NewError(connect.CodeNotFound, errors.New("no binding"))}
	if _, _, err := servicekey.Current(context.Background(), newWiredResolver(t, notFound),
		wireTestPrefix, servicekey.ParticipantCortex, operator); !errors.Is(err, servicekey.ErrUnavailable) {
		t.Fatalf("NotFound error = %v, want ErrUnavailable", err)
	}

	broken := &hubQueryStub{err: connect.NewError(connect.CodeInternal, errors.New("keeper panic"))}
	if _, _, err := servicekey.Current(context.Background(), newWiredResolver(t, broken),
		wireTestPrefix, servicekey.ParticipantCortex, operator); !errors.Is(err, servicekey.ErrAuthority) {
		t.Fatalf("query failure error = %v, want ErrAuthority", err)
	}
}

// The triple check must not be relaxed by one word on the new shape.
func TestCurrentKeepsTripleCheckOnViewV1(t *testing.T) {
	service := wireTestSigner(t, 13)
	other := wireTestSigner(t, 14)
	const operator = "trueopen1operator"

	tests := []struct {
		name    string
		binding func() *hubv1.CurrentServiceKeyViewV1
	}{
		{
			name: "REVOKED is not ACTIVE",
			binding: func() *hubv1.CurrentServiceKeyViewV1 {
				b := activeCortexBinding(operator, service)
				b.ParticipantStatus = &hubv1.CurrentServiceKeyViewV1_CortexServiceKeyStatus{
					CortexServiceKeyStatus: hubv1.ServiceKeyStatus_SERVICE_KEY_STATUS_REVOKED,
				}
				return b
			},
		},
		{
			name: "status oneof missing",
			binding: func() *hubv1.CurrentServiceKeyViewV1 {
				b := activeCortexBinding(operator, service)
				b.ParticipantStatus = nil
				return b
			},
		},
		{
			// The contract requires the status branch to match participant_type. Since wire v0.4.1 both
			// branches are ServiceKeyStatus, but reading across domains still means admitting on the
			// status of the wrong domain, so it must be rejected.
			name: "CORTEX domain carries builder_service_key_status",
			binding: func() *hubv1.CurrentServiceKeyViewV1 {
				b := activeCortexBinding(operator, service)
				b.ParticipantStatus = &hubv1.CurrentServiceKeyViewV1_BuilderServiceKeyStatus{
					BuilderServiceKeyStatus: hubv1.ServiceKeyStatus_SERVICE_KEY_STATUS_ACTIVE,
				}
				return b
			},
		},
		{
			name: "participant_type does not match the query domain",
			binding: func() *hubv1.CurrentServiceKeyViewV1 {
				b := activeCortexBinding(operator, service)
				b.ParticipantType = sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER
				b.ParticipantStatus = &hubv1.CurrentServiceKeyViewV1_BuilderServiceKeyStatus{
					BuilderServiceKeyStatus: hubv1.ServiceKeyStatus_SERVICE_KEY_STATUS_ACTIVE,
				}
				return b
			},
		},
		{
			name: "operator mismatch",
			binding: func() *hubv1.CurrentServiceKeyViewV1 {
				b := activeCortexBinding(operator, service)
				b.OperatorAddress = "trueopen1other"
				return b
			},
		},
		{
			name: "service_pubkey is not a 33-byte compressed public key",
			binding: func() *hubv1.CurrentServiceKeyViewV1 {
				b := activeCortexBinding(operator, service)
				b.ServicePubkey = service.PubKeyCompressed()[:32]
				return b
			},
		},
		{
			name: "derived address differs from service_address",
			binding: func() *hubv1.CurrentServiceKeyViewV1 {
				b := activeCortexBinding(operator, service)
				b.ServiceAddress = other.Address()
				return b
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stub := &hubQueryStub{response: &hubv1.QueryCurrentServiceKeyResponse{Binding: tt.binding()}}
			_, _, err := servicekey.Current(context.Background(), newWiredResolver(t, stub),
				wireTestPrefix, servicekey.ParticipantCortex, operator)
			if !errors.Is(err, servicekey.ErrUnavailable) {
				t.Fatalf("error = %v, want ErrUnavailable", err)
			}
		})
	}
}

// The BUILDER domain goes through the builder_service_key_status branch; the same decode path must
// be correct for both domains.
func TestCurrentDecodesBuilderDomainStatus(t *testing.T) {
	service := wireTestSigner(t, 15)
	const operator = "trueopen1builderoperator"
	stub := &hubQueryStub{response: &hubv1.QueryCurrentServiceKeyResponse{
		Binding: &hubv1.CurrentServiceKeyViewV1{
			ParticipantType: sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER,
			OperatorAddress: operator, ServiceAddress: service.Address(),
			ServicePubkey:             service.PubKeyCompressed(),
			ServiceAuthorizationNonce: 3,
			ParticipantStatus: &hubv1.CurrentServiceKeyViewV1_BuilderServiceKeyStatus{
				BuilderServiceKeyStatus: hubv1.ServiceKeyStatus_SERVICE_KEY_STATUS_ACTIVE,
			},
		},
	}}
	resolver := newWiredResolver(t, stub)

	_, state, err := servicekey.Current(
		context.Background(), resolver, wireTestPrefix, servicekey.ParticipantBuilder, operator)
	if err != nil {
		t.Fatalf("current: %v", err)
	}
	if stub.got.GetParticipantType() != sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER {
		t.Fatalf("participant_type on the wire = %v, want PARTICIPANT_TYPE_BUILDER", stub.got.GetParticipantType())
	}
	if state.Status != servicekey.StatusActive || state.ParticipantType != servicekey.ParticipantBuilder {
		t.Fatalf("state domain/status = %q/%q", state.ParticipantType, state.Status)
	}
	// A BUILDER domain carrying the cortex branch must fail closed just the same.
	crossed := &hubQueryStub{response: &hubv1.QueryCurrentServiceKeyResponse{
		Binding: &hubv1.CurrentServiceKeyViewV1{
			ParticipantType: sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER,
			OperatorAddress: operator, ServiceAddress: service.Address(),
			ServicePubkey: service.PubKeyCompressed(),
			ParticipantStatus: &hubv1.CurrentServiceKeyViewV1_CortexServiceKeyStatus{
				CortexServiceKeyStatus: hubv1.ServiceKeyStatus_SERVICE_KEY_STATUS_ACTIVE,
			},
		},
	}}
	if _, _, err := servicekey.Current(context.Background(), newWiredResolver(t, crossed),
		wireTestPrefix, servicekey.ParticipantBuilder, operator); !errors.Is(err, servicekey.ErrUnavailable) {
		t.Fatalf("crossed builder binding error = %v, want ErrUnavailable", err)
	}
}

// VerifyPresented must still compare the presented pubkey byte for byte on the new shape.
func TestVerifyPresentedComparesViewV1PubKeyByteWise(t *testing.T) {
	service := wireTestSigner(t, 16)
	other := wireTestSigner(t, 17)
	const operator = "trueopen1operator"
	binding := func() *hubv1.QueryCurrentServiceKeyResponse {
		return &hubv1.QueryCurrentServiceKeyResponse{Binding: activeCortexBinding(operator, service)}
	}

	if _, err := servicekey.VerifyPresented(context.Background(),
		newWiredResolver(t, &hubQueryStub{response: binding()}),
		wireTestPrefix, servicekey.ParticipantCortex, operator, service.PubKeyCompressed()); err != nil {
		t.Fatalf("matching pubkey: %v", err)
	}
	if _, err := servicekey.VerifyPresented(context.Background(),
		newWiredResolver(t, &hubQueryStub{response: binding()}),
		wireTestPrefix, servicekey.ParticipantCortex, operator, other.PubKeyCompressed()); !errors.Is(err, servicekey.ErrUnavailable) {
		t.Fatalf("mismatched pubkey error = %v, want ErrUnavailable", err)
	}
}
