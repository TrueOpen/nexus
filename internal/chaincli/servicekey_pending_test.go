package chaincli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"connectrpc.com/connect"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/hub/v1/hubv1connect"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
)

// currentKeyHubQuery answers CurrentServiceKey with a fixed view.
type currentKeyHubQuery struct {
	hubv1connect.QueryClient
	view *hubv1.CurrentServiceKeyViewV1
}

func (q *currentKeyHubQuery) CurrentServiceKey(context.Context, *connect.Request[hubv1.QueryCurrentServiceKeyRequest]) (*connect.Response[hubv1.QueryCurrentServiceKeyResponse], error) {
	return connect.NewResponse(&hubv1.QueryCurrentServiceKeyResponse{Binding: q.view}), nil
}

func builderKeyView(pending *hubv1.PendingServiceKeyRotationState) *hubv1.CurrentServiceKeyViewV1 {
	return &hubv1.CurrentServiceKeyViewV1{
		ParticipantType: sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER, OperatorAddress: testBuilder,
		ServiceAddress: "trueopen1service", ServicePubkey: bytes.Repeat([]byte{0x02}, 33), ServiceAuthorizationNonce: 4,
		ParticipantStatus: &hubv1.CurrentServiceKeyViewV1_BuilderServiceKeyStatus{
			BuilderServiceKeyStatus: hubv1.ServiceKeyStatus_SERVICE_KEY_STATUS_ACTIVE,
		},
		PendingRotation: pending,
	}
}

func pendingRotation() *hubv1.PendingServiceKeyRotationState {
	return &hubv1.PendingServiceKeyRotationState{
		ParticipantType: sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER, OperatorAddress: testBuilder,
		CurrentServiceAuthorizationNonce: 4, NewServicePubkey: bytes.Repeat([]byte{0x03}, 33),
		NextServiceAuthorizationNonce: 5, RegisteredHeight: 100, EffectiveHeight: 400,
	}
}

func queryCurrentKey(t *testing.T, view *hubv1.CurrentServiceKeyViewV1) (ServiceKeyState, error) {
	t.Helper()
	c := &client{log: slog.New(slog.NewTextHandler(io.Discard, nil)), hubQuery: &currentKeyHubQuery{view: view}}
	return c.QueryCurrentServiceKey(context.Background(), "BUILDER", testBuilder)
}

// A registered replacement is reported next to the unchanged current binding.
func TestQueryCurrentServiceKeyMapsPendingRotation(t *testing.T) {
	got, err := queryCurrentKey(t, builderKeyView(pendingRotation()))
	if err != nil {
		t.Fatal(err)
	}
	if got.AuthorizationNonce != 4 || got.Status != "ACTIVE" || got.ServicePubKey != strings.Repeat("02", 33) {
		t.Fatalf("current binding = %+v", got)
	}
	want := &PendingServiceKeyRotation{
		NextServicePubKey: strings.Repeat("03", 33), NextAuthorizationNonce: 5,
		RegisteredHeight: 100, EffectiveHeight: 400,
	}
	if !reflect.DeepEqual(got.PendingRotation, want) {
		t.Fatalf("pending rotation = %+v", got.PendingRotation)
	}

	got, err = queryCurrentKey(t, builderKeyView(nil))
	if err != nil || got.PendingRotation != nil {
		t.Fatalf("no pending rotation = %+v, %v", got.PendingRotation, err)
	}
}

// A pending row that names another operator, role or current generation is a malformed answer.
func TestQueryCurrentServiceKeyRefusesMismatchedPendingRotation(t *testing.T) {
	cases := map[string]func(*hubv1.PendingServiceKeyRotationState){
		"operator": func(p *hubv1.PendingServiceKeyRotationState) { p.OperatorAddress = "trueopen1other" },
		"role": func(p *hubv1.PendingServiceKeyRotationState) {
			p.ParticipantType = sharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX
		},
		"current nonce": func(p *hubv1.PendingServiceKeyRotationState) { p.CurrentServiceAuthorizationNonce = 3 },
		"next nonce":    func(p *hubv1.PendingServiceKeyRotationState) { p.NextServiceAuthorizationNonce = 4 },
		"short pubkey":  func(p *hubv1.PendingServiceKeyRotationState) { p.NewServicePubkey = p.NewServicePubkey[:32] },
		"no pubkey":     func(p *hubv1.PendingServiceKeyRotationState) { p.NewServicePubkey = nil },
		"effective at registration": func(p *hubv1.PendingServiceKeyRotationState) {
			p.EffectiveHeight = p.RegisteredHeight
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			pending := pendingRotation()
			edit(pending)
			if got, err := queryCurrentKey(t, builderKeyView(pending)); !errors.Is(err, ErrMalformedBinding) {
				t.Fatalf("mismatched pending rotation = %+v, %v; want ErrMalformedBinding", got.PendingRotation, err)
			}
		})
	}
}

func withPrevious(view *hubv1.CurrentServiceKeyViewV1) *hubv1.CurrentServiceKeyViewV1 {
	pub, nonce, retired := bytes.Repeat([]byte{0x03}, 33), uint64(3), uint64(120)
	view.PreviousServicePubkey, view.PreviousServiceAuthorizationNonce, view.PreviousRetiredHeight = pub, &nonce, &retired
	return view
}

// The one previous generation a cutover retained is reported with the current binding.
func TestQueryCurrentServiceKeyMapsPreviousGeneration(t *testing.T) {
	got, err := queryCurrentKey(t, withPrevious(builderKeyView(nil)))
	if err != nil {
		t.Fatal(err)
	}
	want := &PreviousServiceKey{ServicePubKey: strings.Repeat("03", 33), AuthorizationNonce: 3, RetiredHeight: 120}
	if !reflect.DeepEqual(got.Previous, want) || got.AuthorizationNonce != 4 {
		t.Fatalf("previous = %+v, current nonce %d", got.Previous, got.AuthorizationNonce)
	}
	if got, err := queryCurrentKey(t, builderKeyView(nil)); err != nil || got.Previous != nil {
		t.Fatalf("no previous = %+v, %v", got.Previous, err)
	}
}

// The three previous fields are present together, name an older generation and a positive
// retirement height; anything else is a malformed answer.
func TestQueryCurrentServiceKeyRefusesMalformedPreviousGeneration(t *testing.T) {
	cases := map[string]func(*hubv1.CurrentServiceKeyViewV1){
		"pubkey only": func(v *hubv1.CurrentServiceKeyViewV1) {
			v.PreviousServiceAuthorizationNonce, v.PreviousRetiredHeight = nil, nil
		},
		"no pubkey":      func(v *hubv1.CurrentServiceKeyViewV1) { v.PreviousServicePubkey = nil },
		"no nonce":       func(v *hubv1.CurrentServiceKeyViewV1) { v.PreviousServiceAuthorizationNonce = nil },
		"no height":      func(v *hubv1.CurrentServiceKeyViewV1) { v.PreviousRetiredHeight = nil },
		"short pubkey":   func(v *hubv1.CurrentServiceKeyViewV1) { v.PreviousServicePubkey = v.PreviousServicePubkey[:32] },
		"zero nonce":     func(v *hubv1.CurrentServiceKeyViewV1) { *v.PreviousServiceAuthorizationNonce = 0 },
		"current nonce":  func(v *hubv1.CurrentServiceKeyViewV1) { *v.PreviousServiceAuthorizationNonce = 4 },
		"zero height":    func(v *hubv1.CurrentServiceKeyViewV1) { *v.PreviousRetiredHeight = 0 },
		"current pubkey": func(v *hubv1.CurrentServiceKeyViewV1) { v.PreviousServicePubkey = v.ServicePubkey },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			view := withPrevious(builderKeyView(nil))
			edit(view)
			if got, err := queryCurrentKey(t, view); !errors.Is(err, ErrMalformedBinding) {
				t.Fatalf("malformed previous generation = %+v, %v; want ErrMalformedBinding", got.Previous, err)
			}
		})
	}
}
