package ingress

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"connectrpc.com/connect"
	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/nexus/v1/nexusv1connect"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/dispatchevidence"
	"github.com/TrueOpen/nexus/internal/sdkauth"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/signer"
)

// The wire DispatchRosterRequestV1 vector: requester and builder_operator are the same operator,
// expiry height 1, signed by the vector's CORTEX service key.
const (
	rosterVectorChain     = "trueopen-phase1-vector-1"
	rosterVectorOperator  = "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz"
	rosterVectorTask      = "14bc7aeea995cfb037517220d0e981df255def7318b07ac0cba6ad82e3ac7ccf"
	rosterVectorPubKey    = "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
	rosterVectorProtobuf  = "0a2014bc7aeea995cfb037517220d0e981df255def7318b07ac0cba6ad82e3ac7ccf122f747275656f70656e3172666a7a3772337538743635746561766835757471756a336b7776736a39383370336a636c7a180120013218747275656f70656e2d7068617365312d766563746f722d313a2f747275656f70656e3172666a7a3772337538743635746561766835757471756a336b7776736a39383370336a636c7a2a409363d31ef29f931ee7074e09f71fb7231865c76f3e74bf8b630493213e28d37e530775aee1494cd15ec28a66ce1b87d360052a91c0da513174144890a7a7a5fb"
	rosterVectorTestSessn = "77625100ba4faa1306ae6eaf5a872a661443aa94f87c5530c4b178614e3d62f7"
)

type fakeRosters struct {
	session, task string
	calls         int
}

func (f *fakeRosters) DispatchRoster(_ context.Context, sessionID, taskID string) (*nexusv1.GetDispatchRosterResponse, error) {
	f.calls++
	if sessionID != f.session || taskID != f.task {
		return nil, dispatchevidence.ErrRosterNotFound
	}
	return &nexusv1.GetDispatchRosterResponse{
		DispatchRecordHash: bytes.Repeat([]byte{0x77}, 32),
		Rounds:             []*nexusv1.DispatchRosterRoundV1{{DispatchRound: 0, Roster: &taskv1.DispatchRosterV1{ReferenceHeight: 90}}},
	}, nil
}

func cortexKeyState(t *testing.T, operator, pubKeyHex string) chaincli.ServiceKeyState {
	t.Helper()
	pub, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	address, err := signer.AddressFromPubKey("trueopen", pub)
	if err != nil {
		t.Fatal(err)
	}
	return chaincli.ServiceKeyState{ParticipantType: servicekey.ParticipantCortex, OperatorAddress: operator, ServiceAddress: address, ServicePubKey: pubKeyHex, Status: "ACTIVE"}
}

// rosterService serves GetDispatchRoster as the vector's Builder at height.
func rosterService(t *testing.T, height uint64, rosters *fakeRosters, keys map[string]chaincli.ServiceKeyState) *service {
	t.Helper()
	return newService(&fakeHandler{taskOwner: mustSigner(t, testKeyHex).Address()}, AuthParams{
		ChainID: rosterVectorChain, BuilderAddress: rosterVectorOperator, Bech32Prefix: "trueopen",
		ServiceKeys: &fakeServiceKeyResolver{states: keys}, Chain: &fakeUserChain{height: height},
	}, withDispatchRosters(rosters))
}

func vectorRosterRequest(t *testing.T) *nexusv1.DispatchRosterRequestV1 {
	t.Helper()
	raw, err := hex.DecodeString(rosterVectorProtobuf)
	if err != nil {
		t.Fatal(err)
	}
	var req nexusv1.DispatchRosterRequestV1
	if err := proto.Unmarshal(raw, &req); err != nil {
		t.Fatal(err)
	}
	return &req
}

func getRoster(s *service, session, task string, req *nexusv1.DispatchRosterRequestV1) (*connect.Response[nexusv1.GetDispatchRosterResponse], error) {
	return s.GetDispatchRoster(context.Background(), connect.NewRequest(&nexusv1.GetDispatchRosterRequest{
		SessionId: wireID(session), TaskId: wireID(task),
		Authentication: &nexusv1.GetDispatchRosterRequest_RosterRequest{RosterRequest: req},
	}))
}

// A Cortex asks with its current service key's signature over the wire projection: the vector
// request is served.
func TestDispatchRosterServesTheVectorRequest(t *testing.T) {
	rosters := &fakeRosters{session: rosterVectorTestSessn, task: rosterVectorTask}
	s := rosterService(t, 1, rosters, map[string]chaincli.ServiceKeyState{
		servicekey.ParticipantCortex + "|" + rosterVectorOperator: cortexKeyState(t, rosterVectorOperator, rosterVectorPubKey),
	})
	resp, err := getRoster(s, rosterVectorTestSessn, rosterVectorTask, vectorRosterRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Msg.GetRounds()) != 1 || !bytes.Equal(resp.Msg.GetDispatchRecordHash(), bytes.Repeat([]byte{0x77}, 32)) {
		t.Fatalf("response = %v", resp.Msg)
	}
}

// signRosterRequest signs req with the Cortex service key keyHex.
func signRosterRequest(t *testing.T, req *nexusv1.DispatchRosterRequestV1, keyHex string) *nexusv1.DispatchRosterRequestV1 {
	t.Helper()
	req.ServiceSignature = nil
	raw, err := proto.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := dispatch.SigningDigest("nexus.v1.DispatchRosterRequestV1", raw)
	if err != nil {
		t.Fatal(err)
	}
	req.ServiceSignature = mustSignDigest(t, keyHex, digest[:])
	return req
}

// The request must name this chain, this Builder and the task asked for, be unexpired at the
// current height and carry the requester's current CORTEX service key signature.
func TestDispatchRosterRequestChecks(t *testing.T) {
	worker := mustSigner(t, workerKeyHex)
	requester := rosterVectorOperator
	keys := map[string]chaincli.ServiceKeyState{
		servicekey.ParticipantCortex + "|" + requester: cortexKeyState(t, requester, hex.EncodeToString(worker.PubKeyCompressed())),
	}
	taskID, _ := hex.DecodeString(rosterVectorTask)
	valid := func() *nexusv1.DispatchRosterRequestV1 {
		return &nexusv1.DispatchRosterRequestV1{
			TaskId: taskID, Requester: requester, Nonce: 5, ExpiryHeight: 10, ChainId: rosterVectorChain, BuilderOperator: rosterVectorOperator,
		}
	}
	rosters := &fakeRosters{session: rosterVectorTestSessn, task: rosterVectorTask}
	s := rosterService(t, 10, rosters, keys)
	if _, err := getRoster(s, rosterVectorTestSessn, rosterVectorTask, signRosterRequest(t, valid(), workerKeyHex)); err != nil {
		t.Fatalf("valid request: %v", err)
	}
	for name, tc := range map[string]struct {
		change func(*nexusv1.DispatchRosterRequestV1)
		keyHex string
		code   connect.Code
	}{
		"expired":        {func(r *nexusv1.DispatchRosterRequestV1) { r.ExpiryHeight = 9 }, workerKeyHex, connect.CodeDeadlineExceeded},
		"other chain":    {func(r *nexusv1.DispatchRosterRequestV1) { r.ChainId = "other-chain" }, workerKeyHex, connect.CodeInvalidArgument},
		"other Builder":  {func(r *nexusv1.DispatchRosterRequestV1) { r.BuilderOperator = worker.Address() }, workerKeyHex, connect.CodeInvalidArgument},
		"other task":     {func(r *nexusv1.DispatchRosterRequestV1) { r.TaskId = bytes.Repeat([]byte{1}, 32) }, workerKeyHex, connect.CodeInvalidArgument},
		"wrong key":      {func(*nexusv1.DispatchRosterRequestV1) {}, alternateKeyHex, connect.CodeUnauthenticated},
		"unknown Cortex": {func(r *nexusv1.DispatchRosterRequestV1) { r.Requester = worker.Address() }, workerKeyHex, connect.CodeUnauthenticated},
	} {
		req := valid()
		tc.change(req)
		_, err := getRoster(s, rosterVectorTestSessn, rosterVectorTask, signRosterRequest(t, req, tc.keyHex))
		if connect.CodeOf(err) != tc.code {
			t.Fatalf("%s: code %v (%v), want %v", name, connect.CodeOf(err), err, tc.code)
		}
	}
	// A signature that does not cover the request as sent is refused.
	req := signRosterRequest(t, valid(), workerKeyHex)
	req.Nonce++
	if _, err := getRoster(s, rosterVectorTestSessn, rosterVectorTask, req); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("altered request: %v", err)
	}
}

// A request without authentication is refused; a task this Builder holds no recorded dispatch of
// is NotFound.
func TestDispatchRosterAuthenticationAndNotFound(t *testing.T) {
	worker := mustSigner(t, workerKeyHex)
	keys := map[string]chaincli.ServiceKeyState{
		servicekey.ParticipantCortex + "|" + rosterVectorOperator: cortexKeyState(t, rosterVectorOperator, hex.EncodeToString(worker.PubKeyCompressed())),
	}
	rosters := &fakeRosters{session: rosterVectorTestSessn, task: rosterVectorTask}
	s := rosterService(t, 10, rosters, keys)
	_, err := s.GetDispatchRoster(context.Background(), connect.NewRequest(&nexusv1.GetDispatchRosterRequest{
		SessionId: wireID(rosterVectorTestSessn), TaskId: wireID(rosterVectorTask),
	}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated || rosters.calls != 0 {
		t.Fatalf("unauthenticated: %v", err)
	}
	otherSession := testSessionID("other session")
	taskID, _ := hex.DecodeString(rosterVectorTask)
	req := signRosterRequest(t, &nexusv1.DispatchRosterRequestV1{
		TaskId: taskID, Requester: rosterVectorOperator, Nonce: 1, ExpiryHeight: 10, ChainId: rosterVectorChain, BuilderOperator: rosterVectorOperator,
	}, workerKeyHex)
	if _, err := getRoster(s, otherSession, rosterVectorTask, req); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("not held: %v", err)
	}
}

// The user who ordered the task may ask with an SDK envelope; another user may not.
func TestDispatchRosterServesTheOrderUser(t *testing.T) {
	owner := mustSigner(t, testKeyHex)
	other := mustSigner(t, alternateKeyHex)
	session, task := testSessionID("roster-session"), testSessionID("roster-task")
	rosters := &fakeRosters{session: session, task: task}
	s := newService(&fakeHandler{taskOwner: owner.Address()}, AuthParams{
		ChainID: "trueopen-localnet", BuilderAddress: rosterVectorOperator, Bech32Prefix: "trueopen", Chain: testUserChain,
	}, withDispatchRosters(rosters))
	body, err := sdkauth.GetDispatchRosterBody(wireID(session), wireID(task))
	if err != nil {
		t.Fatal(err)
	}
	ask := func(sg signer.Signer, nonce string) error {
		_, err := s.GetDispatchRoster(context.Background(), connect.NewRequest(&nexusv1.GetDispatchRosterRequest{
			SessionId: wireID(session), TaskId: wireID(task),
			Authentication: &nexusv1.GetDispatchRosterRequest_RequestEnvelope{RequestEnvelope: signedTaskEnvelope(t, sg, "GetDispatchRoster",
				nexusv1connect.IngressAPIGetDispatchRosterProcedure, wireID(session), wireID(task), body[:], []byte(nonce))},
		}))
		return err
	}
	if err := ask(owner, "roster-1"); err != nil {
		t.Fatalf("order user: %v", err)
	}
	if err := ask(other, "roster-2"); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("another user: %v", err)
	}
}

// Without a roster source the RPC is not served.
func TestDispatchRosterUnimplementedWithoutSource(t *testing.T) {
	s := newService(&fakeHandler{}, AuthParams{ChainID: rosterVectorChain})
	_, err := getRoster(s, rosterVectorTestSessn, rosterVectorTask, &nexusv1.DispatchRosterRequestV1{})
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("code %v", connect.CodeOf(err))
	}
}
