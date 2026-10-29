package chaincli

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"

	"connectrpc.com/connect"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/hub/v1/hubv1connect"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/task/v1/taskv1connect"
	"github.com/TrueOpen/nexus/internal/config"
)

type dispatchTaskQuery struct {
	taskv1connect.QueryClient
	err            error
	recordRequest  *taskv1.QueryDispatchRecordRequest
	record         *taskv1.QueryDispatchRecordResponse
	claimRequest   *taskv1.QueryDispatchCompensationClaimRequest
	claim          *taskv1.QueryDispatchCompensationClaimResponse
	ineligible     *taskv1.QueryDispatchWinnerIneligibleResponse
	challengeQuery *taskv1.QueryDispatchChallengeRequest
	challenge      *taskv1.QueryDispatchChallengeResponse
	params         *taskv1.QueryTaskParamsResponse
	session        *taskv1.QuerySessionResponse
}

func (q *dispatchTaskQuery) DispatchRecord(_ context.Context, req *connect.Request[taskv1.QueryDispatchRecordRequest]) (*connect.Response[taskv1.QueryDispatchRecordResponse], error) {
	q.recordRequest = req.Msg
	if q.err != nil {
		return nil, q.err
	}
	return connect.NewResponse(q.record), nil
}

func (q *dispatchTaskQuery) DispatchCompensationClaim(_ context.Context, req *connect.Request[taskv1.QueryDispatchCompensationClaimRequest]) (*connect.Response[taskv1.QueryDispatchCompensationClaimResponse], error) {
	q.claimRequest = req.Msg
	if q.err != nil {
		return nil, q.err
	}
	return connect.NewResponse(q.claim), nil
}

func (q *dispatchTaskQuery) DispatchWinnerIneligible(context.Context, *connect.Request[taskv1.QueryDispatchWinnerIneligibleRequest]) (*connect.Response[taskv1.QueryDispatchWinnerIneligibleResponse], error) {
	if q.err != nil {
		return nil, q.err
	}
	return connect.NewResponse(q.ineligible), nil
}

func (q *dispatchTaskQuery) DispatchChallenge(_ context.Context, req *connect.Request[taskv1.QueryDispatchChallengeRequest]) (*connect.Response[taskv1.QueryDispatchChallengeResponse], error) {
	q.challengeQuery = req.Msg
	if q.err != nil {
		return nil, q.err
	}
	return connect.NewResponse(q.challenge), nil
}

func (q *dispatchTaskQuery) Params(context.Context, *connect.Request[taskv1.QueryTaskParamsRequest]) (*connect.Response[taskv1.QueryTaskParamsResponse], error) {
	return connect.NewResponse(q.params), nil
}

func (q *dispatchTaskQuery) Session(context.Context, *connect.Request[taskv1.QuerySessionRequest]) (*connect.Response[taskv1.QuerySessionResponse], error) {
	return connect.NewResponse(q.session), nil
}

type dispatchHubQuery struct {
	hubv1connect.QueryClient
	err             error
	memberRequest   *hubv1.QueryCandidatePoolSnapshotMemberRequest
	member          *hubv1.QueryCandidatePoolSnapshotMemberResponse
	snapshotRequest *hubv1.QueryCandidatePoolSnapshotRequest
	snapshot        *hubv1.QueryCandidatePoolSnapshotResponse
	current         *hubv1.QueryCurrentCandidatePoolResponse
	account         *hubv1.QueryBuilderCompensationAccountResponse
	vrfRequest      *hubv1.QueryVrfKeyRequest
	vrf             *hubv1.QueryVrfKeyResponse
	beacon          *hubv1.QueryBeaconResponse
}

func (q *dispatchHubQuery) CandidatePoolSnapshotMember(_ context.Context, req *connect.Request[hubv1.QueryCandidatePoolSnapshotMemberRequest]) (*connect.Response[hubv1.QueryCandidatePoolSnapshotMemberResponse], error) {
	q.memberRequest = req.Msg
	if q.err != nil {
		return nil, q.err
	}
	return connect.NewResponse(q.member), nil
}

func (q *dispatchHubQuery) CandidatePoolSnapshot(_ context.Context, req *connect.Request[hubv1.QueryCandidatePoolSnapshotRequest]) (*connect.Response[hubv1.QueryCandidatePoolSnapshotResponse], error) {
	q.snapshotRequest = req.Msg
	return connect.NewResponse(q.snapshot), nil
}

func (q *dispatchHubQuery) CurrentCandidatePool(context.Context, *connect.Request[hubv1.QueryCurrentCandidatePoolRequest]) (*connect.Response[hubv1.QueryCurrentCandidatePoolResponse], error) {
	if q.err != nil {
		return nil, q.err
	}
	return connect.NewResponse(q.current), nil
}

func (q *dispatchHubQuery) BuilderCompensationAccount(context.Context, *connect.Request[hubv1.QueryBuilderCompensationAccountRequest]) (*connect.Response[hubv1.QueryBuilderCompensationAccountResponse], error) {
	if q.err != nil {
		return nil, q.err
	}
	return connect.NewResponse(q.account), nil
}

func (q *dispatchHubQuery) VrfKey(_ context.Context, req *connect.Request[hubv1.QueryVrfKeyRequest]) (*connect.Response[hubv1.QueryVrfKeyResponse], error) {
	q.vrfRequest = req.Msg
	if q.err != nil {
		return nil, q.err
	}
	return connect.NewResponse(q.vrf), nil
}

func (q *dispatchHubQuery) Beacon(context.Context, *connect.Request[hubv1.QueryBeaconRequest]) (*connect.Response[hubv1.QueryBeaconResponse], error) {
	return connect.NewResponse(q.beacon), nil
}

var notFound = connect.NewError(connect.CodeNotFound, errors.New("not found"))

func TestQueryDispatchRecordSelectsByOrderOrHash(t *testing.T) {
	record := &taskv1.DispatchRecordState{
		TaskId: testTaskIDBytes, DispatchRecordHash: mustHash32("a1"), DispatchTicketHash: mustHash32("a2"),
		BuilderAddress: "trueopen1builder", ReferenceHeight: 100, VrfEpoch: 3, WinnerRound: 1, RecordedHeight: 120,
	}
	query := &dispatchTaskQuery{record: &taskv1.QueryDispatchRecordResponse{Record: record}}
	c := &client{taskQuery: query}

	got, err := c.QueryDispatchRecordByOrder(context.Background(), testSessionIDHex, 7)
	if err != nil || got.GetRecordedHeight() != 120 || got.GetBuilderAddress() != "trueopen1builder" {
		t.Fatalf("by order = %v, %v", got, err)
	}
	byOrder := query.recordRequest.GetByOrder()
	if !bytes.Equal(byOrder.GetSessionId(), testSessionIDBytes) || byOrder.GetOrderSequence() != 7 {
		t.Fatalf("by order request = %v", query.recordRequest)
	}

	got, err = c.QueryDispatchRecordByHash(context.Background(), mustHash32("a1"))
	if err != nil || !bytes.Equal(got.GetDispatchTicketHash(), mustHash32("a2")) {
		t.Fatalf("by hash = %v, %v", got, err)
	}
	if !bytes.Equal(query.recordRequest.GetDispatchRecordHash(), mustHash32("a1")) {
		t.Fatalf("by hash request = %v", query.recordRequest)
	}
	if _, err := c.QueryDispatchRecordByHash(context.Background(), mustHash32("ff")); err == nil {
		t.Fatal("a record for another hash was accepted")
	}

	for name, bad := range map[string]*taskv1.QueryDispatchRecordResponse{
		"short ticket hash": {Record: &taskv1.DispatchRecordState{TaskId: testTaskIDBytes, DispatchRecordHash: mustHash32("a1"), DispatchTicketHash: []byte{1}}},
		"short task id":     {Record: &taskv1.DispatchRecordState{TaskId: []byte{1}, DispatchRecordHash: mustHash32("a1"), DispatchTicketHash: mustHash32("a2")}},
	} {
		c := &client{taskQuery: &dispatchTaskQuery{record: bad}}
		if _, err := c.QueryDispatchRecordByOrder(context.Background(), testSessionIDHex, 7); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	for name, q := range map[string]*dispatchTaskQuery{
		"empty response": {record: &taskv1.QueryDispatchRecordResponse{}},
		"not found":      {err: notFound},
	} {
		c := &client{taskQuery: q}
		if _, err := c.QueryDispatchRecordByOrder(context.Background(), testSessionIDHex, 7); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: err = %v, want ErrNotFound", name, err)
		}
	}
	if _, err := c.QueryDispatchRecordByOrder(context.Background(), "not-hex", 7); err == nil {
		t.Fatal("a malformed session id was sent")
	}
	if _, err := c.QueryDispatchRecordByOrder(context.Background(), testSessionIDHex, 0); err == nil {
		t.Fatal("order sequence 0 was sent")
	}
	if _, err := c.QueryDispatchRecordByHash(context.Background(), []byte{1}); err == nil {
		t.Fatal("a short record hash was sent")
	}
}

func TestQueryDispatchClaimIneligibleAndChallengeMatchTheirKeys(t *testing.T) {
	ticket, challengeID := mustHash32("b1"), mustHash32("c1")
	query := &dispatchTaskQuery{
		claim: &taskv1.QueryDispatchCompensationClaimResponse{Claim: &taskv1.DispatchCompensationClaimState{
			DispatchTicketHash: ticket, TaskId: testTaskIDBytes, SessionId: testSessionIDBytes, OrderSequence: 4,
			BuilderAddress: "trueopen1builder", WorkerOperatorAddress: "trueopen1worker",
			Status: taskv1.DispatchCompensationClaimStatusV1(1), RebuttalDeadlineHeight: 300,
		}},
		ineligible: &taskv1.QueryDispatchWinnerIneligibleResponse{Row: &taskv1.DispatchWinnerIneligibleState{
			DispatchTicketHash: ticket, TaskId: testTaskIDBytes, WorkerOperatorAddress: "trueopen1worker",
		}},
		challenge: &taskv1.QueryDispatchChallengeResponse{Row: &taskv1.DispatchChallengeState{
			ChallengeId: challengeID, TaskId: testTaskIDBytes, Kind: sharedv1.DispatchChallengeKindV1_DISPATCH_CHALLENGE_KIND_V1_SKIP,
			BuilderAddress: "trueopen1builder", OpenedHeight: 50,
		}},
	}
	c := &client{taskQuery: query}

	claim, err := c.QueryDispatchCompensationClaim(context.Background(), ticket)
	if err != nil || claim.GetRebuttalDeadlineHeight() != 300 || !bytes.Equal(query.claimRequest.GetDispatchTicketHash(), ticket) {
		t.Fatalf("claim = %v, %v", claim, err)
	}
	row, err := c.QueryDispatchWinnerIneligible(context.Background(), ticket)
	if err != nil || row.GetWorkerOperatorAddress() != "trueopen1worker" {
		t.Fatalf("ineligible = %v, %v", row, err)
	}
	challenge, err := c.QueryDispatchChallenge(context.Background(), challengeID)
	if err != nil || challenge.GetOpenedHeight() != 50 || !bytes.Equal(query.challengeQuery.GetChallengeId(), challengeID) {
		t.Fatalf("challenge = %v, %v", challenge, err)
	}

	other := mustHash32("ee")
	if _, err := c.QueryDispatchCompensationClaim(context.Background(), other); err == nil {
		t.Fatal("a claim for another ticket was accepted")
	}
	if _, err := c.QueryDispatchWinnerIneligible(context.Background(), other); err == nil {
		t.Fatal("an ineligibility row for another ticket was accepted")
	}
	if _, err := c.QueryDispatchChallenge(context.Background(), other); err == nil {
		t.Fatal("a challenge with another id was accepted")
	}

	empty := &client{taskQuery: &dispatchTaskQuery{
		claim: &taskv1.QueryDispatchCompensationClaimResponse{}, ineligible: &taskv1.QueryDispatchWinnerIneligibleResponse{},
		challenge: &taskv1.QueryDispatchChallengeResponse{},
	}}
	if _, err := empty.QueryDispatchCompensationClaim(context.Background(), ticket); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty claim: %v", err)
	}
	if _, err := empty.QueryDispatchWinnerIneligible(context.Background(), ticket); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty ineligible: %v", err)
	}
	if _, err := empty.QueryDispatchChallenge(context.Background(), challengeID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty challenge: %v", err)
	}
	missing := &client{taskQuery: &dispatchTaskQuery{err: notFound}}
	if _, err := missing.QueryDispatchChallenge(context.Background(), challengeID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("not found challenge: %v", err)
	}
	if _, err := c.QueryDispatchCompensationClaim(context.Background(), nil); err == nil {
		t.Fatal("an empty ticket hash was sent")
	}
}

func TestQueryDispatchParamsReadsTheDispatchGroup(t *testing.T) {
	params := &taskv1.DispatchParamsV1{
		RecordDeadlineBlocks: 20, MaxDispatchEntriesPerRecord: 16, MaxDispatchRecordBytes: 1 << 20, MaxSkips: 3,
		StickyWindowBlocks: 600, StickyMaxOrders: 8, OrderFreshnessMarginBlocks: 2, MaxPrerecordOutputTokens: 64,
		BuilderCompensationAccountMinBalance: &sharedv1.Amount{AtomicUnits: "1000"},
	}
	c := &client{taskQuery: &dispatchTaskQuery{params: &taskv1.QueryTaskParamsResponse{Params: &taskv1.TaskParamsV1{Dispatch: params}}}}
	got, err := c.QueryDispatchParams(context.Background())
	if err != nil || got.GetRecordDeadlineBlocks() != 20 || got.GetMaxSkips() != 3 ||
		got.GetBuilderCompensationAccountMinBalance().GetAtomicUnits() != "1000" {
		t.Fatalf("params = %v, %v", got, err)
	}
	for name, response := range map[string]*taskv1.QueryTaskParamsResponse{
		"no dispatch group":   {Params: &taskv1.TaskParamsV1{}},
		"zero deadline":       {Params: &taskv1.TaskParamsV1{Dispatch: &taskv1.DispatchParamsV1{MaxDispatchEntriesPerRecord: 1}}},
		"zero entries/record": {Params: &taskv1.TaskParamsV1{Dispatch: &taskv1.DispatchParamsV1{RecordDeadlineBlocks: 1}}},
	} {
		c := &client{taskQuery: &dispatchTaskQuery{params: response}}
		if _, err := c.QueryDispatchParams(context.Background()); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestQueryCandidatePoolSnapshotMemberSendsOptionalProfile(t *testing.T) {
	snapshotID, modelID := mustHash32("d1"), mustHash32("d2")
	weight := uint64(77)
	query := &dispatchHubQuery{member: &hubv1.QueryCandidatePoolSnapshotMemberResponse{Member: &hubv1.CandidatePoolSnapshotMemberViewV1{
		InPool: true, Slot: 5, SlotVersion: 2, BindingHash: mustHash32("d3"), CandidateWeight: &weight,
	}}}
	c := &client{hubQuery: query}

	got, err := c.QueryCandidatePoolSnapshotMember(context.Background(), CandidatePoolMemberKey{
		SnapshotID: snapshotID, Operator: "trueopen1worker", ModelID: modelID, ProfileVersion: 3,
	})
	if err != nil || !got.GetInPool() || got.GetSlot() != 5 || got.GetCandidateWeight() != 77 {
		t.Fatalf("member = %v, %v", got, err)
	}
	req := query.memberRequest
	if !bytes.Equal(req.GetSnapshotId(), snapshotID) || req.GetOperatorAddress() != "trueopen1worker" ||
		!bytes.Equal(req.GetModelId(), modelID) || req.ProfileVersion == nil || req.GetProfileVersion() != 3 {
		t.Fatalf("request = %v", req)
	}

	if _, err := c.QueryCandidatePoolSnapshotMember(context.Background(), CandidatePoolMemberKey{
		SnapshotID: snapshotID, Operator: "trueopen1worker",
	}); err != nil {
		t.Fatal(err)
	}
	if req := query.memberRequest; req.ModelId != nil || req.ProfileVersion != nil {
		t.Fatalf("profile-free request carried a profile: %v", req)
	}

	for name, key := range map[string]CandidatePoolMemberKey{
		"short snapshot":     {SnapshotID: []byte{1}, Operator: "trueopen1worker"},
		"no operator":        {SnapshotID: snapshotID},
		"model, no version":  {SnapshotID: snapshotID, Operator: "trueopen1worker", ModelID: modelID},
		"version, no model":  {SnapshotID: snapshotID, Operator: "trueopen1worker", ProfileVersion: 3},
		"short model id":     {SnapshotID: snapshotID, Operator: "trueopen1worker", ModelID: []byte{1}, ProfileVersion: 3},
		"padded operator id": {SnapshotID: snapshotID, Operator: " trueopen1worker"},
	} {
		if _, err := c.QueryCandidatePoolSnapshotMember(context.Background(), key); err == nil {
			t.Fatalf("%s: sent", name)
		}
	}
	empty := &client{hubQuery: &dispatchHubQuery{member: &hubv1.QueryCandidatePoolSnapshotMemberResponse{}}}
	if _, err := empty.QueryCandidatePoolSnapshotMember(context.Background(), CandidatePoolMemberKey{SnapshotID: snapshotID, Operator: "trueopen1worker"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty member: %v", err)
	}
}

func TestQueryCandidatePoolSnapshots(t *testing.T) {
	view := &hubv1.CandidatePoolSnapshotViewV1{
		Epoch: 9, SnapshotId: mustHash32("e1"), PoolHash: mustHash32("e2"),
		Status: hubv1.CandidatePoolSnapshotStatus(1), EffectiveHeight: 900, ExpiresHeight: 1800,
	}
	query := &dispatchHubQuery{
		snapshot: &hubv1.QueryCandidatePoolSnapshotResponse{Snapshot: view},
		current:  &hubv1.QueryCurrentCandidatePoolResponse{Snapshot: view},
	}
	c := &client{hubQuery: query}
	got, err := c.QueryCandidatePoolSnapshot(context.Background(), mustHash32("e1"))
	if err != nil || got.GetEpoch() != 9 || !bytes.Equal(query.snapshotRequest.GetSnapshotId(), mustHash32("e1")) {
		t.Fatalf("snapshot = %v, %v", got, err)
	}
	if _, err := c.QueryCandidatePoolSnapshot(context.Background(), mustHash32("ee")); err == nil {
		t.Fatal("a snapshot with another id was accepted")
	}
	current, err := c.QueryCurrentCandidatePool(context.Background())
	if err != nil || current.GetEffectiveHeight() != 900 {
		t.Fatalf("current = %v, %v", current, err)
	}

	bad := &client{hubQuery: &dispatchHubQuery{current: &hubv1.QueryCurrentCandidatePoolResponse{Snapshot: &hubv1.CandidatePoolSnapshotViewV1{SnapshotId: []byte{1}}}}}
	if _, err := bad.QueryCurrentCandidatePool(context.Background()); err == nil {
		t.Fatal("a short snapshot id was accepted")
	}
	missing := &client{hubQuery: &dispatchHubQuery{err: notFound}}
	if _, err := missing.QueryCurrentCandidatePool(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no current pool: %v", err)
	}
}

func TestQueryBuilderCompensationAccount(t *testing.T) {
	account := &hubv1.BuilderCompensationAccountState{BuilderAddress: "trueopen1builder", Balance: &sharedv1.Amount{AtomicUnits: "500"}}
	c := &client{hubQuery: &dispatchHubQuery{account: &hubv1.QueryBuilderCompensationAccountResponse{Account: account}}}
	got, err := c.QueryBuilderCompensationAccount(context.Background(), "trueopen1builder")
	if err != nil || got.GetBalance().GetAtomicUnits() != "500" {
		t.Fatalf("account = %v, %v", got, err)
	}
	if _, err := c.QueryBuilderCompensationAccount(context.Background(), "trueopen1other"); err == nil {
		t.Fatal("another Builder's account was accepted")
	}
	empty := &client{hubQuery: &dispatchHubQuery{account: &hubv1.QueryBuilderCompensationAccountResponse{}}}
	if _, err := empty.QueryBuilderCompensationAccount(context.Background(), "trueopen1builder"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty account: %v", err)
	}
}

func TestQueryVrfKeySendsParticipantType(t *testing.T) {
	active, pending := bytes.Repeat([]byte{0x01}, 32), bytes.Repeat([]byte{0x02}, 32)
	pendingEpoch := uint64(8)
	query := &dispatchHubQuery{vrf: &hubv1.QueryVrfKeyResponse{
		ActiveVrfPubkey: active, ActiveFromEpoch: 5, PendingVrfPubkey: pending, PendingFromEpoch: &pendingEpoch, VrfAuthorizationNonce: 2,
	}}
	c := &client{hubQuery: query}
	got, err := c.QueryVrfKey(context.Background(), "BUILDER", "trueopen1builder")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.ActivePubKey, active) || got.ActiveFromEpoch != 5 || !bytes.Equal(got.PendingPubKey, pending) ||
		got.PendingFromEpoch != 8 || got.AuthorizationNonce != 2 {
		t.Fatalf("key = %+v", got)
	}
	if query.vrfRequest.GetParticipantType() != sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER ||
		query.vrfRequest.GetOperatorAddress() != "trueopen1builder" {
		t.Fatalf("request = %v", query.vrfRequest)
	}
	if key, err := (&client{hubQuery: &dispatchHubQuery{vrf: &hubv1.QueryVrfKeyResponse{ActiveVrfPubkey: active, ActiveFromEpoch: 5}}}).
		QueryVrfKey(context.Background(), "CORTEX", "trueopen1worker"); err != nil || key.PendingPubKey != nil || key.PendingFromEpoch != 0 {
		t.Fatalf("no pending key = %+v, %v", key, err)
	}
	if _, err := c.QueryVrfKey(context.Background(), "", "trueopen1builder"); err == nil {
		t.Fatal("an unspecified participant type was sent; zero selects the Validator key")
	}
	for name, response := range map[string]*hubv1.QueryVrfKeyResponse{
		"short active key":         {ActiveVrfPubkey: active[:31]},
		"short pending key":        {ActiveVrfPubkey: active, PendingVrfPubkey: pending[:31], PendingFromEpoch: &pendingEpoch},
		"pending key, no epoch":    {ActiveVrfPubkey: active, PendingVrfPubkey: pending},
		"pending epoch, no key":    {ActiveVrfPubkey: active, PendingFromEpoch: &pendingEpoch},
		"pending not after active": {ActiveVrfPubkey: active, ActiveFromEpoch: 9, PendingVrfPubkey: pending, PendingFromEpoch: &pendingEpoch},
	} {
		c := &client{hubQuery: &dispatchHubQuery{vrf: response}}
		if _, err := c.QueryVrfKey(context.Background(), "BUILDER", "trueopen1builder"); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	empty := &client{hubQuery: &dispatchHubQuery{vrf: &hubv1.QueryVrfKeyResponse{}}}
	if _, err := empty.QueryVrfKey(context.Background(), "BUILDER", "trueopen1builder"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no key: %v", err)
	}
}

func TestQueryBeacon(t *testing.T) {
	beacon := &hubv1.BeaconState{Height: 100, RandomnessHex: "ab", Verified: true, BlockHash: mustHash32("f1")}
	c := &client{hubQuery: &dispatchHubQuery{beacon: &hubv1.QueryBeaconResponse{Beacon: beacon}}}
	got, err := c.QueryBeacon(context.Background(), 100)
	if err != nil || got.GetRandomnessHex() != "ab" {
		t.Fatalf("beacon = %v, %v", got, err)
	}
	if _, err := c.QueryBeacon(context.Background(), 101); err == nil {
		t.Fatal("a beacon for another height was accepted")
	}
	if _, err := c.QueryBeacon(context.Background(), 0); err == nil {
		t.Fatal("height 0 was sent")
	}
	empty := &client{hubQuery: &dispatchHubQuery{beacon: &hubv1.QueryBeaconResponse{}}}
	if _, err := empty.QueryBeacon(context.Background(), 100); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no beacon: %v", err)
	}
}

func TestStubAnswersPhase1QueriesWithoutAChain(t *testing.T) {
	stub := NewStub(slog.New(slog.DiscardHandler), config.ChainConfig{ChainID: "trueopen-localnet-1"})
	ctx := context.Background()
	if _, err := stub.QueryDispatchRecordByOrder(ctx, testSessionIDHex, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("record: %v", err)
	}
	if _, err := stub.QueryDispatchParams(ctx); !errors.Is(err, ErrNotSupportedOnChain) {
		t.Fatalf("params: %v", err)
	}
	if _, err := stub.QueryVrfKey(ctx, "BUILDER", "trueopen1builder"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("vrf key: %v", err)
	}
}

type memberPages struct {
	hubv1connect.QueryClient
	pages    map[string]*hubv1.QueryCandidatePoolMembersResponse // by page token
	requests []*hubv1.QueryCandidatePoolMembersRequest
}

func (q *memberPages) CandidatePoolMembers(_ context.Context, req *connect.Request[hubv1.QueryCandidatePoolMembersRequest]) (*connect.Response[hubv1.QueryCandidatePoolMembersResponse], error) {
	q.requests = append(q.requests, req.Msg)
	page, ok := q.pages[string(req.Msg.GetPage().GetPageToken())]
	if !ok {
		return nil, notFound
	}
	return connect.NewResponse(page), nil
}

func poolMembers(slots ...uint32) []*hubv1.CandidatePoolMemberViewV1 {
	out := make([]*hubv1.CandidatePoolMemberViewV1, len(slots))
	for i, slot := range slots {
		out[i] = &hubv1.CandidatePoolMemberViewV1{CandidateSlot: slot, SlotVersion: 1, OperatorAddress: "trueopen1op" + string(rune('a'+slot))}
	}
	return out
}

func TestListCandidatePoolMembersWalksEveryPage(t *testing.T) {
	snapshot := mustHash32("66")
	query := &memberPages{pages: map[string]*hubv1.QueryCandidatePoolMembersResponse{
		"":   {Members: poolMembers(1, 3), Page: &sharedv1.QueryPageResponseV1{NextPageToken: []byte("p2")}},
		"p2": {Members: poolMembers(7)},
	}}
	c := &client{hubQuery: query}
	got, err := ListCandidatePoolMembers(context.Background(), c, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].GetCandidateSlot() != 1 || got[2].GetCandidateSlot() != 7 {
		t.Fatalf("members = %v", got)
	}
	if len(query.requests) != 2 || !bytes.Equal(query.requests[0].GetSnapshotId(), snapshot) ||
		string(query.requests[1].GetPage().GetPageToken()) != "p2" {
		t.Fatalf("requests = %v", query.requests)
	}

	for name, pages := range map[string]map[string]*hubv1.QueryCandidatePoolMembersResponse{
		"slots out of order in a page": {"": {Members: poolMembers(3, 1)}},
		"page goes back": {
			"":   {Members: poolMembers(1, 3), Page: &sharedv1.QueryPageResponseV1{NextPageToken: []byte("p2")}},
			"p2": {Members: poolMembers(3)},
		},
		"token repeats":           {"": {Members: poolMembers(1)}, "p": {Members: nil, Page: &sharedv1.QueryPageResponseV1{NextPageToken: []byte("p")}}},
		"member without operator": {"": {Members: []*hubv1.CandidatePoolMemberViewV1{{CandidateSlot: 1}}}},
	} {
		if name == "token repeats" {
			pages[""].Page = &sharedv1.QueryPageResponseV1{NextPageToken: []byte("p")}
		}
		if _, err := ListCandidatePoolMembers(context.Background(), &client{hubQuery: &memberPages{pages: pages}}, snapshot); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if _, _, err := c.QueryCandidatePoolMembers(context.Background(), []byte{1}, nil); err == nil {
		t.Fatal("a short snapshot id was sent")
	}
}
