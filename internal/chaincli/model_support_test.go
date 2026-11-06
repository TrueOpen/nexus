package chaincli

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/hub/v1/hubv1connect"
)

const supportTestOperator = "trueopen15x328f9956n632d24wk2mt40kzcm9va5vw5e0a"

// supportHubQuery answers the Hub reads the model support relay makes; other methods panic.
type supportHubQuery struct {
	hubv1connect.QueryClient
	params    *hubv1.HubParamsV2
	support   *hubv1.QueryDailySupportResponse
	bond      *hubv1.QueryServiceBondResponse
	err       error
	gotDaily  *hubv1.QueryDailySupportRequest
	gotBond   *hubv1.QueryServiceBondRequest
	paramsErr error
}

func (q *supportHubQuery) Params(context.Context, *connect.Request[hubv1.QueryHubParamsRequest]) (*connect.Response[hubv1.QueryHubParamsResponse], error) {
	if q.paramsErr != nil {
		return nil, q.paramsErr
	}
	return connect.NewResponse(&hubv1.QueryHubParamsResponse{Params: q.params}), nil
}

func (q *supportHubQuery) DailySupport(_ context.Context, req *connect.Request[hubv1.QueryDailySupportRequest]) (*connect.Response[hubv1.QueryDailySupportResponse], error) {
	q.gotDaily = req.Msg
	if q.err != nil {
		return nil, q.err
	}
	return connect.NewResponse(q.support), nil
}

func (q *supportHubQuery) ServiceBond(_ context.Context, req *connect.Request[hubv1.QueryServiceBondRequest]) (*connect.Response[hubv1.QueryServiceBondResponse], error) {
	q.gotBond = req.Msg
	if q.err != nil {
		return nil, q.err
	}
	return connect.NewResponse(q.bond), nil
}

func supportTestClient(q *supportHubQuery) *client {
	return &client{log: slog.New(slog.NewTextHandler(io.Discard, nil)), hubQuery: q}
}

func supportTestParams() *hubv1.HubParamsV2 {
	return &hubv1.HubParamsV2{
		Epoch:   &hubv1.EpochParamsV1{EpochLengthBlocks: 100},
		Service: &hubv1.ServiceParamsV1{MaxServiceMaterialExpiryBlocks: 600},
		Support: &hubv1.SupportParamsV1{
			MaxSupportedModelsPerOperator: 8, MaxDailySupportConfirmationsPerBatch: 16,
			MaxDailySupportItemsPerBatch: 64, MaxDailySupportBatchBytes: 32768,
		},
	}
}

func TestQuerySupportParamsReadsLimitsInOneRead(t *testing.T) {
	got, err := supportTestClient(&supportHubQuery{params: supportTestParams()}).QuerySupportParams(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := SupportParams{
		EpochLengthBlocks: 100, MaxServiceMaterialExpiryBlocks: 600, MaxSupportedModelsPerOperator: 8,
		MaxConfirmationsPerBatch: 16, MaxItemsPerBatch: 64, MaxBatchBytes: 32768,
	}
	if got != want {
		t.Fatalf("params = %+v, want %+v", got, want)
	}
}

// A zero epoch length is the Hub default; a zero limit would make the chain refuse every batch,
// so it is an error rather than "no limit".
func TestQuerySupportParamsDefaultsEpochAndRefusesZeroLimits(t *testing.T) {
	params := supportTestParams()
	params.Epoch.EpochLengthBlocks = 0
	got, err := supportTestClient(&supportHubQuery{params: params}).QuerySupportParams(context.Background())
	if err != nil || got.EpochLengthBlocks != defaultEpochLengthBlocks {
		t.Fatalf("epoch length = %d, %v; want the Hub default", got.EpochLengthBlocks, err)
	}
	for name, edit := range map[string]func(*hubv1.HubParamsV2){
		"expiry":        func(p *hubv1.HubParamsV2) { p.Service.MaxServiceMaterialExpiryBlocks = 0 },
		"models":        func(p *hubv1.HubParamsV2) { p.Support.MaxSupportedModelsPerOperator = 0 },
		"confirmations": func(p *hubv1.HubParamsV2) { p.Support.MaxDailySupportConfirmationsPerBatch = 0 },
		"items":         func(p *hubv1.HubParamsV2) { p.Support.MaxDailySupportItemsPerBatch = 0 },
		"bytes":         func(p *hubv1.HubParamsV2) { p.Support.MaxDailySupportBatchBytes = 0 },
	} {
		params := supportTestParams()
		edit(params)
		if _, err := supportTestClient(&supportHubQuery{params: params}).QuerySupportParams(context.Background()); err == nil {
			t.Errorf("%s: zero limit accepted", name)
		}
	}
}

func TestQueryDailySupportReturnsTheRowOfItsKey(t *testing.T) {
	row := &hubv1.DailySupportState{
		Epoch: 7, OperatorAddress: supportTestOperator, SupportedModelsHash: make([]byte, 32),
		SignatureDigest: make([]byte, 32), AcceptedHeight: 705,
	}
	q := &supportHubQuery{support: &hubv1.QueryDailySupportResponse{Support: row}}
	got, err := supportTestClient(q).QueryDailySupport(context.Background(), supportTestOperator, 7)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(got, row) || q.gotDaily.GetOperatorAddress() != supportTestOperator || q.gotDaily.GetEpoch() != 7 {
		t.Fatalf("row = %v for request %v", got, q.gotDaily)
	}
	if _, err := supportTestClient(q).QueryDailySupport(context.Background(), supportTestOperator, 8); err == nil {
		t.Fatal("a row of another epoch was returned")
	}
}

func TestQueryDailySupportNotFound(t *testing.T) {
	for name, q := range map[string]*supportHubQuery{
		"not found": {err: connect.NewError(connect.CodeNotFound, nil)},
		"empty row": {support: &hubv1.QueryDailySupportResponse{Support: &hubv1.DailySupportState{}}},
		"no row":    {support: &hubv1.QueryDailySupportResponse{}},
	} {
		if _, err := supportTestClient(q).QueryDailySupport(context.Background(), supportTestOperator, 7); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: err = %v, want ErrNotFound", name, err)
		}
	}
	unavailable := &supportHubQuery{err: connect.NewError(connect.CodeUnavailable, errors.New("down"))}
	if _, err := supportTestClient(unavailable).QueryDailySupport(context.Background(), supportTestOperator, 7); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("an outage read as %v", err)
	}
}

func TestQueryServiceBond(t *testing.T) {
	bond := &hubv1.ServiceBondState{OperatorAddress: supportTestOperator, Status: hubv1.ServiceBondStatus_SERVICE_BOND_STATUS_JAILED, JailCount: 1}
	q := &supportHubQuery{bond: &hubv1.QueryServiceBondResponse{Bond: bond}}
	got, err := supportTestClient(q).QueryServiceBond(context.Background(), supportTestOperator)
	if err != nil || !proto.Equal(got, bond) || q.gotBond.GetOperatorAddress() != supportTestOperator {
		t.Fatalf("bond = %v, %v", got, err)
	}
	empty := &supportHubQuery{bond: &hubv1.QueryServiceBondResponse{Bond: &hubv1.ServiceBondState{}}}
	if _, err := supportTestClient(empty).QueryServiceBond(context.Background(), supportTestOperator); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty bond: err = %v, want ErrNotFound", err)
	}
	other := &supportHubQuery{bond: &hubv1.QueryServiceBondResponse{Bond: &hubv1.ServiceBondState{OperatorAddress: "trueopen1other"}}}
	if _, err := supportTestClient(other).QueryServiceBond(context.Background(), supportTestOperator); err == nil {
		t.Fatal("another operator's bond was returned")
	}
}

func TestBuildBatchConfirmModelSupportTx(t *testing.T) {
	s := testTxSigner(t)
	msg := &hubv1.MsgBatchConfirmModelSupport{
		EpochIndex: 7, SubmitterAddress: s.Address(),
		Confirmations: []*hubv1.ModelSupportConfirmationV1{{
			OperatorAddress: supportTestOperator, SupportedModels: [][]byte{make([]byte, 32)},
			ServiceAuthorizationNonce: 3, ExpiryHeight: 800, ServiceSignature: make([]byte, 64),
		}},
	}
	raw, err := BuildBatchConfirmModelSupportTx(s, TxParams{ChainID: "trueopen-localnet-1", GasLimit: 400000}, msg)
	if err != nil {
		t.Fatal(err)
	}
	var got hubv1.MsgBatchConfirmModelSupport
	decodeSingleMsg(t, raw, TypeURLMsgBatchConfirmModelSupport, &got)
	if !proto.Equal(&got, msg) {
		t.Fatalf("decoded msg differs:\n%v\n%v", &got, msg)
	}
	for name, edit := range map[string]func(*hubv1.MsgBatchConfirmModelSupport){
		"other submitter":  func(m *hubv1.MsgBatchConfirmModelSupport) { m.SubmitterAddress = "trueopen1other" },
		"no confirmations": func(m *hubv1.MsgBatchConfirmModelSupport) { m.Confirmations = nil },
	} {
		bad := proto.Clone(msg).(*hubv1.MsgBatchConfirmModelSupport)
		edit(bad)
		if _, err := BuildBatchConfirmModelSupportTx(s, TxParams{ChainID: "trueopen-localnet-1"}, bad); err == nil {
			t.Errorf("%s: built", name)
		}
	}
}
