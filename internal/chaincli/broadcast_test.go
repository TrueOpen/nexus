package chaincli

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	abciv1beta1 "cosmossdk.io/api/cosmos/base/abci/v1beta1"
	txv1beta1 "cosmossdk.io/api/cosmos/tx/v1beta1"
)

func TestBroadcastTxUsesGRPCService(t *testing.T) {
	fake := &recordTxService{
		resp: &txv1beta1.BroadcastTxResponse{
			TxResponse: &abciv1beta1.TxResponse{
				Height: 123,
				Txhash: "0A0B",
				Code:   0,
				RawLog: "ok",
			},
		},
	}
	c := &client{tx: fake}

	res, err := c.BroadcastTx(context.Background(), []byte{1, 2, 3})
	if err != nil {
		t.Fatalf("BroadcastTx: %v", err)
	}
	if fake.calls != 1 {
		t.Fatalf("gRPC BroadcastTx calls = %d, want 1", fake.calls)
	}
	if !bytes.Equal(fake.req.GetTxBytes(), []byte{1, 2, 3}) {
		t.Fatalf("tx bytes = %x", fake.req.GetTxBytes())
	}
	if fake.req.GetMode() != txv1beta1.BroadcastMode_BROADCAST_MODE_SYNC {
		t.Fatalf("mode = %v, want SYNC", fake.req.GetMode())
	}
	if res.Code != 0 || res.Height != 123 || string(res.TxHash) != "\x0a\x0b" || res.RawLog != "ok" {
		t.Fatalf("result = %+v", res)
	}
}

func TestQueryTxUsesGRPCService(t *testing.T) {
	fake := &recordTxService{
		getResp: &txv1beta1.GetTxResponse{
			TxResponse: &abciv1beta1.TxResponse{
				Height: 124,
				Txhash: "0A0B",
				Code:   7,
				RawLog: "deliver failed",
			},
		},
	}
	c := &client{tx: fake}

	res, err := c.QueryTx(context.Background(), []byte{0x0a, 0x0b})
	if err != nil {
		t.Fatalf("QueryTx: %v", err)
	}
	if fake.getCalls != 1 {
		t.Fatalf("gRPC GetTx calls = %d, want 1", fake.getCalls)
	}
	if fake.getReq.GetHash() != "0A0B" {
		t.Fatalf("hash = %q, want 0A0B", fake.getReq.GetHash())
	}
	if res.Code != 7 || res.Height != 124 || string(res.TxHash) != "\x0a\x0b" || res.RawLog != "deliver failed" {
		t.Fatalf("result = %+v", res)
	}
}

func TestQueryTxNormalizesNotFound(t *testing.T) {
	fake := &recordTxService{
		getErr: connect.NewError(connect.CodeNotFound, errors.New("tx not found")),
	}
	c := &client{tx: fake}

	_, err := c.QueryTx(context.Background(), []byte{0x0a, 0x0b})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("QueryTx error = %v, want ErrNotFound", err)
	}
}

type recordTxService struct {
	calls    int
	req      *txv1beta1.BroadcastTxRequest
	resp     *txv1beta1.BroadcastTxResponse
	err      error
	getCalls int
	getReq   *txv1beta1.GetTxRequest
	getResp  *txv1beta1.GetTxResponse
	getErr   error
	simReq   *txv1beta1.SimulateRequest
	simResp  *txv1beta1.SimulateResponse
	simErr   error
}

func (s *recordTxService) Simulate(_ context.Context, req *connect.Request[txv1beta1.SimulateRequest]) (*connect.Response[txv1beta1.SimulateResponse], error) {
	s.simReq = req.Msg
	if s.simErr != nil {
		return nil, s.simErr
	}
	return connect.NewResponse(s.simResp), nil
}

func (s *recordTxService) GetTx(_ context.Context, req *connect.Request[txv1beta1.GetTxRequest]) (*connect.Response[txv1beta1.GetTxResponse], error) {
	s.getCalls++
	s.getReq = req.Msg
	if s.getErr != nil {
		return nil, s.getErr
	}
	return connect.NewResponse(s.getResp), nil
}

func (s *recordTxService) BroadcastTx(_ context.Context, req *connect.Request[txv1beta1.BroadcastTxRequest]) (*connect.Response[txv1beta1.BroadcastTxResponse], error) {
	s.calls++
	s.req = req.Msg
	if s.err != nil {
		return nil, s.err
	}
	return connect.NewResponse(s.resp), nil
}

// Simulate tells a tx the chain would refuse (gRPC Unknown, with the chain's reason) apart
// from a node that could not judge it.
func TestSimulate(t *testing.T) {
	refused := "failed to execute message; message index: 0: active worker profile requires active support unless the operator is jailed: invalid assignment with gas used: '93212'"
	tests := []struct {
		name    string
		resp    *txv1beta1.SimulateResponse
		err     error
		want    SimResult
		wantErr error
	}{
		{name: "accepted", resp: &txv1beta1.SimulateResponse{GasInfo: &abciv1beta1.GasInfo{GasUsed: 81000}},
			want: SimResult{OK: true, GasEstimate: 81000}},
		{name: "refused", err: connect.NewError(connect.CodeUnknown, errors.New(refused)),
			want: SimResult{OK: false, Error: refused}},
		{name: "not served", err: connect.NewError(connect.CodeUnimplemented, errors.New("unknown service")), wantErr: ErrNotSupportedOnChain},
		{name: "unreachable", err: connect.NewError(connect.CodeUnavailable, errors.New("connection refused")), wantErr: errors.New("")},
		// A proxy's non-gRPC reply is Unknown too, but it is not the chain judging the tx.
		{name: "proxy error", err: connect.NewError(connect.CodeUnknown, errors.New("HTTP status 500 Internal Server Error")), wantErr: errors.New("")},
		{name: "stale sequence", err: connect.NewError(connect.CodeUnknown, errors.New("account sequence mismatch, expected 43, got 42: incorrect account sequence")),
			want: SimResult{OK: false, Error: "account sequence mismatch, expected 43, got 42: incorrect account sequence"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &recordTxService{simResp: tt.resp, simErr: tt.err}
			c := &client{tx: fake}
			got, err := c.Simulate(context.Background(), []byte("signed-tx"))
			if tt.wantErr != nil {
				if err == nil || (errors.Is(tt.wantErr, ErrNotSupportedOnChain) && !errors.Is(err, ErrNotSupportedOnChain)) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("Simulate() = %+v, %v; want %+v", got, err, tt.want)
			}
			if string(fake.simReq.GetTxBytes()) != "signed-tx" {
				t.Fatalf("simulated tx bytes = %q", fake.simReq.GetTxBytes())
			}
		})
	}
}
