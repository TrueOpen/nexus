package chaincli

import (
	"context"
	"net/http"
	"strings"

	"connectrpc.com/connect"

	authv1beta1 "cosmossdk.io/api/cosmos/auth/v1beta1"
	cmtv1beta1 "cosmossdk.io/api/cosmos/base/tendermint/v1beta1"
	txv1beta1 "cosmossdk.io/api/cosmos/tx/v1beta1"
)

type authQueryClient interface {
	Account(context.Context, *connect.Request[authv1beta1.QueryAccountRequest]) (*connect.Response[authv1beta1.QueryAccountResponse], error)
}

type txServiceClient interface {
	GetTx(context.Context, *connect.Request[txv1beta1.GetTxRequest]) (*connect.Response[txv1beta1.GetTxResponse], error)
	BroadcastTx(context.Context, *connect.Request[txv1beta1.BroadcastTxRequest]) (*connect.Response[txv1beta1.BroadcastTxResponse], error)
	Simulate(context.Context, *connect.Request[txv1beta1.SimulateRequest]) (*connect.Response[txv1beta1.SimulateResponse], error)
}

type latestBlockClient interface {
	GetLatestBlock(context.Context, *connect.Request[cmtv1beta1.GetLatestBlockRequest]) (*connect.Response[cmtv1beta1.GetLatestBlockResponse], error)
}

// cometInfoClient reads the two CometBFT facts the chain identity check needs: a block's hash by
// height and whether the node is still catching up.
type cometInfoClient interface {
	GetBlockByHeight(context.Context, *connect.Request[cmtv1beta1.GetBlockByHeightRequest]) (*connect.Response[cmtv1beta1.GetBlockByHeightResponse], error)
	GetSyncing(context.Context, *connect.Request[cmtv1beta1.GetSyncingRequest]) (*connect.Response[cmtv1beta1.GetSyncingResponse], error)
}

type cosmosAuthClient struct {
	account *connect.Client[authv1beta1.QueryAccountRequest, authv1beta1.QueryAccountResponse]
}

func (c *cosmosAuthClient) Account(ctx context.Context, req *connect.Request[authv1beta1.QueryAccountRequest]) (*connect.Response[authv1beta1.QueryAccountResponse], error) {
	return c.account.CallUnary(ctx, req)
}

type cosmosTxClient struct {
	getTx       *connect.Client[txv1beta1.GetTxRequest, txv1beta1.GetTxResponse]
	broadcastTx *connect.Client[txv1beta1.BroadcastTxRequest, txv1beta1.BroadcastTxResponse]
	simulate    *connect.Client[txv1beta1.SimulateRequest, txv1beta1.SimulateResponse]
}

func (c *cosmosTxClient) Simulate(ctx context.Context, req *connect.Request[txv1beta1.SimulateRequest]) (*connect.Response[txv1beta1.SimulateResponse], error) {
	return c.simulate.CallUnary(ctx, req)
}

func (c *cosmosTxClient) GetTx(ctx context.Context, req *connect.Request[txv1beta1.GetTxRequest]) (*connect.Response[txv1beta1.GetTxResponse], error) {
	return c.getTx.CallUnary(ctx, req)
}

func (c *cosmosTxClient) BroadcastTx(ctx context.Context, req *connect.Request[txv1beta1.BroadcastTxRequest]) (*connect.Response[txv1beta1.BroadcastTxResponse], error) {
	return c.broadcastTx.CallUnary(ctx, req)
}

type cosmosLatestBlockClient struct {
	latest *connect.Client[cmtv1beta1.GetLatestBlockRequest, cmtv1beta1.GetLatestBlockResponse]
}

func (c *cosmosLatestBlockClient) GetLatestBlock(ctx context.Context, req *connect.Request[cmtv1beta1.GetLatestBlockRequest]) (*connect.Response[cmtv1beta1.GetLatestBlockResponse], error) {
	return c.latest.CallUnary(ctx, req)
}

type cosmosCometInfoClient struct {
	blockByHeight *connect.Client[cmtv1beta1.GetBlockByHeightRequest, cmtv1beta1.GetBlockByHeightResponse]
	syncing       *connect.Client[cmtv1beta1.GetSyncingRequest, cmtv1beta1.GetSyncingResponse]
}

func (c *cosmosCometInfoClient) GetBlockByHeight(ctx context.Context, req *connect.Request[cmtv1beta1.GetBlockByHeightRequest]) (*connect.Response[cmtv1beta1.GetBlockByHeightResponse], error) {
	return c.blockByHeight.CallUnary(ctx, req)
}

func (c *cosmosCometInfoClient) GetSyncing(ctx context.Context, req *connect.Request[cmtv1beta1.GetSyncingRequest]) (*connect.Response[cmtv1beta1.GetSyncingResponse], error) {
	return c.syncing.CallUnary(ctx, req)
}

func newCosmosAuthClient(httpClient *http.Client, baseURL string, options ...connect.ClientOption) authQueryClient {
	return &cosmosAuthClient{account: connect.NewClient[authv1beta1.QueryAccountRequest, authv1beta1.QueryAccountResponse](
		httpClient, strings.TrimRight(baseURL, "/")+"/cosmos.auth.v1beta1.Query/Account", options...,
	)}
}

func newCosmosTxClient(httpClient *http.Client, baseURL string, options ...connect.ClientOption) txServiceClient {
	baseURL = strings.TrimRight(baseURL, "/")
	return &cosmosTxClient{
		getTx:       connect.NewClient[txv1beta1.GetTxRequest, txv1beta1.GetTxResponse](httpClient, baseURL+"/cosmos.tx.v1beta1.Service/GetTx", options...),
		broadcastTx: connect.NewClient[txv1beta1.BroadcastTxRequest, txv1beta1.BroadcastTxResponse](httpClient, baseURL+"/cosmos.tx.v1beta1.Service/BroadcastTx", options...),
		simulate:    connect.NewClient[txv1beta1.SimulateRequest, txv1beta1.SimulateResponse](httpClient, baseURL+"/cosmos.tx.v1beta1.Service/Simulate", options...),
	}
}

func newCosmosLatestBlockClient(httpClient *http.Client, baseURL string, options ...connect.ClientOption) latestBlockClient {
	return &cosmosLatestBlockClient{latest: connect.NewClient[cmtv1beta1.GetLatestBlockRequest, cmtv1beta1.GetLatestBlockResponse](
		httpClient, strings.TrimRight(baseURL, "/")+"/cosmos.base.tendermint.v1beta1.Service/GetLatestBlock", options...,
	)}
}

func newCosmosCometInfoClient(httpClient *http.Client, baseURL string, options ...connect.ClientOption) cometInfoClient {
	baseURL = strings.TrimRight(baseURL, "/")
	return &cosmosCometInfoClient{
		blockByHeight: connect.NewClient[cmtv1beta1.GetBlockByHeightRequest, cmtv1beta1.GetBlockByHeightResponse](
			httpClient, baseURL+"/cosmos.base.tendermint.v1beta1.Service/GetBlockByHeight", options...),
		syncing: connect.NewClient[cmtv1beta1.GetSyncingRequest, cmtv1beta1.GetSyncingResponse](
			httpClient, baseURL+"/cosmos.base.tendermint.v1beta1.Service/GetSyncing", options...),
	}
}
