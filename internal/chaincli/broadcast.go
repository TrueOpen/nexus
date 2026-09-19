package chaincli

import (
	"context"
	"encoding/hex"
	"fmt"

	"connectrpc.com/connect"

	txv1beta1 "cosmossdk.io/api/cosmos/tx/v1beta1"
)

// BroadcastTx broadcasts already-signed tx bytes through
// cosmos.tx.v1beta1.Service/BroadcastTx on the node gRPC endpoint.
func (c *client) BroadcastTx(ctx context.Context, tx []byte) (TxResult, error) {
	if c.tx == nil {
		return TxResult{}, fmt.Errorf("broadcast: tx gRPC client is not configured")
	}
	resp, err := c.tx.BroadcastTx(ctx, connect.NewRequest(&txv1beta1.BroadcastTxRequest{
		TxBytes: tx,
		Mode:    txv1beta1.BroadcastMode_BROADCAST_MODE_SYNC,
	}))
	if err != nil {
		return TxResult{}, fmt.Errorf("broadcast: gRPC endpoint unavailable: %s", redactSensitiveText(err.Error()))
	}
	txResp := resp.Msg.GetTxResponse()
	if txResp == nil {
		return TxResult{}, fmt.Errorf("broadcast: empty result")
	}

	res := TxResult{
		Code:   txResp.GetCode(),
		Height: txResp.GetHeight(),
		RawLog: txResp.GetRawLog(),
	}
	if h := txResp.GetTxhash(); h != "" {
		if raw, derr := hex.DecodeString(h); derr == nil {
			res.TxHash = raw
		} else {
			res.TxHash = []byte(h)
		}
	}
	return res, nil
}

// QueryTx fetches the authoritative DeliverTx result for a previously
// broadcast transaction hash.
func (c *client) QueryTx(ctx context.Context, txHash []byte) (TxResult, error) {
	if c.tx == nil {
		return TxResult{}, fmt.Errorf("query tx: tx gRPC client is not configured")
	}
	resp, err := c.tx.GetTx(ctx, connect.NewRequest(&txv1beta1.GetTxRequest{
		Hash: fmt.Sprintf("%X", txHash),
	}))
	if err != nil {
		if connect.CodeOf(err) == connect.CodeNotFound {
			return TxResult{}, fmt.Errorf("query tx hash=%q: %w", fmt.Sprintf("%X", txHash), ErrNotFound)
		}
		return TxResult{}, fmt.Errorf("query tx: gRPC endpoint unavailable: %s", redactSensitiveText(err.Error()))
	}
	txResp := resp.Msg.GetTxResponse()
	if txResp == nil {
		return TxResult{}, fmt.Errorf("query tx: empty result")
	}

	res := TxResult{
		Code:   txResp.GetCode(),
		Height: txResp.GetHeight(),
		RawLog: txResp.GetRawLog(),
	}
	if h := txResp.GetTxhash(); h != "" {
		if raw, derr := hex.DecodeString(h); derr == nil {
			res.TxHash = raw
		} else {
			res.TxHash = []byte(h)
		}
	}
	return res, nil
}
