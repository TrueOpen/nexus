package chaincli

import (
	"context"
	"encoding/hex"
	"errors"
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
		Code:      txResp.GetCode(),
		Codespace: txResp.GetCodespace(),
		Height:    txResp.GetHeight(),
		RawLog:    txResp.GetRawLog(),
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

// Simulate runs signed tx bytes through cosmos.tx.v1beta1.Service/Simulate: the node executes
// the messages against its current state without committing, skipping signature checks and
// without consuming the sequence.
//
// A tx the chain would refuse comes back as SimResult{OK: false, Error: <the chain's reason>}
// with a nil error: the node reports every ante or message failure as gRPC Unknown. Any other
// failure -- node unreachable, the service not served -- is an error, meaning the tx was not
// judged at all.
func (c *client) Simulate(ctx context.Context, tx []byte) (SimResult, error) {
	if c.tx == nil {
		return SimResult{}, fmt.Errorf("simulate tx: tx gRPC client is not configured")
	}
	resp, err := c.tx.Simulate(ctx, connect.NewRequest(&txv1beta1.SimulateRequest{TxBytes: tx}))
	if err != nil {
		if connect.CodeOf(err) == connect.CodeUnknown {
			var connectErr *connect.Error
			message := err.Error()
			if errors.As(err, &connectErr) {
				message = connectErr.Message()
			}
			return SimResult{OK: false, Error: message}, nil
		}
		if connect.CodeOf(err) == connect.CodeUnimplemented {
			return SimResult{}, fmt.Errorf("simulate tx: %w", ErrNotSupportedOnChain)
		}
		return SimResult{}, fmt.Errorf("simulate tx: gRPC endpoint unavailable: %s", redactSensitiveText(err.Error()))
	}
	return SimResult{OK: true, GasEstimate: resp.Msg.GetGasInfo().GetGasUsed()}, nil
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
		Code:      txResp.GetCode(),
		Codespace: txResp.GetCodespace(),
		Height:    txResp.GetHeight(),
		RawLog:    txResp.GetRawLog(),
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
