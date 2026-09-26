package chaincli

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

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
// A tx the chain refuses comes back as SimResult{OK: false, Error: <the chain's reason>} with a
// nil error. The node reports such a refusal as gRPC Unknown carrying the ABCI message; since a
// proxy's non-gRPC reply also reads as Unknown, only an answer that carries the chain's own
// failure text counts as a refusal (simulateRefusalMarks). Anything else -- node unreachable,
// the service not served, a reply that is not the chain's -- is an error: the tx was not judged.
func (c *client) Simulate(ctx context.Context, tx []byte) (SimResult, error) {
	if c.tx == nil {
		return SimResult{}, fmt.Errorf("simulate tx: tx gRPC client is not configured")
	}
	resp, err := c.tx.Simulate(ctx, connect.NewRequest(&txv1beta1.SimulateRequest{TxBytes: tx}))
	if err != nil {
		var connectErr *connect.Error
		if connect.CodeOf(err) == connect.CodeUnknown && errors.As(err, &connectErr) && isChainRefusal(connectErr.Message()) {
			return SimResult{OK: false, Error: connectErr.Message()}, nil
		}
		if connect.CodeOf(err) == connect.CodeUnimplemented {
			return SimResult{}, fmt.Errorf("simulate tx: %w", ErrNotSupportedOnChain)
		}
		return SimResult{}, fmt.Errorf("simulate tx: gRPC endpoint unavailable: %s", redactSensitiveText(err.Error()))
	}
	return SimResult{OK: true, GasEstimate: resp.Msg.GetGasInfo().GetGasUsed()}, nil
}

// simulateRefusalMarks are the texts cosmos-sdk puts in a simulation it ran and refused: a
// message that failed to execute, and the ante handler's sequence check.
var simulateRefusalMarks = []string{"failed to execute message", "account sequence mismatch"}

func isChainRefusal(message string) bool {
	for _, mark := range simulateRefusalMarks {
		if strings.Contains(message, mark) {
			return true
		}
	}
	return false
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
