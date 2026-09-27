package chaincli

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"
	"unicode/utf8"
)

// RawLogLimit is how many bytes of a failed transaction's raw_log are logged. A chain panic puts
// the whole stack into raw_log; the head carries the reason and the rest only floods the log.
const RawLogLimit = 512

// ErrTxUnknown means a broadcast transaction has no block result yet: it was not found in a
// block within the wait, or its result could not be read. It may still be included later.
var ErrTxUnknown = errors.New("chaincli: transaction has no block result yet")

// TxQuerier reads the block execution result of a broadcast transaction.
type TxQuerier interface {
	QueryTx(ctx context.Context, txHash []byte) (TxResult, error)
}

// TxWait describes one WaitTx call.
type TxWait struct {
	// Kind and TaskID label the failure log.
	Kind   string
	TaskID string
	// Interval spaces the queries, about one block apart; Timeout bounds the whole wait.
	Interval time.Duration
	Timeout  time.Duration
}

// txQueryTimeout bounds one block result query inside WaitTx, so a stalled node cannot stretch
// the wait much past its bound.
const txQueryTimeout = 2 * time.Second

// WaitTx queries the block result of txHash every Interval until it is found or Timeout has
// passed; the last query runs at the bound. A found result is returned as is, failed or not;
// the caller reads its Code. A failed one is logged at WARN here, so every execution failure
// leaves the same trace. When no result is found in time the error wraps ErrTxUnknown.
func WaitTx(ctx context.Context, log *slog.Logger, q TxQuerier, txHash []byte, wait TxWait) (TxResult, error) {
	if q == nil || len(txHash) == 0 {
		return TxResult{}, fmt.Errorf("%w: no transaction hash to query", ErrTxUnknown)
	}
	interval := wait.Interval
	if interval <= 0 {
		interval = time.Second
	}
	deadline := time.Now().Add(wait.Timeout)
	for {
		if pause := min(interval, time.Until(deadline)); pause > 0 {
			timer := time.NewTimer(pause)
			select {
			case <-ctx.Done():
				timer.Stop()
				return TxResult{}, fmt.Errorf("%w: tx %x: %v", ErrTxUnknown, txHash, ctx.Err())
			case <-timer.C:
			}
		}
		queryCtx, cancel := context.WithTimeout(ctx, txQueryTimeout)
		result, err := q.QueryTx(queryCtx, txHash)
		cancel()
		if err == nil {
			return found(log, wait, result)
		}
		if time.Now().Before(deadline) {
			continue
		}
		if errors.Is(err, ErrNotFound) {
			return TxResult{}, fmt.Errorf("%w: tx %x not in a block after %s", ErrTxUnknown, txHash, wait.Timeout)
		}
		return TxResult{}, fmt.Errorf("%w: tx %x after %s: %v", ErrTxUnknown, txHash, wait.Timeout, err)
	}
}

func found(log *slog.Logger, wait TxWait, result TxResult) (TxResult, error) {
	if result.Code != 0 {
		LogTxFailure(log, wait.Kind, wait.TaskID, result)
	}
	return result, nil
}

// LogTxFailure records a transaction the chain executed and refused, with raw_log cut to
// RawLogLimit bytes.
func LogTxFailure(log *slog.Logger, kind, taskID string, result TxResult) {
	if log == nil {
		return
	}
	log.Warn("tx failed in block execution",
		"kind", kind, "task_id", taskID, "tx_hash", hex.EncodeToString(result.TxHash),
		"height", result.Height, "code", result.Code, "codespace", result.Codespace,
		"raw_log", TruncateRawLog(result.RawLog), "raw_log_bytes", len(result.RawLog))
}

// TruncateRawLog cuts raw_log to at most RawLogLimit bytes, on a UTF-8 boundary.
func TruncateRawLog(raw string) string {
	if len(raw) <= RawLogLimit {
		return raw
	}
	cut := RawLogLimit
	for cut > 0 && !utf8.RuneStart(raw[cut]) {
		cut--
	}
	return raw[:cut]
}
