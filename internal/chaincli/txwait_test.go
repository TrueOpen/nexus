package chaincli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// scriptedTxQuerier answers QueryTx from a script, then repeats its last answer.
type scriptedTxQuerier struct {
	mu      sync.Mutex
	answers []txAnswer
	calls   int
}

type txAnswer struct {
	result TxResult
	err    error
}

func (q *scriptedTxQuerier) QueryTx(context.Context, []byte) (TxResult, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	answer := q.answers[min(q.calls, len(q.answers)-1)]
	q.calls++
	return answer.result, answer.err
}

func (q *scriptedTxQuerier) callCount() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.calls
}

func jsonLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
}

func logRecords(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("decode log line %q: %v", line, err)
		}
		records = append(records, record)
	}
	return records
}

var testTxWait = TxWait{Kind: "MsgBatchSubmitVerifyResult", TaskID: "task-1", Interval: 5 * time.Millisecond, Timeout: 60 * time.Millisecond}

func TestWaitTxReturnsTheIncludedResult(t *testing.T) {
	notFound := txAnswer{err: ErrNotFound}
	q := &scriptedTxQuerier{answers: []txAnswer{notFound, notFound, {result: TxResult{TxHash: []byte{1}, Height: 9}}}}
	log, buf := jsonLogger()
	got, err := WaitTx(context.Background(), log, q, []byte{1}, testTxWait)
	if err != nil || got.Code != 0 || got.Height != 9 {
		t.Fatalf("WaitTx = %+v, %v", got, err)
	}
	if q.callCount() != 3 {
		t.Fatalf("queries = %d, want 3", q.callCount())
	}
	if len(logRecords(t, buf)) != 0 {
		t.Fatalf("a successful result was logged: %s", buf.String())
	}
}

// A block execution failure comes back as the result, logged at WARN with the kind, task, hash,
// code, codespace and a raw_log cut to 512 bytes -- a panic stack is never logged whole.
func TestWaitTxLogsAnExecutionFailureWithATruncatedRawLog(t *testing.T) {
	rawLog := "panic: runtime error: " + strings.Repeat("goroutine 1 [running]:\n", 200)
	q := &scriptedTxQuerier{answers: []txAnswer{{result: TxResult{
		TxHash: []byte{0xab, 0xcd}, Height: 12, Code: 111222, Codespace: "undefined", RawLog: rawLog,
	}}}}
	log, buf := jsonLogger()
	got, err := WaitTx(context.Background(), log, q, []byte{0xab, 0xcd}, testTxWait)
	if err != nil || got.Code != 111222 || got.RawLog != rawLog {
		t.Fatalf("WaitTx = %+v, %v; the failed result must come back whole", got.Code, err)
	}
	records := logRecords(t, buf)
	if len(records) != 1 {
		t.Fatalf("log records = %d, want 1: %s", len(records), buf.String())
	}
	record := records[0]
	want := map[string]any{
		"level": "WARN", "kind": "MsgBatchSubmitVerifyResult", "task_id": "task-1", "tx_hash": "abcd",
		"code": float64(111222), "codespace": "undefined", "raw_log_bytes": float64(len(rawLog)),
	}
	for key, value := range want {
		if record[key] != value {
			t.Fatalf("log %s = %v, want %v (record %v)", key, record[key], value, record)
		}
	}
	logged, _ := record["raw_log"].(string)
	if len(logged) != RawLogLimit || !strings.HasPrefix(rawLog, logged) {
		t.Fatalf("logged raw_log is %d bytes, want the first %d", len(logged), RawLogLimit)
	}
}

func TestWaitTxTimesOutAsUnknown(t *testing.T) {
	q := &scriptedTxQuerier{answers: []txAnswer{{err: ErrNotFound}}}
	started := time.Now()
	_, err := WaitTx(context.Background(), nil, q, []byte{1}, testTxWait)
	if !errors.Is(err, ErrTxUnknown) {
		t.Fatalf("err = %v, want ErrTxUnknown", err)
	}
	if elapsed := time.Since(started); elapsed < testTxWait.Timeout {
		t.Fatalf("gave up after %s, before the %s bound", elapsed, testTxWait.Timeout)
	}
	if q.callCount() < 2 {
		t.Fatalf("queries = %d, want polling", q.callCount())
	}

	// A result that cannot be read counts as unknown too, not as a failure.
	q = &scriptedTxQuerier{answers: []txAnswer{{err: errors.New("endpoint unavailable")}}}
	if _, err := WaitTx(context.Background(), nil, q, []byte{1}, testTxWait); !errors.Is(err, ErrTxUnknown) ||
		!strings.Contains(err.Error(), "endpoint unavailable") {
		t.Fatalf("err = %v, want ErrTxUnknown carrying the query error", err)
	}
	if _, err := WaitTx(context.Background(), nil, q, nil, testTxWait); !errors.Is(err, ErrTxUnknown) {
		t.Fatalf("no hash: err = %v", err)
	}
}

func TestTruncateRawLogKeepsUTF8Whole(t *testing.T) {
	if got := TruncateRawLog("short"); got != "short" {
		t.Fatalf("short raw_log changed: %q", got)
	}
	raw := strings.Repeat("a", RawLogLimit-1) + "é" + "tail"
	got := TruncateRawLog(raw)
	if len(got) != RawLogLimit-1 || !strings.HasPrefix(raw, got) {
		t.Fatalf("cut = %d bytes, want %d (before the split rune)", len(got), RawLogLimit-1)
	}
}
