package dispatcher

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// newLoggedEnv is newEnv with the dispatcher's log captured.
func newLoggedEnv(t *testing.T) (*env, *bytes.Buffer) {
	t.Helper()
	e := newEnv(t)
	logs := &bytes.Buffer{}
	e.d.log = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return e, logs
}

// logLine returns the one log line with msg, failing when there is none.
func logLine(t *testing.T, logs *bytes.Buffer, msg string) string {
	t.Helper()
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, `msg="`+msg+`"`) {
			return line
		}
	}
	t.Fatalf("no %q logged:\n%s", msg, logs)
	return ""
}

func wantAttrs(t *testing.T, line string, attrs ...string) {
	t.Helper()
	for _, a := range attrs {
		if !strings.Contains(line, " "+a) {
			t.Errorf("%q missing from %s", a, line)
		}
	}
}

// An accept and a reject are logged with how long after its issue the answer came, the window
// the ticket was given, what of it was left and the Worker's RTT.
func TestAnswersAreLoggedWithTheirTiming(t *testing.T) {
	e, logs := newLoggedEnv(t)
	e.streams.rtt[op7] = 30 * time.Millisecond  // tier 1: 300 ms
	e.streams.rtt[op1] = 120 * time.Millisecond // tier 2: 500 ms
	s := e.session(0xaa, 0)
	e.dispatch(e.order(s, 0, 1)) // drawn op7, op1, op3
	e.clock.advance(70 * time.Millisecond)
	if op := e.reject(); op != op7 {
		t.Fatalf("rejected by %s", op)
	}
	wantAttrs(t, logLine(t, logs, "dispatch rejected"),
		"operator="+op7, "free_slot=true", "tier=1", "answer_ms=70", "window_ms=300", "left_ms=230", "rtt_ms=30")
	e.clock.advance(180 * time.Millisecond)
	if op, _ := e.accept(); op != op1 {
		t.Fatalf("accepted by %s", op)
	}
	wantAttrs(t, logLine(t, logs, "dispatch accepted"),
		"worker="+op1, "rank=", "tier=2", "answer_ms=180", "window_ms=500", "left_ms=320", "rtt_ms=120")
}

// A ticket that times out is logged with its window, and an accept that comes after the walk
// moved on is logged with how late it was.
func TestTimeoutAndLateAcceptAreLogged(t *testing.T) {
	e, logs := newLoggedEnv(t)
	s := e.session(0xaa, 0)
	e.dispatch(e.order(s, 0, 1))
	op, ticket, hash := e.lastOffer()
	e.clock.advance(500 * time.Millisecond) // no RTT measured: the last tier, 500 ms
	line := logLine(t, logs, "dispatch ticket timed out")
	wantAttrs(t, line, "operator="+op, "tier=2", "answer_ms=500", "window_ms=500", "left_ms=0")
	if strings.Contains(line, "rtt_ms=") {
		t.Errorf("an unmeasured RTT is logged: %s", line)
	}
	e.clock.advance(40 * time.Millisecond)
	m, from := e.acceptMsg(ticket, hash)
	if err := e.d.HandleDispatchAccept(context.Background(), from, m); !errors.Is(err, ErrTicketClosed) {
		t.Fatalf("late accept = %v", err)
	}
	line = logLine(t, logs, "dispatch accept of a timed-out ticket")
	wantAttrs(t, line, "operator="+op, "left_ms=-40")
	if strings.Contains(line, "answer_ms=") || strings.Contains(line, "window_ms=") {
		t.Errorf("the next ticket's issue time is logged for a timed-out one: %s", line)
	}
}

// A ticket issued before a restart has no known issue time: its answer is logged with what is
// left of its window only.
func TestAnswerAfterARestartHasNoIssueTime(t *testing.T) {
	e := newEnv(t)
	s := e.session(0xaa, 0)
	e.dispatch(e.order(s, 0, 1))
	e.clock.advance(100 * time.Millisecond)
	if err := e.d.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.open(e.store)
	logs := &bytes.Buffer{}
	e.d.log = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	if err := e.d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.accept()
	line := logLine(t, logs, "dispatch accepted")
	wantAttrs(t, line, "left_ms=400")
	if strings.Contains(line, "answer_ms=") || strings.Contains(line, "window_ms=") {
		t.Errorf("an unknown issue time is logged: %s", line)
	}
}
