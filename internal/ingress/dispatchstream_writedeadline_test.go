package ingress

import (
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/nexus/v1/nexusv1connect"
	"github.com/TrueOpen/nexus/internal/config"
)

// deadlineRecorder is a response writer that, like the HTTP/2 one, takes write deadlines; it logs
// them and the body writes in order.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	mu        sync.Mutex
	events    []string
	deadlines []time.Time
}

func (d *deadlineRecorder) Write(p []byte) (int, error) {
	d.log("write")
	return d.ResponseRecorder.Write(p)
}

func (d *deadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	if deadline.IsZero() {
		d.log("clear")
		return nil
	}
	d.mu.Lock()
	d.deadlines = append(d.deadlines, deadline)
	d.mu.Unlock()
	d.log("set")
	return nil
}

// log records event, folding repeated writes into one.
func (d *deadlineRecorder) log(event string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if event == "write" && len(d.events) > 0 && d.events[len(d.events)-1] == "write" {
		return
	}
	d.events = append(d.events, event)
}

// Every frame the hub sends to a Cortex is written under a deadline, so a Cortex that stops
// reading cannot hold the handler (and the hub's wait for its sender) forever; the end of the call
// is written without one.
func TestDispatchStreamFrameWritesCarryADeadline(t *testing.T) {
	s, err := New(slog.New(slog.NewTextHandler(io.Discard, nil)), config.IngressConfig{}, AuthParams{Chain: testUserChain},
		&fakeHandler{}, WithDispatchStream(echoServer{}))
	if err != nil {
		t.Fatal(err)
	}
	frame, err := proto.Marshal(&nexusv1.DispatchStreamRequest{Frame: &nexusv1.DispatchStreamFrameV1{
		StreamNonce: bytes.Repeat([]byte{7}, 32),
		Message:     &nexusv1.DispatchStreamFrameV1_Keepalive{Keepalive: &nexusv1.StreamKeepaliveV1{SentAtMs: 1}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	var prefix [5]byte
	binary.BigEndian.PutUint32(prefix[1:], uint32(len(frame)))
	body.Write(prefix[:])
	body.Write(frame)
	request := httptest.NewRequest(http.MethodPost, nexusv1connect.IngressAPIDispatchStreamProcedure, &body)
	request.ProtoMajor, request.ProtoMinor = 2, 0
	request.Header.Set("Content-Type", "application/connect+proto")
	recorder := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	before := time.Now()
	s.handler().ServeHTTP(recorder, request)
	after := time.Now()

	events := strings.Join(recorder.events, " ")
	if !strings.HasSuffix(events, "set write clear write") {
		t.Fatalf("response events = %q, want the echoed frame written between set and clear, then the end of the call", events)
	}
	if len(recorder.deadlines) != 1 {
		t.Fatalf("deadlines = %v, want one per frame", recorder.deadlines)
	}
	if d := recorder.deadlines[0]; d.Before(before.Add(dispatchStreamWriteTimeout)) || d.After(after.Add(dispatchStreamWriteTimeout)) {
		t.Fatalf("deadline %v is not %s after the write", d, dispatchStreamWriteTimeout)
	}
}
