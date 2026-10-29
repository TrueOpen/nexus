package ingress

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/nexus/v1/nexusv1connect"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/dispatchstream"
)

// countingDispatchStream reads frames until the uplink ends and counts them.
type countingDispatchStream struct{ frames int }

func (c *countingDispatchStream) Serve(_ context.Context, stream dispatchstream.FrameStream) error {
	for {
		if _, err := stream.Receive(); err != nil {
			return err
		}
		c.frames++
	}
}

// TestDispatchStreamIsNotTotalBodyCapped: the request body of a dispatch stream is the whole uplink
// of a long-lived connection, so only the per-message limit may apply to it, never the cumulative
// HTTP body cap of unary RPCs.
func TestDispatchStreamIsNotTotalBodyCapped(t *testing.T) {
	hub := &countingDispatchStream{}
	s, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		config.IngressConfig{}, AuthParams{Chain: testUserChain}, &fakeHandler{},
		WithPayloadMaxBytes(32), WithDispatchStream(hub),
	)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := proto.Marshal(&nexusv1.DispatchStreamRequest{Frame: &nexusv1.DispatchStreamFrameV1{
		StreamNonce: bytes.Repeat([]byte{7}, 32), Cursor: 0,
		Message: &nexusv1.DispatchStreamFrameV1_Keepalive{Keepalive: &nexusv1.StreamKeepaliveV1{SentAtMs: 1}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	want := 0
	for int64(body.Len()) <= s.httpMaxBytes {
		var prefix [5]byte
		binary.BigEndian.PutUint32(prefix[1:], uint32(len(frame)))
		body.Write(prefix[:])
		body.Write(frame)
		want++
	}
	request := httptest.NewRequest(http.MethodPost, nexusv1connect.IngressAPIDispatchStreamProcedure, &body)
	request.ProtoMajor, request.ProtoMinor = 2, 0
	request.Header.Set("Content-Type", "application/connect+proto")
	recorder := httptest.NewRecorder()
	s.handler().ServeHTTP(recorder, request)
	if recorder.Code == http.StatusTooManyRequests || bytes.Contains(recorder.Body.Bytes(), []byte("resource_exhausted")) {
		t.Fatalf("dispatch stream was capped by total HTTP body size: status=%d body=%q", recorder.Code, recorder.Body.Bytes())
	}
	if hub.frames != want {
		t.Fatalf("hub read %d frames, want all %d", hub.frames, want)
	}
}
