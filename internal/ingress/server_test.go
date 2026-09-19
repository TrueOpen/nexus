package ingress

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/nexus/v1/nexusv1connect"
	"github.com/TrueOpen/nexus/internal/config"
)

func TestStartReturnsListenError(t *testing.T) {
	s := &Server{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg: config.IngressConfig{ListenAddr: "localhost:0"},
		h:   &fakeHandler{},
		listen: func(string, string) (net.Listener, error) {
			return nil, errors.New("bind failed")
		},
	}

	err := s.Start(context.Background())
	if err == nil {
		t.Fatal("expected listen error")
	}
	if !strings.Contains(err.Error(), "bind failed") {
		t.Fatalf("error = %v, want bind failure", err)
	}
}

func TestServerExposesBuilderDescriptor(t *testing.T) {
	body := []byte(`{"schema_version":"trueopen-builder-descriptor-v1"}`)
	s, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		config.IngressConfig{},
		AuthParams{},
		&fakeHandler{},
		WithBuilderDescriptor(body),
	)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/.well-known/trueopen-builder.json", nil))
	if rr.Code != http.StatusOK || !bytes.Equal(rr.Body.Bytes(), body) {
		t.Fatalf("response code=%d body=%q", rr.Code, rr.Body.Bytes())
	}
}

func TestServerRejectsOversizedPayloadBeforeService(t *testing.T) {
	fake := &fakeHandler{}
	s, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		config.IngressConfig{}, AuthParams{}, fake,
		WithPayloadMaxBytes(32),
	)
	if err != nil {
		t.Fatal(err)
	}
	client := nexusv1connect.NewIngressAPIClient(
		&http.Client{Transport: handlerRoundTripper{h: s.handler()}}, "http://ingress.test",
	)
	_, err = client.SubmitOrder(context.Background(), connect.NewRequest(&nexusv1.SubmitOrderRequest{
		Payload: bytes.Repeat([]byte("x"), s.readMaxBytes+1),
	}))
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("oversized request code = %v, want ResourceExhausted: %v", connect.CodeOf(err), err)
	}
	if fake.lastOrder.TaskID != "" {
		t.Fatalf("oversized request reached service: %+v", fake.lastOrder)
	}
}

func TestServerCapsRawHTTPBody(t *testing.T) {
	s, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		config.IngressConfig{}, AuthParams{}, &fakeHandler{},
		WithPayloadMaxBytes(32),
	)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(s.handler())
	t.Cleanup(server.Close)
	req, err := http.NewRequest(
		http.MethodPost,
		server.URL+nexusv1connect.IngressAPISubmitOrderProcedure,
		bytes.NewReader(bytes.Repeat([]byte("x"), int(s.httpMaxBytes)+1)),
	)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusTooManyRequests || !bytes.Contains(body, []byte(`"code":"resource_exhausted"`)) {
		t.Fatalf("oversized HTTP status = %d body=%q, want 429/resource_exhausted", response.StatusCode, body)
	}
}

func TestReadMaxUsesTaskDataChunkSizeAndStreamsAreNotTotalBodyCapped(t *testing.T) {
	s, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		config.IngressConfig{}, AuthParams{}, &fakeHandler{},
		WithReadMaxBytes(256<<10),
	)
	if err != nil {
		t.Fatal(err)
	}
	if s.taskDataReadMaxBytes != 256<<10+payloadMessageOverheadBytes {
		t.Fatalf("read max = %d", s.taskDataReadMaxBytes)
	}
	request := httptest.NewRequest(
		http.MethodPost, nexusv1connect.IngressAPIOpenTaskProcedure,
		bytes.NewReader(bytes.Repeat([]byte("x"), int(s.httpMaxBytes)+1)),
	)
	request.Header.Set("Content-Type", "application/proto")
	recorder := httptest.NewRecorder()
	s.handler().ServeHTTP(recorder, request)
	if recorder.Code == http.StatusTooManyRequests {
		t.Fatal("client-streaming OpenTask was capped by total HTTP body size")
	}
}
