package ingress

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/nexus/v1/nexusv1connect"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/inflight"
	"github.com/TrueOpen/nexus/internal/opsmetrics"
)

// A route added with WithRoute is plain HTTP on the ingress port: the API key that guards the
// Connect API does not apply to it. These tests open no listener.
func TestRoutesAreServedOutsideTheAPIKey(t *testing.T) {
	s, err := New(slog.New(slog.NewTextHandler(io.Discard, nil)), config.IngressConfig{APIKeys: []string{"secret"}},
		AuthParams{Chain: testUserChain}, &fakeHandler{},
		WithRoute("GET /readyz", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ready")) })))
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusOK || rr.Body.String() != "ready" {
		t.Fatalf("readyz: %d %q", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	s.handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/readyz", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST readyz: %d", rr.Code)
	}
}

// The precheck an OpenTask ran is timed into the metrics.
func TestOpenTaskTimesThePrecheck(t *testing.T) {
	h := newRegisteredKeyHeader(t)
	h.signEnvelopeWithWallet(t)
	auth := h.svc.auth
	auth.Precheck = &fakePrechecker{result: inflight.Result{Existing: &inflight.Entry{Sequence: 7, State: inflight.StateAccepted}}}
	metrics := opsmetrics.New()
	mux := http.NewServeMux()
	path, connectHandler := nexusv1connect.NewIngressAPIHandler(newService(&fakeHandler{}, auth,
		withTaskDataAPI(&fakeTaskDataAPI{chunkSize: 4096}), withServiceMetrics(metrics)))
	mux.Handle(path, connectHandler)
	client := nexusv1connect.NewIngressAPIClient(&http.Client{Transport: handlerRoundTripper{h: mux}}, "http://task-data.test")
	stream := client.OpenTask(context.Background())
	if err := stream.Send(&nexusv1.OpenTaskRequest{Frame: &nexusv1.OpenTaskRequest_Header{Header: h.header}}); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.CloseAndReceive(); err != nil {
		t.Fatalf("OpenTask: %v", err)
	}
	if got := metrics.Snapshot().Stages[opsmetrics.StagePrecheck].Count; got != 1 {
		t.Fatalf("precheck timed %d times", got)
	}
}
