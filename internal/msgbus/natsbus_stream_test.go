package msgbus

import (
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/nats-io/nats.go"

	"github.com/TrueOpen/nexus/internal/config"
)

// streamJS records the stream configs ensureStreams sends. existing is the stream already on the
// server (nil = none, so AddStream succeeds).
type streamJS struct {
	nats.JetStreamContext
	existing *nats.StreamConfig
	added    []nats.StreamConfig
	updated  []nats.StreamConfig
}

func (j *streamJS) AddStream(cfg *nats.StreamConfig, _ ...nats.JSOpt) (*nats.StreamInfo, error) {
	j.added = append(j.added, *cfg)
	if j.existing != nil {
		return nil, errors.New("stream name already in use with a different configuration")
	}
	return &nats.StreamInfo{Config: *cfg}, nil
}

func (j *streamJS) StreamInfo(string, ...nats.JSOpt) (*nats.StreamInfo, error) {
	if j.existing == nil {
		return nil, nats.ErrStreamNotFound
	}
	return &nats.StreamInfo{Config: *j.existing}, nil
}

func (j *streamJS) UpdateStream(cfg *nats.StreamConfig, _ ...nats.JSOpt) (*nats.StreamInfo, error) {
	j.updated = append(j.updated, *cfg)
	return &nats.StreamInfo{Config: *cfg}, nil
}

func ensureWith(t *testing.T, replicas int, existing *nats.StreamConfig) *streamJS {
	t.Helper()
	js := &streamJS{existing: existing}
	bus := &natsBus{log: slog.New(slog.NewTextHandler(io.Discard, nil)), cfg: config.NATSConfig{StreamReplicas: replicas}, js: js}
	bus.ensureStreams()
	return js
}

// A new stream is created with nats.stream_replicas copies (1 when unset).
func TestEnsureStreamsCreatesWithConfiguredReplicas(t *testing.T) {
	for _, tt := range []struct{ configured, want int }{{0, 1}, {1, 1}, {3, 3}} {
		js := ensureWith(t, tt.configured, nil)
		if len(js.added) != 1 || js.added[0].Replicas != tt.want || len(js.updated) != 0 {
			t.Fatalf("configured %d: added=%+v updated=%d", tt.configured, js.added, len(js.updated))
		}
	}
}

// An update never lowers the replica count of an existing stream, and raises it when configured.
func TestEnsureStreamsNeverLowersReplicas(t *testing.T) {
	for _, tt := range []struct{ existing, configured, want int }{
		{existing: 3, configured: 0, want: 3},
		{existing: 3, configured: 1, want: 3},
		{existing: 1, configured: 3, want: 3},
		{existing: 3, configured: 5, want: 5},
	} {
		js := ensureWith(t, tt.configured, &nats.StreamConfig{Name: jsStreamName, Replicas: tt.existing})
		if len(js.updated) != 1 || js.updated[0].Replicas != tt.want {
			t.Fatalf("existing %d configured %d: updated=%+v", tt.existing, tt.configured, js.updated)
		}
	}
}
