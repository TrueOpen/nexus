package taskdata

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/TrueOpen/nexus/internal/mmr"
	"github.com/TrueOpen/nexus/internal/nodecontract"
)

// A group member writes the output replica of a recorded winner through a stream bound to the
// winner's ticket: it resumes from its progress, and the frames replay with that ticket.
func TestReplicaStreamIsBoundToTheWinnerTicket(t *testing.T) {
	store, _, _ := newTestStore(t, streamStoreConfig())
	key := streamKey(testTaskID)
	ticket := bytes.Repeat([]byte{0x31}, 32)
	stream, progress, err := store.OpenReplicaStream(context.Background(), key, "worker-1", testStreamConfig(), ticket)
	if err != nil || progress.Received {
		t.Fatalf("open = %+v, %v", progress, err)
	}
	acc, _ := mmr.New(nodecontract.DomainOutputMMRV1)
	chunk := chunkFor(acc, 0, "hello, ")
	chunk.DispatchTicketHash = ticket
	if _, err := stream.Append(context.Background(), chunk); err != nil {
		t.Fatal(err)
	}
	stream.Close()
	stream, progress, err = store.OpenReplicaStream(context.Background(), key, "worker-1", testStreamConfig(), ticket)
	if err != nil || !progress.Received || progress.LastSeq != 0 {
		t.Fatalf("resume = %+v, %v", progress, err)
	}
	root := acc.Root()
	if _, err := stream.Finish(context.Background(), OutputFin{FinalSeq: 0, OutputMMRRoot: root[:], FinishReason: 1, DispatchTicketHash: ticket}); err != nil {
		t.Fatal(err)
	}
	frames, err := store.OutputFrames(context.Background(), key, nil)
	if err != nil || len(frames) != 2 || frames[1].Fin == nil || !bytes.Equal(frames[0].Chunk.DispatchTicketHash, ticket) {
		t.Fatalf("frames = %+v, %v", frames, err)
	}
	if _, _, err := store.OpenReplicaStream(context.Background(), key, "worker-1", testStreamConfig(), nil); err == nil {
		t.Fatal("a replica stream without a ticket was opened")
	}
}

// OutputFramesUpTo stops once the text read reaches maxBytes (always returning at least one
// chunk), and appends the Fin only when every chunk after afterSeq fits.
func TestOutputFramesUpToStopsAtMaxBytes(t *testing.T) {
	store, _, _ := newTestStore(t, streamStoreConfig())
	key := streamKey(testTaskID)
	ticket := bytes.Repeat([]byte{0x31}, 32)
	stream, _, err := store.OpenReplicaStream(context.Background(), key, "worker-1", testStreamConfig(), ticket)
	if err != nil {
		t.Fatal(err)
	}
	acc, _ := mmr.New(nodecontract.DomainOutputMMRV1)
	for i, text := range []string{"aaaa", "bbbb", "cccc"} {
		chunk := chunkFor(acc, uint64(i), text)
		chunk.DispatchTicketHash = ticket
		if _, err := stream.Append(context.Background(), chunk); err != nil {
			t.Fatal(err)
		}
	}
	root := acc.Root()
	if _, err := stream.Finish(context.Background(), OutputFin{FinalSeq: 2, OutputMMRRoot: root[:], FinishReason: 1, DispatchTicketHash: ticket}); err != nil {
		t.Fatal(err)
	}
	seqs := func(frames []OutputFrame) (out []int) {
		for _, f := range frames {
			if f.Chunk != nil {
				out = append(out, int(f.Chunk.Seq))
			} else {
				out = append(out, -1) // Fin
			}
		}
		return out
	}
	zero := uint64(0)
	for _, tc := range []struct {
		after *uint64
		max   int
		want  []int
	}{
		{nil, 8, []int{0, 1}},
		{nil, 9, []int{0, 1}},
		{nil, 1, []int{0}},
		{nil, 12, []int{0, 1, 2, -1}},
		{&zero, 8, []int{1, 2, -1}},
		{&zero, 4, []int{1}},
	} {
		frames, err := store.OutputFramesUpTo(context.Background(), key, tc.after, tc.max)
		if err != nil || fmt.Sprint(seqs(frames)) != fmt.Sprint(tc.want) {
			t.Fatalf("after %v max %d: frames %v, %v; want %v", tc.after, tc.max, seqs(frames), err, tc.want)
		}
	}
}
