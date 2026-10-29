package taskdata

import (
	"bytes"
	"context"
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
