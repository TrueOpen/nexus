package ingress

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"connectrpc.com/connect"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/internal/taskdata"
)

// OpenTask hands the order's order_expire_height to request authorization, and an expired order
// is refused before anything is stored, with the client's remaining chunks drained.
func TestOpenTaskRefusesExpiredOrder(t *testing.T) {
	user := mustSigner(t, testKeyHex)
	api := &fakeTaskDataAPI{chunkSize: 4,
		openTaskErr: fmt.Errorf("%w: height 501 is past order_expire_height 500", taskdata.ErrOrderExpired)}
	handler := &fakeHandler{}
	client := newTaskDataClientWithHandler(t, handler, api, AuthParams{Chain: testUserChain,
		EVMChainID: testEVMChainID, ChainID: "trueopen-localnet", Bech32Prefix: "trueopen"})
	input := []byte(strings.Repeat("abcd", 64))
	header := openTaskHeader(t, user, testSessionID("session-expired-order"), 6, input)
	stream := client.OpenTask(context.Background())
	if err := stream.Send(&nexusv1.OpenTaskRequest{Frame: &nexusv1.OpenTaskRequest_Header{Header: header}}); err != nil {
		t.Fatal(err)
	}
	for offset := 0; offset < len(input); offset += 4 {
		_ = stream.Send(&nexusv1.OpenTaskRequest{Frame: &nexusv1.OpenTaskRequest_Chunk{Chunk: input[offset : offset+4]}})
	}
	_, err := stream.CloseAndReceive()
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.HasPrefix(connectMessage(err), "NEXUS_INGRESS_ORDER_EXPIRED:") {
		t.Fatalf("OpenTask error=%v code=%v, want FailedPrecondition NEXUS_INGRESS_ORDER_EXPIRED", err, connect.CodeOf(err))
	}
	// The header validation requires a non-zero order_expire_height, so zero means it was not passed.
	if api.orderExpiry == 0 {
		t.Fatal("order_expire_height was not passed to request authorization")
	}
	if api.inputUpload != nil || handler.lastOrder.TaskID != "" {
		t.Fatal("an expired order reached storage or the coordinator")
	}
}
