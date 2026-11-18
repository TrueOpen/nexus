package chaincli

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/task/v1/taskv1connect"
)

// frozenParamsTaskQuery answers only task.v1.Query/TaskFrozenParams, in process: no server, no listener.
type frozenParamsTaskQuery struct {
	taskv1connect.QueryClient
	response *taskv1.QueryTaskFrozenParamsResponse
	err      error
	request  *taskv1.QueryTaskFrozenParamsRequest
	calls    int
}

func (q *frozenParamsTaskQuery) TaskFrozenParams(_ context.Context, req *connect.Request[taskv1.QueryTaskFrozenParamsRequest]) (*connect.Response[taskv1.QueryTaskFrozenParamsResponse], error) {
	q.calls++
	q.request = req.Msg
	if q.err != nil {
		return nil, q.err
	}
	return connect.NewResponse(q.response), nil
}

func frozenParamsWithRoundLimit(limit uint32) *taskv1.QueryTaskFrozenParamsResponse {
	return &taskv1.QueryTaskFrozenParamsResponse{
		Params:        &taskv1.TaskParamsV1{Challenge: &taskv1.ChallengeParamsV1{MaxVerifyRound: limit}},
		ParamsVersion: 3,
	}
}

func TestQueryTaskFrozenMaxVerifyRoundReadsTheTaskBinding(t *testing.T) {
	q := &frozenParamsTaskQuery{response: frozenParamsWithRoundLimit(2)}
	c := &client{taskQuery: q}
	got, err := c.QueryTaskMaxVerifyRound(context.Background(), testTaskIDHex)
	if err != nil || got != 2 {
		t.Fatalf("max verify round = %d, %v; want 2", got, err)
	}
	if q.request == nil || !bytes.Equal(q.request.GetTaskId(), testTaskIDBytes) {
		t.Fatalf("request = %+v; want the task id bytes", q.request)
	}
}

func TestQueryTaskFrozenMaxVerifyRoundRefusesZero(t *testing.T) {
	c := &client{taskQuery: &frozenParamsTaskQuery{response: frozenParamsWithRoundLimit(0)}}
	if _, err := c.QueryTaskMaxVerifyRound(context.Background(), testTaskIDHex); err == nil {
		t.Fatal("zero max_verify_round accepted")
	}
	c = &client{taskQuery: &frozenParamsTaskQuery{response: &taskv1.QueryTaskFrozenParamsResponse{}}}
	if _, err := c.QueryTaskMaxVerifyRound(context.Background(), testTaskIDHex); err == nil {
		t.Fatal("missing params accepted")
	}
}

func TestQueryTaskFrozenMaxVerifyRoundMapsChainErrors(t *testing.T) {
	c := &client{taskQuery: &frozenParamsTaskQuery{err: connect.NewError(connect.CodeNotFound, errors.New("task not found"))}}
	if _, err := c.QueryTaskMaxVerifyRound(context.Background(), testTaskIDHex); !errors.Is(err, ErrNotFound) {
		t.Fatalf("not found: err = %v; want ErrNotFound", err)
	}
	c = &client{taskQuery: &frozenParamsTaskQuery{err: connect.NewError(connect.CodeInternal, errors.New("binding missing"))}}
	_, err := c.QueryTaskMaxVerifyRound(context.Background(), testTaskIDHex)
	if err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("internal: err = %v; want a non-NotFound error", err)
	}
}

func TestQueryTaskFrozenMaxVerifyRoundRejectsMalformedTaskID(t *testing.T) {
	q := &frozenParamsTaskQuery{response: frozenParamsWithRoundLimit(2)}
	c := &client{taskQuery: q}
	if _, err := c.QueryTaskMaxVerifyRound(context.Background(), "not-a-task-id"); err == nil {
		t.Fatal("malformed task id accepted")
	}
	if q.calls != 0 {
		t.Fatal("malformed task id reached the chain")
	}
}
