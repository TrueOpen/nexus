package chaincli

import (
	"bytes"
	"context"
	"fmt"

	"connectrpc.com/connect"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/nodecontract"
)

// The dispatch record, claim, challenge and ineligibility rows come back as the wire state
// messages: evidence, rebuttals and challenge responses feed their fields to the wire dispatch
// package byte for byte, and a local copy of every field would only add a second shape to keep
// in step. Each answer is checked against the key it was asked for. ErrNotFound means the chain
// returned no row; it does not mean a task was never recorded, since records are pruned once
// their retention ends.

// QueryDispatchRecordByOrder reads the dispatch record the chain admitted for one session order
// (task.v1.Query/DispatchRecord by_order).
func (c *client) QueryDispatchRecordByOrder(ctx context.Context, sessionID string, orderSequence uint64) (*taskv1.DispatchRecordState, error) {
	id, err := nodecontract.Hash32Bytes("session_id", sessionID)
	if err != nil {
		return nil, fmt.Errorf("query dispatch record: %w", err)
	}
	if orderSequence == 0 {
		return nil, fmt.Errorf("query dispatch record: order_sequence must be greater than zero")
	}
	return c.queryDispatchRecord(ctx, &taskv1.QueryDispatchRecordRequest{
		Selector: &taskv1.QueryDispatchRecordRequest_ByOrder{ByOrder: &taskv1.DispatchRecordByOrderV1{
			SessionId: id, OrderSequence: orderSequence,
		}},
	}, nil)
}

// QueryDispatchRecordByHash reads one dispatch record by dispatch_record_hash.
func (c *client) QueryDispatchRecordByHash(ctx context.Context, recordHash []byte) (*taskv1.DispatchRecordState, error) {
	if err := checkHash32("dispatch_record_hash", recordHash); err != nil {
		return nil, fmt.Errorf("query dispatch record: %w", err)
	}
	return c.queryDispatchRecord(ctx, &taskv1.QueryDispatchRecordRequest{
		Selector: &taskv1.QueryDispatchRecordRequest_DispatchRecordHash{DispatchRecordHash: recordHash},
	}, recordHash)
}

func (c *client) queryDispatchRecord(ctx context.Context, request *taskv1.QueryDispatchRecordRequest, recordHash []byte) (*taskv1.DispatchRecordState, error) {
	resp, err := c.taskQuery.DispatchRecord(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, applicationQueryError("dispatch record", err)
	}
	record := resp.Msg.GetRecord()
	if record == nil || len(record.GetDispatchRecordHash()) == 0 {
		return nil, fmt.Errorf("query dispatch record: %w", ErrNotFound)
	}
	if len(record.GetTaskId()) != 32 || len(record.GetDispatchRecordHash()) != 32 || len(record.GetDispatchTicketHash()) != 32 {
		return nil, fmt.Errorf("query dispatch record: task_id, dispatch_record_hash and dispatch_ticket_hash must be 32 bytes")
	}
	if recordHash != nil && !bytes.Equal(record.GetDispatchRecordHash(), recordHash) {
		return nil, fmt.Errorf("query dispatch record: response record does not match request")
	}
	return record, nil
}

// QueryDispatchCompensationClaim reads the compensation claim keyed by a dispatch ticket hash.
func (c *client) QueryDispatchCompensationClaim(ctx context.Context, ticketHash []byte) (*taskv1.DispatchCompensationClaimState, error) {
	if err := checkHash32("dispatch_ticket_hash", ticketHash); err != nil {
		return nil, fmt.Errorf("query dispatch compensation claim: %w", err)
	}
	resp, err := c.taskQuery.DispatchCompensationClaim(ctx, connect.NewRequest(&taskv1.QueryDispatchCompensationClaimRequest{
		DispatchTicketHash: ticketHash,
	}))
	if err != nil {
		return nil, applicationQueryError("dispatch compensation claim", err)
	}
	claim := resp.Msg.GetClaim()
	if claim == nil || len(claim.GetDispatchTicketHash()) == 0 {
		return nil, fmt.Errorf("query dispatch compensation claim: %w", ErrNotFound)
	}
	if !bytes.Equal(claim.GetDispatchTicketHash(), ticketHash) {
		return nil, fmt.Errorf("query dispatch compensation claim: response ticket does not match request")
	}
	return claim, nil
}

// QueryDispatchWinnerIneligible reads the marker that excludes a ticket's failure from
// compensation because the winner itself was ineligible.
func (c *client) QueryDispatchWinnerIneligible(ctx context.Context, ticketHash []byte) (*taskv1.DispatchWinnerIneligibleState, error) {
	if err := checkHash32("dispatch_ticket_hash", ticketHash); err != nil {
		return nil, fmt.Errorf("query dispatch winner ineligible: %w", err)
	}
	resp, err := c.taskQuery.DispatchWinnerIneligible(ctx, connect.NewRequest(&taskv1.QueryDispatchWinnerIneligibleRequest{
		DispatchTicketHash: ticketHash,
	}))
	if err != nil {
		return nil, applicationQueryError("dispatch winner ineligible", err)
	}
	row := resp.Msg.GetRow()
	if row == nil || len(row.GetDispatchTicketHash()) == 0 {
		return nil, fmt.Errorf("query dispatch winner ineligible: %w", ErrNotFound)
	}
	if !bytes.Equal(row.GetDispatchTicketHash(), ticketHash) {
		return nil, fmt.Errorf("query dispatch winner ineligible: response ticket does not match request")
	}
	return row, nil
}

// QueryDispatchChallenge reads one dispatch challenge by challenge_id.
func (c *client) QueryDispatchChallenge(ctx context.Context, challengeID []byte) (*taskv1.DispatchChallengeState, error) {
	if err := checkHash32("challenge_id", challengeID); err != nil {
		return nil, fmt.Errorf("query dispatch challenge: %w", err)
	}
	resp, err := c.taskQuery.DispatchChallenge(ctx, connect.NewRequest(&taskv1.QueryDispatchChallengeRequest{ChallengeId: challengeID}))
	if err != nil {
		return nil, applicationQueryError("dispatch challenge", err)
	}
	row := resp.Msg.GetRow()
	if row == nil || len(row.GetChallengeId()) == 0 {
		return nil, fmt.Errorf("query dispatch challenge: %w", ErrNotFound)
	}
	if !bytes.Equal(row.GetChallengeId(), challengeID) {
		return nil, fmt.Errorf("query dispatch challenge: response challenge does not match request")
	}
	return row, nil
}

// QueryDispatchParams reads task params dispatch: record deadline, skip and sticky limits, record
// size bounds, compensation and challenge windows, the compensation account floor. Like the other
// params reads it asks the chain on every call. A zero record_deadline_blocks or
// max_dispatch_entries_per_record is refused: no record could ever be admitted.
func (c *client) QueryDispatchParams(ctx context.Context) (*taskv1.DispatchParamsV1, error) {
	resp, err := c.taskQuery.Params(ctx, connect.NewRequest(&taskv1.QueryTaskParamsRequest{}))
	if err != nil {
		return nil, applicationQueryError("task params", err)
	}
	params := resp.Msg.GetParams().GetDispatch()
	switch {
	case params == nil:
		return nil, fmt.Errorf("query task params: dispatch is missing")
	case params.GetRecordDeadlineBlocks() == 0:
		return nil, fmt.Errorf("query task params: dispatch.record_deadline_blocks is zero")
	case params.GetMaxDispatchEntriesPerRecord() == 0:
		return nil, fmt.Errorf("query task params: dispatch.max_dispatch_entries_per_record is zero")
	}
	return params, nil
}

// QueryCandidateWeightParams reads task params weights, which bound the weighted draw. A zero
// max_weighted_draw_attempts_per_selection is refused: no draw could complete.
func (c *client) QueryCandidateWeightParams(ctx context.Context) (*taskv1.CandidateWeightParamsV1, error) {
	resp, err := c.taskQuery.Params(ctx, connect.NewRequest(&taskv1.QueryTaskParamsRequest{}))
	if err != nil {
		return nil, applicationQueryError("task params", err)
	}
	weights := resp.Msg.GetParams().GetWeights()
	switch {
	case weights == nil:
		return nil, fmt.Errorf("query task params: weights is missing")
	case weights.GetMaxWeightedDrawAttemptsPerSelection() == 0:
		return nil, fmt.Errorf("query task params: weights.max_weighted_draw_attempts_per_selection is zero")
	}
	return weights, nil
}

func checkHash32(field string, value []byte) error {
	if len(value) != 32 {
		return fmt.Errorf("%s is %d bytes, want 32", field, len(value))
	}
	return nil
}

// The stub has no chain to ask; ErrNotFound for rows, ErrNotSupportedOnChain for params, so
// callers fail closed.

func (c *stubClient) QueryCandidateWeightParams(context.Context) (*taskv1.CandidateWeightParamsV1, error) {
	return nil, ErrNotSupportedOnChain
}

func (c *stubClient) QueryDispatchRecordByOrder(context.Context, string, uint64) (*taskv1.DispatchRecordState, error) {
	return nil, ErrNotFound
}

func (c *stubClient) QueryDispatchRecordByHash(context.Context, []byte) (*taskv1.DispatchRecordState, error) {
	return nil, ErrNotFound
}

func (c *stubClient) QueryDispatchCompensationClaim(context.Context, []byte) (*taskv1.DispatchCompensationClaimState, error) {
	return nil, ErrNotFound
}

func (c *stubClient) QueryDispatchWinnerIneligible(context.Context, []byte) (*taskv1.DispatchWinnerIneligibleState, error) {
	return nil, ErrNotFound
}

func (c *stubClient) QueryDispatchChallenge(context.Context, []byte) (*taskv1.DispatchChallengeState, error) {
	return nil, ErrNotFound
}

func (c *stubClient) QueryDispatchParams(context.Context) (*taskv1.DispatchParamsV1, error) {
	return nil, ErrNotSupportedOnChain
}
