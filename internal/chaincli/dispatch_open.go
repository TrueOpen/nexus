package chaincli

import (
	"bytes"
	"context"
	"fmt"

	"connectrpc.com/connect"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

// maxOpenDispatchItemPages bounds one walk of a Builder's open challenges or claims; the chain caps
// every page, so a walk longer than this is a page token that never ends.
const maxOpenDispatchItemPages = 4096

// The open challenges and claims against a Builder are what it must still answer. Both queries
// walk the Builder's open index only, page by page under a token that pins every page to the
// height the first page read, so a walk returns the open items of one height. They recover what an
// event stream gap of any length may have missed.

// QueryDispatchChallengesByBuilder reads one page of the challenges against builder that await a
// proof or a roster (task.v1.Query/DispatchChallengesByBuilder), in ascending challenge_id order,
// and the token of the next page (empty after the last).
func (c *client) QueryDispatchChallengesByBuilder(ctx context.Context, builder string, pageToken []byte) ([]*taskv1.DispatchChallengeState, []byte, error) {
	if builder == "" {
		return nil, nil, fmt.Errorf("query dispatch challenges by builder: builder address is required")
	}
	resp, err := c.taskQuery.DispatchChallengesByBuilder(ctx, connect.NewRequest(&taskv1.QueryDispatchChallengesByBuilderRequest{
		BuilderAddress: builder, Page: &sharedv1.QueryPageRequestV1{PageToken: pageToken},
	}))
	if err != nil {
		return nil, nil, applicationQueryError("dispatch challenges by builder", err)
	}
	rows := resp.Msg.GetRows()
	for i, row := range rows {
		status := row.GetStatus()
		switch {
		case len(row.GetChallengeId()) != 32:
			return nil, nil, fmt.Errorf("query dispatch challenges by builder: row %d challenge_id is not 32 bytes", i)
		case row.GetBuilderAddress() != builder:
			return nil, nil, fmt.Errorf("query dispatch challenges by builder: row %d is against %q", i, row.GetBuilderAddress())
		case status != taskv1.DispatchChallengeStatusV1_DISPATCH_CHALLENGE_STATUS_V1_AWAITING_PROOF &&
			status != taskv1.DispatchChallengeStatusV1_DISPATCH_CHALLENGE_STATUS_V1_AWAITING_ROSTER:
			return nil, nil, fmt.Errorf("query dispatch challenges by builder: row %d is not open (%s)", i, status)
		case i > 0 && bytes.Compare(rows[i-1].GetChallengeId(), row.GetChallengeId()) >= 0:
			return nil, nil, fmt.Errorf("query dispatch challenges by builder: challenge ids are not strictly ascending")
		}
	}
	return rows, bytes.Clone(resp.Msg.GetPage().GetNextPageToken()), nil
}

// QueryDispatchCompensationClaimsByBuilder reads one page of the claims on builder's tickets that
// await its rebuttal (task.v1.Query/DispatchCompensationClaimsByBuilder), in ascending ticket hash
// order, and the token of the next page (empty after the last).
func (c *client) QueryDispatchCompensationClaimsByBuilder(ctx context.Context, builder string, pageToken []byte) ([]*taskv1.DispatchCompensationClaimState, []byte, error) {
	if builder == "" {
		return nil, nil, fmt.Errorf("query dispatch compensation claims by builder: builder address is required")
	}
	resp, err := c.taskQuery.DispatchCompensationClaimsByBuilder(ctx, connect.NewRequest(&taskv1.QueryDispatchCompensationClaimsByBuilderRequest{
		BuilderAddress: builder, Page: &sharedv1.QueryPageRequestV1{PageToken: pageToken},
	}))
	if err != nil {
		return nil, nil, applicationQueryError("dispatch compensation claims by builder", err)
	}
	claims := resp.Msg.GetClaims()
	for i, claim := range claims {
		switch {
		case len(claim.GetDispatchTicketHash()) != 32:
			return nil, nil, fmt.Errorf("query dispatch compensation claims by builder: claim %d ticket hash is not 32 bytes", i)
		case claim.GetBuilderAddress() != builder:
			return nil, nil, fmt.Errorf("query dispatch compensation claims by builder: claim %d is on %q", i, claim.GetBuilderAddress())
		case claim.GetStatus() != taskv1.DispatchCompensationClaimStatusV1_DISPATCH_COMPENSATION_CLAIM_STATUS_V1_PENDING_REBUTTAL:
			return nil, nil, fmt.Errorf("query dispatch compensation claims by builder: claim %d is not pending (%s)", i, claim.GetStatus())
		case i > 0 && bytes.Compare(claims[i-1].GetDispatchTicketHash(), claim.GetDispatchTicketHash()) >= 0:
			return nil, nil, fmt.Errorf("query dispatch compensation claims by builder: ticket hashes are not strictly ascending")
		}
	}
	return claims, bytes.Clone(resp.Msg.GetPage().GetNextPageToken()), nil
}

// OpenDispatchItemPager is the paged reads ListOpenDispatchChallenges and
// ListOpenDispatchCompensationClaims walk.
type OpenDispatchItemPager interface {
	QueryDispatchChallengesByBuilder(ctx context.Context, builder string, pageToken []byte) ([]*taskv1.DispatchChallengeState, []byte, error)
	QueryDispatchCompensationClaimsByBuilder(ctx context.Context, builder string, pageToken []byte) ([]*taskv1.DispatchCompensationClaimState, []byte, error)
}

// ListOpenDispatchChallenges walks every page of the open challenges against builder.
func ListOpenDispatchChallenges(ctx context.Context, q OpenDispatchItemPager, builder string) ([]*taskv1.DispatchChallengeState, error) {
	return walkKeyedPages("dispatch challenges by builder", func(token []byte) ([]*taskv1.DispatchChallengeState, []byte, error) {
		return q.QueryDispatchChallengesByBuilder(ctx, builder, token)
	}, (*taskv1.DispatchChallengeState).GetChallengeId)
}

// ListOpenDispatchCompensationClaims walks every page of the claims awaiting builder's rebuttal.
func ListOpenDispatchCompensationClaims(ctx context.Context, q OpenDispatchItemPager, builder string) ([]*taskv1.DispatchCompensationClaimState, error) {
	return walkKeyedPages("dispatch compensation claims by builder", func(token []byte) ([]*taskv1.DispatchCompensationClaimState, []byte, error) {
		return q.QueryDispatchCompensationClaimsByBuilder(ctx, builder, token)
	}, (*taskv1.DispatchCompensationClaimState).GetDispatchTicketHash)
}

// walkKeyedPages reads pages until the token is empty. A page that does not continue after the
// previous one's last key, or a token that does not advance, fails the walk: a partial list is
// never returned as the whole.
func walkKeyedPages[T any](kind string, page func(token []byte) ([]T, []byte, error), key func(T) []byte) ([]T, error) {
	var out []T
	var token []byte
	for n := 0; n < maxOpenDispatchItemPages; n++ {
		rows, next, err := page(token)
		if err != nil {
			return nil, err
		}
		if len(out) > 0 && len(rows) > 0 && bytes.Compare(key(rows[0]), key(out[len(out)-1])) <= 0 {
			return nil, fmt.Errorf("list %s: page %d does not continue after the previous page", kind, n)
		}
		out = append(out, rows...)
		if len(next) == 0 {
			return out, nil
		}
		if bytes.Equal(next, token) {
			return nil, fmt.Errorf("list %s: page token did not advance", kind)
		}
		token = next
	}
	return nil, fmt.Errorf("list %s: more than %d pages", kind, maxOpenDispatchItemPages)
}

// The stub has no chain to ask; ErrNotFound like its other row reads.

func (c *stubClient) QueryDispatchChallengesByBuilder(context.Context, string, []byte) ([]*taskv1.DispatchChallengeState, []byte, error) {
	return nil, nil, ErrNotFound
}

func (c *stubClient) QueryDispatchCompensationClaimsByBuilder(context.Context, string, []byte) ([]*taskv1.DispatchCompensationClaimState, []byte, error) {
	return nil, nil, ErrNotFound
}
