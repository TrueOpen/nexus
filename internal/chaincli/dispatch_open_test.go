package chaincli

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/task/v1/taskv1connect"
)

const (
	openBuilder     = "trueopen1builder"
	awaitingProof   = taskv1.DispatchChallengeStatusV1_DISPATCH_CHALLENGE_STATUS_V1_AWAITING_PROOF
	awaitingRoster  = taskv1.DispatchChallengeStatusV1_DISPATCH_CHALLENGE_STATUS_V1_AWAITING_ROSTER
	pendingRebuttal = taskv1.DispatchCompensationClaimStatusV1_DISPATCH_COMPENSATION_CLAIM_STATUS_V1_PENDING_REBUTTAL
)

// openItemsQuery serves the open challenge and claim pages keyed by the page token asked for.
type openItemsQuery struct {
	taskv1connect.QueryClient
	err        error
	challenges map[string]*taskv1.QueryDispatchChallengesByBuilderResponse
	claims     map[string]*taskv1.QueryDispatchCompensationClaimsByBuilderResponse
	asked      []string // builder|token of every request
}

func (q *openItemsQuery) DispatchChallengesByBuilder(_ context.Context, req *connect.Request[taskv1.QueryDispatchChallengesByBuilderRequest]) (*connect.Response[taskv1.QueryDispatchChallengesByBuilderResponse], error) {
	q.asked = append(q.asked, req.Msg.GetBuilderAddress()+"|"+string(req.Msg.GetPage().GetPageToken()))
	if q.err != nil {
		return nil, q.err
	}
	resp, ok := q.challenges[string(req.Msg.GetPage().GetPageToken())]
	if !ok {
		return nil, errors.New("unknown page token")
	}
	return connect.NewResponse(resp), nil
}

func (q *openItemsQuery) DispatchCompensationClaimsByBuilder(_ context.Context, req *connect.Request[taskv1.QueryDispatchCompensationClaimsByBuilderRequest]) (*connect.Response[taskv1.QueryDispatchCompensationClaimsByBuilderResponse], error) {
	q.asked = append(q.asked, req.Msg.GetBuilderAddress()+"|"+string(req.Msg.GetPage().GetPageToken()))
	if q.err != nil {
		return nil, q.err
	}
	resp, ok := q.claims[string(req.Msg.GetPage().GetPageToken())]
	if !ok {
		return nil, errors.New("unknown page token")
	}
	return connect.NewResponse(resp), nil
}

func openChallenge(id string, status taskv1.DispatchChallengeStatusV1) *taskv1.DispatchChallengeState {
	return &taskv1.DispatchChallengeState{
		ChallengeId: mustHash32(id), TaskId: testTaskIDBytes, BuilderAddress: openBuilder, Status: status,
		Kind: sharedv1.DispatchChallengeKindV1_DISPATCH_CHALLENGE_KIND_V1_SKIP,
	}
}

func openClaim(ticket string) *taskv1.DispatchCompensationClaimState {
	return &taskv1.DispatchCompensationClaimState{
		DispatchTicketHash: mustHash32(ticket), TaskId: testTaskIDBytes, BuilderAddress: openBuilder, Status: pendingRebuttal,
		RebuttalDeadlineHeight: 300,
	}
}

func challengePage(next string, rows ...*taskv1.DispatchChallengeState) *taskv1.QueryDispatchChallengesByBuilderResponse {
	return &taskv1.QueryDispatchChallengesByBuilderResponse{Rows: rows, Page: &sharedv1.QueryPageResponseV1{NextPageToken: []byte(next)}}
}

func claimPage(next string, claims ...*taskv1.DispatchCompensationClaimState) *taskv1.QueryDispatchCompensationClaimsByBuilderResponse {
	return &taskv1.QueryDispatchCompensationClaimsByBuilderResponse{Claims: claims, Page: &sharedv1.QueryPageResponseV1{NextPageToken: []byte(next)}}
}

// Every page of a Builder's open challenges and claims is read, following the chain's page token
// (which pins the walk to one height), and the rows come back in key order.
func TestListOpenDispatchItemsWalksEveryPage(t *testing.T) {
	q := &openItemsQuery{
		challenges: map[string]*taskv1.QueryDispatchChallengesByBuilderResponse{
			"":   challengePage("p2", openChallenge("01", awaitingProof), openChallenge("02", awaitingRoster)),
			"p2": challengePage("", openChallenge("03", awaitingProof)),
		},
		claims: map[string]*taskv1.QueryDispatchCompensationClaimsByBuilderResponse{
			"":   claimPage("p2", openClaim("a1")),
			"p2": claimPage(""),
		},
	}
	c := &client{taskQuery: q}
	challenges, err := ListOpenDispatchChallenges(context.Background(), c, openBuilder)
	if err != nil || len(challenges) != 3 || !bytes.Equal(challenges[2].GetChallengeId(), mustHash32("03")) {
		t.Fatalf("challenges = %v, %v", challenges, err)
	}
	claims, err := ListOpenDispatchCompensationClaims(context.Background(), c, openBuilder)
	if err != nil || len(claims) != 1 || claims[0].GetRebuttalDeadlineHeight() != 300 {
		t.Fatalf("claims = %v, %v", claims, err)
	}
	want := []string{openBuilder + "|", openBuilder + "|p2", openBuilder + "|", openBuilder + "|p2"}
	if len(q.asked) != len(want) {
		t.Fatalf("asked %v, want %v", q.asked, want)
	}
	for i := range want {
		if q.asked[i] != want[i] {
			t.Fatalf("asked %v, want %v", q.asked, want)
		}
	}

	empty := &client{taskQuery: &openItemsQuery{
		challenges: map[string]*taskv1.QueryDispatchChallengesByBuilderResponse{"": challengePage("")},
		claims:     map[string]*taskv1.QueryDispatchCompensationClaimsByBuilderResponse{"": {}},
	}}
	if rows, err := ListOpenDispatchChallenges(context.Background(), empty, openBuilder); err != nil || len(rows) != 0 {
		t.Fatalf("no open challenges = %v, %v", rows, err)
	}
	if rows, err := ListOpenDispatchCompensationClaims(context.Background(), empty, openBuilder); err != nil || len(rows) != 0 {
		t.Fatalf("no open claims = %v, %v", rows, err)
	}
}

// A page that is not a Builder's open items in key order, or a walk that does not advance, fails
// the whole walk: a partial list is never taken as every open item.
func TestListOpenDispatchItemsRefusesInconsistentPages(t *testing.T) {
	challengeCases := map[string]map[string]*taskv1.QueryDispatchChallengesByBuilderResponse{
		"another Builder": {"": challengePage("", func() *taskv1.DispatchChallengeState {
			c := openChallenge("01", awaitingProof)
			c.BuilderAddress = "trueopen1other"
			return c
		}())},
		"resolved row":      {"": challengePage("", openChallenge("01", taskv1.DispatchChallengeStatusV1_DISPATCH_CHALLENGE_STATUS_V1_UPHELD))},
		"short id":          {"": challengePage("", &taskv1.DispatchChallengeState{ChallengeId: []byte{1}, BuilderAddress: openBuilder, Status: awaitingProof})},
		"not ascending":     {"": challengePage("", openChallenge("02", awaitingProof), openChallenge("01", awaitingProof))},
		"page goes back":    {"": challengePage("p2", openChallenge("02", awaitingProof)), "p2": challengePage("", openChallenge("01", awaitingProof))},
		"token not advance": {"": challengePage("p2", openChallenge("01", awaitingProof)), "p2": challengePage("p2")},
	}
	for name, pages := range challengeCases {
		c := &client{taskQuery: &openItemsQuery{challenges: pages}}
		if _, err := ListOpenDispatchChallenges(context.Background(), c, openBuilder); err == nil {
			t.Fatalf("challenges, %s: accepted", name)
		}
	}
	claimCases := map[string]map[string]*taskv1.QueryDispatchCompensationClaimsByBuilderResponse{
		"another Builder": {"": claimPage("", func() *taskv1.DispatchCompensationClaimState {
			c := openClaim("a1")
			c.BuilderAddress = "trueopen1other"
			return c
		}())},
		"paid claim": {"": claimPage("", func() *taskv1.DispatchCompensationClaimState {
			c := openClaim("a1")
			c.Status = taskv1.DispatchCompensationClaimStatusV1_DISPATCH_COMPENSATION_CLAIM_STATUS_V1_PAID
			return c
		}())},
		"not ascending": {"": claimPage("", openClaim("a2"), openClaim("a1"))},
	}
	for name, pages := range claimCases {
		c := &client{taskQuery: &openItemsQuery{claims: pages}}
		if _, err := ListOpenDispatchCompensationClaims(context.Background(), c, openBuilder); err == nil {
			t.Fatalf("claims, %s: accepted", name)
		}
	}
	failing := &client{taskQuery: &openItemsQuery{err: connect.NewError(connect.CodeUnavailable, errors.New("down"))}}
	if _, err := ListOpenDispatchChallenges(context.Background(), failing, openBuilder); err == nil {
		t.Fatal("a failed read was taken as no open challenge")
	}
	if _, _, err := failing.QueryDispatchChallengesByBuilder(context.Background(), "", nil); err == nil {
		t.Fatal("an empty Builder address was sent")
	}
}
