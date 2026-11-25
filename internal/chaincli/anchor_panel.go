package chaincli

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/nodecontract"
)

// AnchorAuditModePanel is VerificationParamsV1.anchor_audit_mode 2: a selected anchor audit is
// decided by a panel of Verifiers drawn through the ordinary Verifier window.
const AnchorAuditModePanel = 2

// AnchorPanel is what a Builder needs from a task's anchor audit row to collect hand-raises for a
// Verifier panel: whether the task is audited by a panel at all, and the latest panel round.
type AnchorPanel struct {
	// AuditMode is anchor_audit_mode as frozen into the task; only AnchorAuditModePanel has rounds.
	AuditMode uint32
	// Round is the latest panel round opened for the task; zero when none is. It is the verify-round
	// number a hand-raise of that round carries: 2 for the first panel of a task whose round 1
	// selected nobody, and one more for every later round (retry, re-audit, late attempt).
	Round uint32
	// Kind is AnchorPanelRoundKindV1 of that round (initial, retry, re-audit).
	Kind uint32
	// OpenHeight is the height the round's Verifier window was opened at.
	OpenHeight uint64
	// Collecting is true while the round is open and its members are not drawn yet: the only time
	// a hand-raise for it is of use.
	Collecting bool
	// PriorMembers are the operators drawn in earlier rounds of the task. The chain does not draw
	// them again, so a Builder does not propose them.
	PriorMembers []string
}

// AnchorPanelQuerier reads a task's panel state.
type AnchorPanelQuerier interface {
	QueryAnchorPanel(ctx context.Context, taskID string) (AnchorPanel, error)
}

// ErrAnchorPanelUnsupported is a chain that does not serve the anchor audit query.
var ErrAnchorPanelUnsupported = errors.New("the chain does not serve the anchor audit query")

// QueryAnchorPanel reads the anchor audit row of a task (task.v1.Query/AnchorAudit) and reduces it
// to its panel state. A task without an audit row returns ErrNotFound.
func (c *client) QueryAnchorPanel(ctx context.Context, taskID string) (AnchorPanel, error) {
	id, err := nodecontract.Hash32Bytes("task_id", taskID)
	if err != nil {
		return AnchorPanel{}, fmt.Errorf("query anchor panel task=%q: task_id is required and canonical", taskID)
	}
	resp, err := c.taskQuery.AnchorAudit(ctx, connect.NewRequest(&taskv1.QueryAnchorAuditRequest{TaskId: id}))
	if err != nil {
		if connect.CodeOf(err) == connect.CodeUnimplemented {
			return AnchorPanel{}, ErrAnchorPanelUnsupported
		}
		return AnchorPanel{}, applicationQueryError("anchor audit", err)
	}
	audit := resp.Msg.GetAudit()
	if audit == nil || len(audit.GetTaskId()) == 0 {
		return AnchorPanel{}, ErrNotFound
	}
	if !bytes.Equal(audit.GetTaskId(), id) {
		return AnchorPanel{}, fmt.Errorf("query anchor panel: response key does not match request")
	}
	return anchorPanelOf(audit), nil
}

func anchorPanelOf(audit *taskv1.AnchorAuditState) AnchorPanel {
	panel := AnchorPanel{AuditMode: audit.GetAuditMode(), Round: audit.GetPanelRound()}
	if panel.AuditMode != AnchorAuditModePanel || panel.Round == 0 {
		return AnchorPanel{AuditMode: panel.AuditMode}
	}
	seen := map[string]bool{}
	for _, round := range audit.GetPanelRounds() {
		if round.GetPanelRound() == panel.Round {
			panel.Kind = uint32(round.GetKind())
			panel.OpenHeight = round.GetOpenHeight()
			panel.Collecting = round.GetAssignmentHeight() == 0 && round.GetClosedHeight() == 0 &&
				round.GetResult() == taskv1.AnchorVerdictV1_ANCHOR_VERDICT_V1_UNSPECIFIED
			continue
		}
		for _, member := range round.GetMembers() {
			if member != "" && !seen[member] {
				seen[member] = true
				panel.PriorMembers = append(panel.PriorMembers, member)
			}
		}
	}
	return panel
}
