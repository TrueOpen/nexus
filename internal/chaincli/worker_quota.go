package chaincli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
)

// ErrWorkerQuotaUnsupported is the answer of a chain that does not serve hub.v1.Query/WorkerQuota
// (a node older than the Worker quota). Callers treat it as "no quota enforced".
var ErrWorkerQuotaUnsupported = errors.New("hub.v1.Query/WorkerQuota is not served by this chain")

// WorkerQuota is one Worker's order quota of the current settlement period and its pause state.
type WorkerQuota struct {
	Period        uint64
	Quota         uint64
	ReservedValue uint64
	SettledValue  uint64
	Remaining     uint64
	// Enforced is false while the network has not switched the quota on.
	Enforced bool
	// DispatchPaused is set while the Worker must not be offered orders; PauseReasons says why
	// (bit 1 late submission pending, 2 unbonding, 4 jailed).
	DispatchPaused bool
	PauseReasons   uint32
}

// WorkerQuotaReader is implemented by clients that can read a Worker's quota.
type WorkerQuotaReader interface {
	QueryWorkerQuota(ctx context.Context, operator string) (WorkerQuota, error)
}

// QueryWorkerQuota reads hub.v1.Query/WorkerQuota for the current period. A Worker without a quota
// row is answered by the chain with zero reserved value, not ErrNotFound.
func (c *client) QueryWorkerQuota(ctx context.Context, operator string) (WorkerQuota, error) {
	if operator == "" || strings.TrimSpace(operator) != operator {
		return WorkerQuota{}, fmt.Errorf("query worker quota: operator is empty or padded")
	}
	resp, err := c.hubQuery.WorkerQuota(ctx, connect.NewRequest(&hubv1.QueryWorkerQuotaRequest{OperatorAddress: operator}))
	if err != nil {
		if connect.CodeOf(err) == connect.CodeUnimplemented {
			return WorkerQuota{}, ErrWorkerQuotaUnsupported
		}
		return WorkerQuota{}, applicationQueryError("worker quota", err)
	}
	m := resp.Msg
	return WorkerQuota{
		Period: m.GetPeriod(), Quota: m.GetQuota(), ReservedValue: m.GetReservedValue(), SettledValue: m.GetSettledValue(),
		Remaining: m.GetRemaining(), Enforced: m.GetEnforced(), DispatchPaused: m.GetDispatchPaused(), PauseReasons: m.GetPauseReasons(),
	}, nil
}

// QueryWorkerQuota of the stub reports the query as unsupported, so nothing is enforced.
func (c *stubClient) QueryWorkerQuota(context.Context, string) (WorkerQuota, error) {
	return WorkerQuota{}, ErrWorkerQuotaUnsupported
}
