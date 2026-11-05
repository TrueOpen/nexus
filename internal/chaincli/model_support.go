package chaincli

import (
	"context"
	"fmt"

	"connectrpc.com/connect"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
)

// TypeURLMsgBatchConfirmModelSupport is the Hub message that carries Cortex-signed model support
// confirmations; any account may submit it and pay for it.
const TypeURLMsgBatchConfirmModelSupport = "/hub.v1.MsgBatchConfirmModelSupport"

// SupportParams are the live Hub parameters a model support confirmation and its batch are judged
// by, read together from one params query.
type SupportParams struct {
	// EpochLengthBlocks is epoch.epoch_length_blocks (zero read as the Hub default); the epoch of
	// a height is height / EpochLengthBlocks.
	EpochLengthBlocks uint64
	// MaxServiceMaterialExpiryBlocks is service.max_service_material_expiry_blocks: how far above
	// the executing height a confirmation's expiry_height may lie.
	MaxServiceMaterialExpiryBlocks uint64
	// MaxSupportedModelsPerOperator bounds one confirmation's model list.
	MaxSupportedModelsPerOperator uint32
	// MaxConfirmationsPerBatch, MaxItemsPerBatch and MaxBatchBytes bound one
	// MsgBatchConfirmModelSupport: its confirmations, its model ids summed over them, and its
	// encoded size.
	MaxConfirmationsPerBatch uint32
	MaxItemsPerBatch         uint32
	MaxBatchBytes            uint64
}

// QuerySupportParams reads SupportParams. A zero expiry window or support limit makes the chain
// refuse every confirmation, so it is an error rather than "no limit".
func (c *client) QuerySupportParams(ctx context.Context) (SupportParams, error) {
	resp, err := c.hubQuery.Params(ctx, connect.NewRequest(&hubv1.QueryHubParamsRequest{}))
	if err != nil {
		return SupportParams{}, applicationQueryError("hub params", err)
	}
	params := resp.Msg.GetParams()
	support := params.GetSupport()
	out := SupportParams{
		EpochLengthBlocks:              params.GetEpoch().GetEpochLengthBlocks(),
		MaxServiceMaterialExpiryBlocks: params.GetService().GetMaxServiceMaterialExpiryBlocks(),
		MaxSupportedModelsPerOperator:  support.GetMaxSupportedModelsPerOperator(),
		MaxConfirmationsPerBatch:       support.GetMaxDailySupportConfirmationsPerBatch(),
		MaxItemsPerBatch:               support.GetMaxDailySupportItemsPerBatch(),
		MaxBatchBytes:                  support.GetMaxDailySupportBatchBytes(),
	}
	if out.EpochLengthBlocks == 0 {
		out.EpochLengthBlocks = defaultEpochLengthBlocks
	}
	if out.MaxServiceMaterialExpiryBlocks == 0 || out.MaxSupportedModelsPerOperator == 0 ||
		out.MaxConfirmationsPerBatch == 0 || out.MaxItemsPerBatch == 0 || out.MaxBatchBytes == 0 {
		return SupportParams{}, fmt.Errorf("query hub params: service expiry window or a support batch limit is zero: %+v", out)
	}
	return out, nil
}

// QueryDailySupport reads the chain-accepted support confirmation row of (operator, epoch)
// (hub.v1.Query/DailySupport); ErrNotFound when the chain holds none.
func (c *client) QueryDailySupport(ctx context.Context, operator string, epoch uint64) (*hubv1.DailySupportState, error) {
	resp, err := c.hubQuery.DailySupport(ctx, connect.NewRequest(&hubv1.QueryDailySupportRequest{OperatorAddress: operator, Epoch: epoch}))
	if err != nil {
		return nil, applicationQueryError("daily support", err)
	}
	row := resp.Msg.GetSupport()
	if row == nil || row.GetOperatorAddress() == "" {
		return nil, ErrNotFound
	}
	if row.GetOperatorAddress() != operator || row.GetEpoch() != epoch {
		return nil, fmt.Errorf("query daily support: response key does not match request")
	}
	return row, nil
}

// QueryServiceBond reads an operator's service bond (hub.v1.Query/ServiceBond); ErrNotFound when
// the chain holds none.
func (c *client) QueryServiceBond(ctx context.Context, operator string) (*hubv1.ServiceBondState, error) {
	resp, err := c.hubQuery.ServiceBond(ctx, connect.NewRequest(&hubv1.QueryServiceBondRequest{OperatorAddress: operator}))
	if err != nil {
		return nil, applicationQueryError("service bond", err)
	}
	bond := resp.Msg.GetBond()
	if bond == nil || bond.GetOperatorAddress() == "" {
		return nil, ErrNotFound
	}
	if bond.GetOperatorAddress() != operator {
		return nil, fmt.Errorf("query service bond: response key does not match request")
	}
	return bond, nil
}

// BuildBatchConfirmModelSupportTx signs a MsgBatchConfirmModelSupport whose submitter_address is
// the signing account. The confirmations go as given: their order, limits and validity are the
// caller's to establish.
func BuildBatchConfirmModelSupportTx(s TxSigner, p TxParams, msg *hubv1.MsgBatchConfirmModelSupport) ([]byte, error) {
	if err := checkDispatchMsgSigner(s, "submitter_address", msg.GetSubmitterAddress()); err != nil {
		return nil, fmt.Errorf("batch confirm model support: %w", err)
	}
	if len(msg.GetConfirmations()) == 0 {
		return nil, fmt.Errorf("batch confirm model support: no confirmations")
	}
	return buildDispatchTx(s, p, TypeURLMsgBatchConfirmModelSupport, msg)
}

func (c *stubClient) QuerySupportParams(context.Context) (SupportParams, error) {
	return SupportParams{}, ErrNotSupportedOnChain
}

func (c *stubClient) QueryDailySupport(context.Context, string, uint64) (*hubv1.DailySupportState, error) {
	return nil, ErrNotSupportedOnChain
}

func (c *stubClient) QueryServiceBond(context.Context, string) (*hubv1.ServiceBondState, error) {
	return nil, ErrNotSupportedOnChain
}
