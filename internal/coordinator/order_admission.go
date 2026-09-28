package coordinator

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/types"
	"github.com/cosmos/btcutil/bech32"
	"google.golang.org/protobuf/proto"
)

var (
	ErrNotSelectedBuilder   = errors.New("NEXUS_INGRESS_NOT_SELECTED_BUILDER")
	ErrAdmissionUnavailable = errors.New("NEXUS_INGRESS_STAGE1_UNAVAILABLE")
)

// serviceKeyStatusActive is the short name of the ServiceKeyStatus enum (chaincli's enumShortName strips
// the SERVICE_KEY_STATUS_ prefix). BuilderState no longer carries an admission status:
// "can this Builder work" = current service key ACTIVE and this address is in active_builders of the
// BuilderSet at that height (admission is fixed by governance and can only be inferred from set membership).
const serviceKeyStatusActive = "ACTIVE"

// OrderAdmission authorizes an order before Nexus persists payload or task state.
type OrderAdmission interface {
	AdmitOrder(context.Context, types.Order) (OrderAdmissionResult, error)
}

// OrderAdmissionResult is this Builder's place in the task's Builder selection.
type OrderAdmissionResult struct {
	// TermID is the version of the BuilderSet the selection ran over.
	TermID uint64
	// Rank is this Builder's 1-based position in the selection order.
	Rank uint64
	// Proof is the lowercase hex of the TRUEOPEN_SELECTED_TASK_BUILDERS_V1 digest, the value the chain
	// commits as selected_task_builders_hash once it admits the order.
	Proof string
}

// AdmissionRegistry is the Hub state order admission reads.
type AdmissionRegistry interface {
	BuilderRegistry
	// QueryBuildersPerTask reads the Hub parameter builder.builders_per_task.
	QueryBuildersPerTask(context.Context) (uint32, error)
}

type hubStage1Admission struct {
	registry     AdmissionRegistry
	localAddress string
	taskChainID  string
}

// NewHubStage1Admission builds fail-closed order admission from Hub state. It reproduces the
// Task Builder selection the task Keeper runs when it admits the signed order (see
// nodecontract.SelectTaskBuilders), so its answer agrees with task.v1.Query/TaskBuilders.
func NewHubStage1Admission(registry AdmissionRegistry, localAddress, taskChainID string) OrderAdmission {
	return &hubStage1Admission{
		registry:     registry,
		localAddress: localAddress,
		taskChainID:  taskChainID,
	}
}

func (a *hubStage1Admission) AdmitOrder(ctx context.Context, order types.Order) (OrderAdmissionResult, error) {
	if a.registry == nil {
		return OrderAdmissionResult{}, authorityUnavailable("builder registry is not configured", nil)
	}
	localHRP, err := canonicalBuilderAddress(a.localAddress)
	if err != nil {
		return OrderAdmissionResult{}, authorityUnavailable("local builder address is not canonical", err)
	}
	if !isCanonicalRequired(a.taskChainID) {
		return OrderAdmissionResult{}, authorityUnavailable("task chain ID is not canonical", nil)
	}
	taskID, err := nodecontract.Hash32Bytes("task_id", order.TaskID)
	if err != nil {
		return OrderAdmissionResult{}, authorityUnavailable("task ID is not canonical", err)
	}
	// The selection seed and the BuilderSet come from the order the user signed: the chain ranks the
	// BuilderSet at session_anchor_height, under session_anchor_block_hash.
	signed, err := signedTaskOrder(order)
	if err != nil {
		return OrderAdmissionResult{}, authorityUnavailable("signed order", err)
	}
	if signed.GetChainId() != a.taskChainID {
		return OrderAdmissionResult{}, authorityUnavailable(fmt.Sprintf("signed order chain_id %q is not the task chain %q", signed.GetChainId(), a.taskChainID), nil)
	}
	anchorHeight := signed.GetSessionAnchorHeight()
	if anchorHeight == 0 {
		return OrderAdmissionResult{}, authorityUnavailable("signed order has no session_anchor_height", nil)
	}

	builder, err := a.registry.QueryBuilder(ctx, a.localAddress)
	if err != nil {
		return OrderAdmissionResult{}, authorityUnavailable("query Builder", err)
	}
	if builder.Address != a.localAddress {
		return OrderAdmissionResult{}, authorityUnavailable(fmt.Sprintf("Builder address %q does not match local address", builder.Address), nil)
	}
	if builder.ServiceKeyStatus != serviceKeyStatusActive {
		return OrderAdmissionResult{}, authorityUnavailable(fmt.Sprintf("Builder %q service key status is %q", a.localAddress, builder.ServiceKeyStatus), nil)
	}
	// Up to here the only assertable fact is "this Builder's service key is ACTIVE". Admission is
	// answered by the BuilderSet query below (selfFound).

	set, err := a.registry.QueryBuilderSetAtHeight(ctx, anchorHeight)
	if err != nil {
		return OrderAdmissionResult{}, authorityUnavailable(fmt.Sprintf("query BuilderSet at session anchor height %d", anchorHeight), err)
	}
	if set.Epoch == 0 {
		return OrderAdmissionResult{}, authorityUnavailable(fmt.Sprintf("BuilderSet at height %d returned no version", anchorHeight), nil)
	}
	if len(set.Members) == 0 {
		return OrderAdmissionResult{}, authorityUnavailable(fmt.Sprintf("BuilderSet version %d is empty", set.Epoch), nil)
	}

	builders := make([]string, 0, len(set.Members))
	seen := make(map[string]struct{}, len(set.Members))
	selfFound := false
	for _, member := range set.Members {
		hrp, err := canonicalBuilderAddress(member.Address)
		if err != nil || hrp != localHRP {
			return OrderAdmissionResult{}, authorityUnavailable(fmt.Sprintf("BuilderSet version %d contains an invalid Builder address %q", set.Epoch, member.Address), err)
		}
		if _, exists := seen[member.Address]; exists {
			return OrderAdmissionResult{}, authorityUnavailable(fmt.Sprintf("BuilderSet version %d contains duplicate Builder address %q", set.Epoch, member.Address), nil)
		}
		seen[member.Address] = struct{}{}
		builders = append(builders, member.Address)
		selfFound = selfFound || member.Address == a.localAddress
	}
	// The set hash is not recomputed locally: BuilderSetViewV1 does not deliver builder_set_members_hash.
	// chaincli already checks it is a 32-byte Hash32; here it must also be the set the user signed.
	if !isHash32Hex(set.SetHash) {
		return OrderAdmissionResult{}, authorityUnavailable(fmt.Sprintf("BuilderSet version %d commitment is not a 32-byte hash", set.Epoch), nil)
	}
	setHash, _ := hex.DecodeString(set.SetHash)
	if set.BuilderSetID != signed.GetBuilderSetId() || !bytes.Equal(setHash, signed.GetBuilderSetHash()) {
		return OrderAdmissionResult{}, authorityUnavailable(fmt.Sprintf("BuilderSet version %d at height %d is not the BuilderSet the order signed", set.Epoch, anchorHeight), nil)
	}
	if !selfFound {
		return OrderAdmissionResult{}, authorityUnavailable(fmt.Sprintf("BuilderSet version %d does not contain local Builder", set.Epoch), nil)
	}
	// Read consistency: only compare identity facts that actually exist on the current wire before and after the
	// read. Descriptor version is the monotonic value on the same row that MsgUpdateServiceDescriptor can
	// actually advance during the read.
	confirmedBuilder, err := a.registry.QueryBuilder(ctx, a.localAddress)
	if err != nil {
		return OrderAdmissionResult{}, authorityUnavailable("re-query Builder", err)
	}
	if confirmedBuilder.Address != builder.Address || confirmedBuilder.ServiceKeyStatus != builder.ServiceKeyStatus ||
		confirmedBuilder.CurrentDescriptorVersion != builder.CurrentDescriptorVersion {
		return OrderAdmissionResult{}, authorityUnavailable("Builder state changed while reading the active BuilderSet", nil)
	}
	count, err := a.registry.QueryBuildersPerTask(ctx)
	if err != nil {
		return OrderAdmissionResult{}, authorityUnavailable("query builders_per_task", err)
	}

	seed, err := nodecontract.TaskBuilderSeed(a.taskChainID, taskID, setHash, signed.GetSessionAnchorBlockHash())
	if err != nil {
		return OrderAdmissionResult{}, authorityUnavailable("task builder seed", err)
	}
	selected, err := nodecontract.SelectTaskBuilders(seed, builders, count)
	if err != nil {
		return OrderAdmissionResult{}, authorityUnavailable("invalid BuilderSet", err)
	}
	for index, address := range selected {
		if address != a.localAddress {
			continue
		}
		digest, err := nodecontract.SelectedTaskBuildersHash(a.taskChainID, taskID, set.BuilderSetID, setHash, selected)
		if err != nil {
			return OrderAdmissionResult{}, authorityUnavailable("selected task builders hash", err)
		}
		return OrderAdmissionResult{TermID: set.Epoch, Rank: uint64(index + 1), Proof: hex.EncodeToString(digest[:])}, nil
	}
	return OrderAdmissionResult{}, fmt.Errorf("%w: builder %q builder_set_version %d", ErrNotSelectedBuilder, a.localAddress, set.Epoch)
}

// signedTaskOrder decodes the TaskOrderV3 inside the SDK-provided SignedOrderV2. Orders that still
// carry only the legacy JSON envelope have no session anchor or BuilderSet, so they cannot be ranked.
func signedTaskOrder(order types.Order) (*taskv1.TaskOrderV3, error) {
	if len(order.SignedOrder) == 0 {
		return nil, fmt.Errorf("order carries no SignedOrderV2")
	}
	var signed taskv1.SignedOrderV2
	if err := proto.Unmarshal(order.SignedOrder, &signed); err != nil {
		return nil, fmt.Errorf("decode SignedOrderV2: %w", err)
	}
	if signed.GetOrder() == nil {
		return nil, fmt.Errorf("SignedOrderV2 carries no order")
	}
	return signed.GetOrder(), nil
}

func canonicalBuilderAddress(address string) (string, error) {
	if !isCanonicalRequired(address) {
		return "", fmt.Errorf("address is empty or padded")
	}
	hrp, raw, err := bech32.DecodeToBase256(address)
	if err != nil {
		return "", err
	}
	if len(raw) != 20 {
		return "", fmt.Errorf("address payload length is %d, want 20", len(raw))
	}
	canonical, err := bech32.EncodeFromBase256(hrp, raw)
	if err != nil {
		return "", err
	}
	if canonical != address {
		return "", fmt.Errorf("address is not in canonical Bech32 form")
	}
	return hrp, nil
}

func isCanonicalRequired(value string) bool {
	return value != "" && strings.TrimSpace(value) == value && !strings.ContainsRune(value, '\x00')
}

// isHash32Hex checks shape only: lowercase 64-hex, i.e. chaincli's encoding of a 32-byte Hash32.
func isHash32Hex(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func authorityUnavailable(reason string, cause error) error {
	if cause != nil {
		return fmt.Errorf("%w: %s: %v", ErrAdmissionUnavailable, reason, cause)
	}
	return fmt.Errorf("%w: %s", ErrAdmissionUnavailable, reason)
}
