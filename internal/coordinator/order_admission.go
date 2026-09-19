package coordinator

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/types"
	"github.com/cosmos/btcutil/bech32"
)

var (
	ErrNotSelectedBuilder   = errors.New("NEXUS_INGRESS_NOT_SELECTED_BUILDER")
	ErrAdmissionUnavailable = errors.New("NEXUS_INGRESS_STAGE1_UNAVAILABLE")
)

// serviceKeyStatusActive is the short name of the ServiceKeyStatus enum (chaincli's enumShortName strips
// the SERVICE_KEY_STATUS_ prefix). From wire v0.4.1 BuilderState no longer carries an admission status:
// "can this Builder work" = current service key ACTIVE and this address is in active_builders of the
// BuilderSet at that height (admission is fixed by governance and can only be inferred from set membership).
const serviceKeyStatusActive = "ACTIVE"

// OrderAdmission authorizes an order before Nexus persists payload or task state.
type OrderAdmission interface {
	AdmitOrder(context.Context, types.Order) (OrderAdmissionResult, error)
}

type OrderAdmissionResult struct {
	TermID uint64
	Rank   uint64
	Proof  string
}

type hubStage1Admission struct {
	registry     BuilderRegistry
	localAddress string
	taskChainID  string
}

// NewHubStage1Admission builds fail-closed Stage-1 admission from current Hub state.
func NewHubStage1Admission(registry BuilderRegistry, localAddress, taskChainID string) OrderAdmission {
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
	if !isCanonicalRequired(order.TaskID) {
		return OrderAdmissionResult{}, authorityUnavailable("task ID is not canonical", nil)
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
	// answered by the fixed-height BuilderSet query below (selfFound).

	height, err := a.registry.LatestHeight(ctx)
	if err != nil {
		return OrderAdmissionResult{}, authorityUnavailable("query latest height", err)
	}
	if height == 0 {
		return OrderAdmissionResult{}, authorityUnavailable("latest height is zero", nil)
	}
	set, err := a.registry.QueryBuilderSetAtHeight(ctx, height)
	if err != nil {
		return OrderAdmissionResult{}, authorityUnavailable(fmt.Sprintf("query BuilderSet at height %d", height), err)
	}
	if set.Epoch == 0 {
		return OrderAdmissionResult{}, authorityUnavailable(fmt.Sprintf("BuilderSet at height %d returned no version", height), nil)
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
	// The set hash is no longer recomputed locally: BuilderSetViewV1 does not deliver builder_set_members_hash,
	// and the on-chain commitment is TRUEOPEN_BUILDER_SET_V1(chain_id, term, set_id, epochs,
	// snapshot_height, method_version, count, members_hash). Any local recomputation is a different
	// formula and the comparison would fail consistently. chaincli already checks it is a 32-byte Hash32;
	// anything beyond shape belongs to the chain.
	if !isHash32Hex(set.SetHash) {
		return OrderAdmissionResult{}, authorityUnavailable(fmt.Sprintf("BuilderSet version %d commitment is not a 32-byte hash", set.Epoch), nil)
	}
	if !selfFound {
		return OrderAdmissionResult{}, authorityUnavailable(fmt.Sprintf("BuilderSet version %d does not contain local Builder", set.Epoch), nil)
	}
	// Read consistency: only compare identity facts that actually exist on the current wire before and after the
	// read. This used to compare active term, which no longer exists; descriptor version replaces it because it is
	// the monotonic value on the same row that MsgUpdateServiceDescriptor can actually advance during the read.
	confirmedBuilder, err := a.registry.QueryBuilder(ctx, a.localAddress)
	if err != nil {
		return OrderAdmissionResult{}, authorityUnavailable("re-query Builder", err)
	}
	if confirmedBuilder.Address != builder.Address || confirmedBuilder.ServiceKeyStatus != builder.ServiceKeyStatus ||
		confirmedBuilder.CurrentDescriptorVersion != builder.CurrentDescriptorVersion {
		return OrderAdmissionResult{}, authorityUnavailable("Builder state changed while reading the active BuilderSet", nil)
	}
	selection, err := nodecontract.ComputeBuilderSelection(
		set.Epoch,
		a.taskChainID,
		"",
		order.TaskID,
		"ASSIGN",
		"",
		set.SetHash,
		builders,
	)
	if err != nil {
		return OrderAdmissionResult{}, authorityUnavailable("invalid BuilderSet", err)
	}
	rank, proof, err := selection.ProofFor(a.localAddress)
	if err == nil {
		return OrderAdmissionResult{TermID: set.Epoch, Rank: rank, Proof: proof}, nil
	}
	return OrderAdmissionResult{}, fmt.Errorf("%w: builder %q builder_set_version %d", ErrNotSelectedBuilder, a.localAddress, set.Epoch)
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
