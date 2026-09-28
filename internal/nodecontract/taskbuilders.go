package nodecontract

import (
	"bytes"
	"fmt"
	"math"
	"sort"
)

// Task Builder selection, byte-for-byte what the task Keeper runs when it admits a signed order:
//
//	task_builder_seed = H_FIELDS_V1("TRUEOPEN_TASK_BUILDERS_V1",
//	                        chain_id, task_id, builder_set_hash, session_anchor_block_hash)
//	rank(builder)     = H_FIELDS_V1("TRUEOPEN_TASK_BUILDER_RANK_V1",
//	                        task_builder_seed, builder_operator_address)
//
// Every active Builder of the BuilderSet at the order's session_anchor_height is ranked, the ranks
// sort as raw bytes ascending (address codec bytes break the impossible tie), and the first
// builders_per_task (a Hub parameter) are selected in that order. The chain commits the result as
// H_FIELDS_V1("TRUEOPEN_SELECTED_TASK_BUILDERS_V1", chain_id, task_id, builder_set_id,
// builder_set_hash, REPEATED_V1(builder_operator_address)) and serves it from task.v1.Query/TaskBuilders.
// Bytes fields are raw, never hex text; addresses are codec bytes, never Bech32 text. The wire
// vectors testdata/v1/task/task_builder_rank_v1.json and task_domains_v1.json pin all three.
const (
	DomainTaskBuildersV1         = "TRUEOPEN_TASK_BUILDERS_V1"
	DomainTaskBuilderRankV1      = "TRUEOPEN_TASK_BUILDER_RANK_V1"
	DomainSelectedTaskBuildersV1 = "TRUEOPEN_SELECTED_TASK_BUILDERS_V1"
)

// TaskBuilderSeed derives task_builder_seed. taskID, builderSetHash and sessionAnchorBlockHash are
// raw 32-byte values.
func TaskBuilderSeed(chainID string, taskID, builderSetHash, sessionAnchorBlockHash []byte) ([32]byte, error) {
	if chainID == "" {
		return [32]byte{}, fmt.Errorf("task builder seed: chain_id is required")
	}
	chain, err := CanonicalUTF8Field("chain_id", chainID)
	if err != nil {
		return [32]byte{}, err
	}
	fields := [][]byte{chain}
	for _, field := range []struct {
		name  string
		value []byte
	}{
		{"task_id", taskID},
		{"builder_set_hash", builderSetHash},
		{"session_anchor_block_hash", sessionAnchorBlockHash},
	} {
		value, err := CanonicalHash32Field(field.name, field.value)
		if err != nil {
			return [32]byte{}, err
		}
		fields = append(fields, value)
	}
	return CanonicalHashBytes(DomainTaskBuildersV1, fields...), nil
}

// TaskBuilderRank maps one Builder onto its rank under a task_builder_seed.
func TaskBuilderRank(seed [32]byte, builderOperatorAddress string) ([32]byte, error) {
	operator, err := CanonicalOperatorAddressBytes("builder_operator_address", builderOperatorAddress)
	if err != nil {
		return [32]byte{}, err
	}
	return CanonicalHashBytes(DomainTaskBuilderRankV1, seed[:], operator), nil
}

// SelectTaskBuilders returns the first count Builders of activeBuilders in rank order, the same
// list the chain freezes for the task. The input order of activeBuilders does not matter.
func SelectTaskBuilders(seed [32]byte, activeBuilders []string, count uint32) ([]string, error) {
	if count == 0 || uint64(count) > uint64(len(activeBuilders)) {
		return nil, fmt.Errorf("task builder selection: %d active Builders cannot fill builders_per_task %d", len(activeBuilders), count)
	}
	type rankedBuilder struct {
		operator string
		raw      []byte
		rank     [32]byte
	}
	ranked := make([]rankedBuilder, 0, len(activeBuilders))
	seen := make(map[string]struct{}, len(activeBuilders))
	for _, operator := range activeBuilders {
		raw, err := CanonicalOperatorAddressBytes("builder_operator_address", operator)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[string(raw)]; duplicate {
			return nil, fmt.Errorf("task builder selection: duplicate Builder %q", operator)
		}
		seen[string(raw)] = struct{}{}
		ranked = append(ranked, rankedBuilder{
			operator: operator,
			raw:      raw,
			rank:     CanonicalHashBytes(DomainTaskBuilderRankV1, seed[:], raw),
		})
	}
	sort.Slice(ranked, func(i, j int) bool {
		if cmp := bytes.Compare(ranked[i].rank[:], ranked[j].rank[:]); cmp != 0 {
			return cmp < 0
		}
		return bytes.Compare(ranked[i].raw, ranked[j].raw) < 0
	})
	selected := make([]string, count)
	for i := range selected {
		selected[i] = ranked[i].operator
	}
	return selected, nil
}

// SelectedTaskBuildersHash is the chain's commitment to a frozen selection
// (TaskBuilderSelectionState.selected_task_builders_hash); selected is in selection order.
func SelectedTaskBuildersHash(chainID string, taskID []byte, builderSetID string, builderSetHash []byte, selected []string) ([32]byte, error) {
	if chainID == "" || builderSetID == "" {
		return [32]byte{}, fmt.Errorf("selected task builders: chain_id and builder_set_id are required")
	}
	chain, err := CanonicalUTF8Field("chain_id", chainID)
	if err != nil {
		return [32]byte{}, err
	}
	setID, err := CanonicalUTF8Field("builder_set_id", builderSetID)
	if err != nil {
		return [32]byte{}, err
	}
	task, err := CanonicalHash32Field("task_id", taskID)
	if err != nil {
		return [32]byte{}, err
	}
	setHash, err := CanonicalHash32Field("builder_set_hash", builderSetHash)
	if err != nil {
		return [32]byte{}, err
	}
	if len(selected) == 0 || uint64(len(selected)) > math.MaxUint32 {
		return [32]byte{}, fmt.Errorf("selected task builders: the list must be non-empty and bounded")
	}
	// REPEATED_V1: a frame holding u32_be(element count) and then each element.
	elements := make([][]byte, 0, len(selected)+1)
	elements = append(elements, Uint32BE(uint32(len(selected))))
	for index, builder := range selected {
		operator, err := CanonicalOperatorAddressBytes(fmt.Sprintf("selected_task_builders[%d]", index), builder)
		if err != nil {
			return [32]byte{}, err
		}
		elements = append(elements, operator)
	}
	return CanonicalHashBytes(DomainSelectedTaskBuildersV1, chain, task, setID, setHash, CanonicalFrameBytes(elements...)), nil
}
