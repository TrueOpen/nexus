package nodecontract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const (
	BuilderSelectionProofVersion = "trueopen-builder-selection-v2"
	SupportedVerifyRoundV1       = uint64(1)

	builderStageAssignDomain     = "TRUEOPEN_BUILDER_STAGE1_V1"
	builderStageOpenVerifyDomain = "TRUEOPEN_BUILDER_STAGE2_V1"
	builderStageSettleDomain     = "TRUEOPEN_BUILDER_STAGE3_V1"
)

type BuilderSelection struct {
	TermID             uint64
	ChainID            string
	SessionID          string
	TaskID             string
	Stage              string
	StageRef           string
	SelectedBuilders   []string
	SeedHash           string
	SelectionProofHash string
}

func ComputeBuilderSelection(termID uint64, chainID, sessionID, taskID, stage, stageRef, setHash string, builders []string) (BuilderSelection, error) {
	stage = strings.ToUpper(strings.TrimSpace(stage))
	if termID == 0 {
		return BuilderSelection{}, fmt.Errorf("builder selection: term, chain, task, and set hash are required")
	}
	for _, field := range []struct {
		name     string
		value    string
		required bool
	}{
		{name: "chain", value: chainID, required: true},
		{name: "session", value: sessionID},
		{name: "task", value: taskID, required: true},
		{name: "stage ref", value: stageRef},
		{name: "set hash", value: setHash, required: true},
	} {
		if field.required && field.value == "" {
			return BuilderSelection{}, fmt.Errorf("builder selection: %s is required", field.name)
		}
		if strings.TrimSpace(field.value) != field.value || strings.ContainsRune(field.value, '\x00') {
			return BuilderSelection{}, fmt.Errorf("builder selection: %s must be canonical", field.name)
		}
	}
	stageDomain := ""
	switch stage {
	case "ASSIGN":
		stageDomain = builderStageAssignDomain
	case "OPEN_VERIFY":
		stageDomain = builderStageOpenVerifyDomain
	case "SETTLE":
		stageDomain = builderStageSettleDomain
	default:
		return BuilderSelection{}, fmt.Errorf("builder selection: invalid stage %q", stage)
	}
	if len(builders) < 3 {
		return BuilderSelection{}, fmt.Errorf("builder selection: need at least three builders")
	}

	seedFields := []string{chainID, strconv.FormatUint(termID, 10), sessionID, taskID, stageRef, setHash}
	type rankedBuilder struct {
		address string
		hash    []byte
	}
	ranked := make([]rankedBuilder, 0, len(builders))
	seen := make(map[string]struct{}, len(builders))
	for _, address := range builders {
		if address == "" || strings.TrimSpace(address) != address || strings.ContainsRune(address, '\x00') {
			return BuilderSelection{}, fmt.Errorf("builder selection: builder address must be canonical")
		}
		if _, exists := seen[address]; exists {
			return BuilderSelection{}, fmt.Errorf("builder selection: duplicate builder %q", address)
		}
		seen[address] = struct{}{}
		ranked = append(ranked, rankedBuilder{address: address, hash: canonicalHash(stageDomain, append(seedFields, address)...)})
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		if cmp := bytes.Compare(ranked[i].hash, ranked[j].hash); cmp != 0 {
			return cmp < 0
		}
		return ranked[i].address < ranked[j].address
	})
	selected := []string{ranked[0].address, ranked[1].address, ranked[2].address}
	seedHash := canonicalHashHex(stageDomain, seedFields...)
	proofHash := canonicalHashHex(
		BuilderSelectionProofVersion,
		strconv.FormatUint(termID, 10), chainID, sessionID, taskID, stage, stageRef,
		strings.Join(selected, ","), setHash, seedHash,
	)
	return BuilderSelection{
		TermID: termID, ChainID: chainID, SessionID: sessionID, TaskID: taskID,
		Stage: stage, StageRef: stageRef, SelectedBuilders: selected,
		SeedHash: seedHash, SelectionProofHash: proofHash,
	}, nil
}

func (s BuilderSelection) ProofFor(builder string) (uint64, string, error) {
	builder = strings.TrimSpace(builder)
	rank := uint64(0)
	for i, selected := range s.SelectedBuilders {
		if selected == builder {
			rank = uint64(i + 1)
			break
		}
	}
	if rank == 0 {
		return 0, "", fmt.Errorf("builder selection: builder %q is not selected", builder)
	}
	frame := canonicalFrame(
		strconv.FormatUint(s.TermID, 10), s.ChainID, s.SessionID, s.TaskID, s.Stage, s.StageRef,
		strings.Join(s.SelectedBuilders, ","), s.SeedHash, s.SelectionProofHash,
		strconv.FormatUint(rank, 10), builder,
	)
	return rank, BuilderSelectionProofVersion + ":" + hex.EncodeToString(frame), nil
}

func canonicalHashHex(domain string, fields ...string) string {
	return hex.EncodeToString(canonicalHash(domain, fields...))
}

func canonicalHash(domain string, fields ...string) []byte {
	values := append([]string{domain}, fields...)
	sum := sha256.Sum256(canonicalFrame(values...))
	return sum[:]
}

func canonicalFrame(fields ...string) []byte {
	var length [8]byte
	size := 0
	for _, field := range fields {
		size += 8 + len(field)
	}
	framed := make([]byte, 0, size)
	for _, field := range fields {
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		framed = append(framed, length[:]...)
		framed = append(framed, field...)
	}
	return framed
}
