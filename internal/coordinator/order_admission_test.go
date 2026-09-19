package coordinator

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/types"
)

// admissionHeight is the "latest height" reported by the fake registry. Admission must use it to
// query the BuilderSet, not any local term.
const admissionHeight = uint64(9001)

func TestHubStage1AdmissionAllowsSelectedBuilder(t *testing.T) {
	const (
		chainID = "trueopen-localnet-1"
		taskID  = "4f5fc5f611e7fe40cecd95c945bdb8a3383ddbd7d55545758ae8c860546ce193"
		setHash = "68f4c02de973deecab42a56635ac34c47b311371b5c326cf50688065970f7322"
		self    = "trueopen1870sqtdru7dj3xgwpzcexry0dwvyz2ku7xv9mg"
	)
	registry := admissionRegistry(
		chaincli.BuilderState{Address: self, ServiceKeyStatus: "ACTIVE", CurrentDescriptorVersion: 1},
		chaincli.BuilderSet{
			Epoch: 1, BuilderSetID: "1", SetHash: setHash,
			ActiveBuilderCount: 3, BodyStatus: "ACTIVE",
			Members: builderRefs(
				self,
				"trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man",
				"trueopen1yfse4c367uc2rja5g3905ynmnuv2hjk8gcgvfl",
			),
		},
	)
	admission := NewHubStage1Admission(registry, self, chainID)

	result, err := admission.AdmitOrder(context.Background(), types.Order{TaskHash: testPlaceholderTaskHash, TaskID: taskID})
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if result.TermID != 1 || result.Rank != 1 || !strings.HasPrefix(result.Proof, nodecontract.BuilderSelectionProofVersion+":") {
		t.Fatalf("admission result=%+v want term=1 rank=1", result)
	}
	// Admission goes through the height selector; builder_set_version can only come from the return value.
	if registry.queriedHeight != admissionHeight {
		t.Fatalf("BuilderSet queried at height=%d want %d", registry.queriedHeight, admissionHeight)
	}
}

func TestHubStage1AdmissionRejectsBuilderOutsideTopThree(t *testing.T) {
	const (
		chainID = "chain-1"
		taskID  = "task-1"
		setHash = "5f2b1c8d4a6e90f3b7c5d1e8a4f60293b8d7c6e5a4f30291b8c7d6e5a4f30291"
	)
	builders := admissionTestAddresses(t, 4)
	selection, err := nodecontract.ComputeBuilderSelection(7, chainID, "", taskID, "ASSIGN", "", setHash, builders)
	if err != nil {
		t.Fatal(err)
	}
	selected := make(map[string]struct{}, len(selection.SelectedBuilders))
	for _, address := range selection.SelectedBuilders {
		selected[address] = struct{}{}
	}
	self := ""
	for _, address := range builders {
		if _, ok := selected[address]; !ok {
			self = address
			break
		}
	}
	registry := admissionRegistry(
		chaincli.BuilderState{Address: self, ServiceKeyStatus: "ACTIVE"},
		chaincli.BuilderSet{
			Epoch: 7, BuilderSetID: "7", SetHash: setHash,
			ActiveBuilderCount: 4, BodyStatus: "ACTIVE", Members: builderRefs(builders...),
		},
	)

	_, err = NewHubStage1Admission(registry, self, chainID).AdmitOrder(context.Background(), types.Order{TaskHash: testPlaceholderTaskHash, TaskID: taskID})
	if !errors.Is(err, ErrNotSelectedBuilder) {
		t.Fatalf("Admit error=%v want ErrNotSelectedBuilder", err)
	}
}

func TestHubStage1AdmissionFailsClosedWithoutAuthoritativeState(t *testing.T) {
	addresses := admissionTestAddresses(t, 4)
	self := addresses[0]
	validBuilder := chaincli.BuilderState{Address: self, ServiceKeyStatus: "ACTIVE"}
	validSet := chaincli.BuilderSet{
		Epoch: 7, BuilderSetID: "7",
		SetHash: strings.Repeat("ab", 32), ActiveBuilderCount: 3,
		BodyStatus: "ACTIVE", Members: builderRefs(addresses[:3]...),
	}
	invalidAddressSet := validSet
	invalidAddressSet.Members = builderRefs(self, "not-a-bech32-address", addresses[2])
	// The set hash is no longer recomputed locally, so these negative cases change only the item under test and keep the rest valid.
	nonHash32Set := validSet
	nonHash32Set.SetHash = "deadbeef"
	uppercaseHashSet := validSet
	uppercaseHashSet.SetHash = strings.ToUpper(validSet.SetHash)
	emptySet := validSet
	emptySet.Members = nil
	shortSet := validSet
	shortSet.Members = builderRefs(self, addresses[1])
	duplicateSet := validSet
	duplicateSet.Members = builderRefs(self, self, addresses[2])
	selfAbsentSet := validSet
	selfAbsentSet.Members = builderRefs(addresses[1:]...)
	tests := []struct {
		name     string
		registry *fakeBuilderRegistry
		self     string
		chainID  string
		taskID   string
	}{
		{name: "missing registry", self: self, chainID: "chain-1", taskID: "task-1"},
		{name: "builder query failure", registry: &fakeBuilderRegistry{builderErr: errors.New("hub unavailable")}, self: self, chainID: "chain-1", taskID: "task-1"},
		{name: "builder address mismatch", registry: admissionRegistry(chaincli.BuilderState{Address: addresses[1], ServiceKeyStatus: "ACTIVE"}, validSet), self: self, chainID: "chain-1", taskID: "task-1"},
		// Since wire v0.4.1 BuilderState has no admission status; only the service key on the Builder row can be checked.
		{name: "revoked service key", registry: admissionRegistry(chaincli.BuilderState{Address: self, ServiceKeyStatus: "REVOKED"}, validSet), self: self, chainID: "chain-1", taskID: "task-1"},
		// Latest height unavailable / zero: must report STAGE1_UNAVAILABLE, no falling back to guessing by term.
		{name: "latest height failure", registry: &fakeBuilderRegistry{builder: validBuilder, height: admissionHeight, heightErr: errors.New("hub unavailable"), set: validSet}, self: self, chainID: "chain-1", taskID: "task-1"},
		{name: "zero latest height", registry: &fakeBuilderRegistry{builder: validBuilder, set: validSet}, self: self, chainID: "chain-1", taskID: "task-1"},
		{name: "set query failure", registry: &fakeBuilderRegistry{builder: validBuilder, height: admissionHeight, setErr: errors.New("hub unavailable")}, self: self, chainID: "chain-1", taskID: "task-1"},
		{name: "no version returned", registry: admissionRegistry(validBuilder, chaincli.BuilderSet{BuilderSetID: "0", SetHash: validSet.SetHash, Members: validSet.Members}), self: self, chainID: "chain-1", taskID: "task-1"},
		{name: "missing set hash", registry: admissionRegistry(validBuilder, chaincli.BuilderSet{Epoch: 7, Members: validSet.Members}), self: self, chainID: "chain-1", taskID: "task-1"},
		{name: "non hash32 set hash", registry: admissionRegistry(validBuilder, nonHash32Set), self: self, chainID: "chain-1", taskID: "task-1"},
		{name: "uppercase set hash", registry: admissionRegistry(validBuilder, uppercaseHashSet), self: self, chainID: "chain-1", taskID: "task-1"},
		{name: "empty set", registry: admissionRegistry(validBuilder, emptySet), self: self, chainID: "chain-1", taskID: "task-1"},
		{name: "invalid member address", registry: admissionRegistry(validBuilder, invalidAddressSet), self: self, chainID: "chain-1", taskID: "task-1"},
		{name: "short set", registry: admissionRegistry(validBuilder, shortSet), self: self, chainID: "chain-1", taskID: "task-1"},
		{name: "duplicate member", registry: admissionRegistry(validBuilder, duplicateSet), self: self, chainID: "chain-1", taskID: "task-1"},
		{name: "self absent", registry: admissionRegistry(validBuilder, selfAbsentSet), self: self, chainID: "chain-1", taskID: "task-1"},
		{name: "missing self", registry: admissionRegistry(validBuilder, validSet), chainID: "chain-1", taskID: "task-1"},
		{name: "missing chain", registry: admissionRegistry(validBuilder, validSet), self: self, taskID: "task-1"},
		{name: "missing task", registry: admissionRegistry(validBuilder, validSet), self: self, chainID: "chain-1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var registry BuilderRegistry
			if tt.registry != nil {
				registry = tt.registry
			}
			_, err := NewHubStage1Admission(registry, tt.self, tt.chainID).AdmitOrder(context.Background(), types.Order{TaskHash: testPlaceholderTaskHash, TaskID: tt.taskID})
			if !errors.Is(err, ErrAdmissionUnavailable) {
				t.Fatalf("Admit error=%v want ErrAdmissionUnavailable", err)
			}
		})
	}
}

// The read-time consistency check target changes from "active term changed" to "descriptor version
// changed": active_term is no longer on the wire; descriptor version is the monotonic value on the
// same row that MsgUpdateServiceDescriptor actually advances during a read.
func TestHubStage1AdmissionRejectsBuilderIdentityChangeBetweenQueries(t *testing.T) {
	addresses := admissionTestAddresses(t, 3)
	set := chaincli.BuilderSet{
		Epoch: 7, BuilderSetID: "7",
		SetHash: strings.Repeat("cd", 32), ActiveBuilderCount: 3,
		BodyStatus: "ACTIVE", Members: builderRefs(addresses...),
	}
	tests := []struct {
		name      string
		responses []chaincli.BuilderState
	}{
		{name: "descriptor version bumped", responses: []chaincli.BuilderState{
			{Address: addresses[0], ServiceKeyStatus: "ACTIVE", CurrentDescriptorVersion: 1},
			{Address: addresses[0], ServiceKeyStatus: "ACTIVE", CurrentDescriptorVersion: 2},
		}},
		{name: "service key status changed", responses: []chaincli.BuilderState{
			{Address: addresses[0], ServiceKeyStatus: "ACTIVE", CurrentDescriptorVersion: 1},
			{Address: addresses[0], ServiceKeyStatus: "REVOKED", CurrentDescriptorVersion: 1},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := &fakeBuilderRegistry{builderResponses: tt.responses, height: admissionHeight, set: set}
			_, err := NewHubStage1Admission(registry, addresses[0], "chain-1").AdmitOrder(context.Background(), types.Order{TaskHash: testPlaceholderTaskHash, TaskID: "task-1"})
			if !errors.Is(err, ErrAdmissionUnavailable) {
				t.Fatalf("Admit error=%v want ErrAdmissionUnavailable", err)
			}
		})
	}
}

func admissionRegistry(builder chaincli.BuilderState, set chaincli.BuilderSet) *fakeBuilderRegistry {
	return &fakeBuilderRegistry{builder: builder, height: admissionHeight, set: set}
}

func builderRefs(addresses ...string) []types.BuilderRef {
	refs := make([]types.BuilderRef, 0, len(addresses))
	for index, address := range addresses {
		refs = append(refs, types.BuilderRef{Address: address, Rank: index + 1})
	}
	return refs
}

func admissionTestAddresses(t *testing.T, count int) []string {
	t.Helper()
	addresses := make([]string, 0, count)
	for index := 1; index <= count; index++ {
		sg, err := signer.NewFromHex(fmt.Sprintf("%064x", index), "trueopen")
		if err != nil {
			t.Fatal(err)
		}
		addresses = append(addresses, sg.Address())
	}
	return addresses
}
