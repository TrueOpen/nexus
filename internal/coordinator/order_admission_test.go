package coordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/cosmos/btcutil/bech32"
	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/types"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

// The BuilderSet the admission cases sign and query: admission must read it at the order's
// session_anchor_height and rank it under the order's session_anchor_block_hash.
const (
	admissionChainID      = "trueopen-localnet-1"
	admissionAnchorHeight = uint64(9001)
	admissionSetID        = "builder-set-7"
	admissionSetVersion   = uint64(7)
	admissionPerTask      = uint32(3)
	admissionSequence     = uint64(0)
	admissionWindow       = uint64(100)
)

var (
	admissionAnchorHash = bytes.Repeat([]byte{0x9c}, 32)
	admissionSetHash    = bytes.Repeat([]byte{0x8b}, 32)
)

func TestHubStage1AdmissionAllowsSelectedBuilder(t *testing.T) {
	builders := admissionTestAddresses(t, 4)
	for want := 1; want <= int(admissionPerTask); want++ {
		taskID, selected := admissionTaskWhere(t, builders, func(order []string) bool { return order[want-1] == builders[0] })
		registry := admissionRegistry(activeBuilder(builders[0]), admissionSet(builders...))

		result, err := NewHubStage1Admission(registry, builders[0], admissionChainID).AdmitOrder(context.Background(), admissionOrder(t, taskID))
		if err != nil {
			t.Fatalf("rank %d: Admit: %v", want, err)
		}
		if result.TermID != admissionSetVersion || result.Rank != uint64(want) {
			t.Fatalf("rank %d: admission result=%+v", want, result)
		}
		if wantProof := independentSelectedHash(t, taskID, selected); result.Proof != wantProof {
			t.Fatalf("rank %d: proof=%s want %s", want, result.Proof, wantProof)
		}
		// The BuilderSet is read at the order's session anchor, not at the latest height.
		if registry.queriedHeight != admissionAnchorHeight {
			t.Fatalf("BuilderSet queried at height=%d want %d", registry.queriedHeight, admissionAnchorHeight)
		}
	}
}

func TestHubStage1AdmissionRejectsBuilderOutsideSelection(t *testing.T) {
	builders := admissionTestAddresses(t, 4)
	taskID, _ := admissionTaskWhere(t, builders, func(order []string) bool { return order[3] == builders[0] })
	registry := admissionRegistry(activeBuilder(builders[0]), admissionSet(builders...))

	_, err := NewHubStage1Admission(registry, builders[0], admissionChainID).AdmitOrder(context.Background(), admissionOrder(t, taskID))
	if !errors.Is(err, ErrNotSelectedBuilder) {
		t.Fatalf("Admit error=%v want ErrNotSelectedBuilder", err)
	}
}

// The member order the Hub returns must not matter: the chain sorts by rank.
func TestHubStage1AdmissionIgnoresMemberOrder(t *testing.T) {
	builders := admissionTestAddresses(t, 5)
	taskID, _ := admissionTaskWhere(t, builders, func(order []string) bool { return order[1] == builders[0] })
	reversed := make([]string, len(builders))
	for i, address := range builders {
		reversed[len(builders)-1-i] = address
	}
	for _, members := range [][]string{builders, reversed} {
		result, err := NewHubStage1Admission(admissionRegistry(activeBuilder(builders[0]), admissionSet(members...)), builders[0], admissionChainID).
			AdmitOrder(context.Background(), admissionOrder(t, taskID))
		if err != nil || result.Rank != 2 {
			t.Fatalf("members=%v result=%+v err=%v", members, result, err)
		}
	}
}

func TestHubStage1AdmissionFailsClosedWithoutAuthoritativeState(t *testing.T) {
	addresses := admissionTestAddresses(t, 4)
	self := addresses[0]
	taskID := admissionTaskFor(t, bytes.Repeat([]byte{0x7a}, 32))
	validBuilder := activeBuilder(self)
	validSet := admissionSet(addresses[:3]...)
	withSet := func(edit func(*chaincli.BuilderSet)) *fakeBuilderRegistry {
		set := validSet
		edit(&set)
		return admissionRegistry(validBuilder, set)
	}
	withOrder := func(edit func(*taskv1.TaskOrderV3)) types.Order {
		order := admissionOrder(t, taskID)
		var signed taskv1.SignedOrderV2
		if err := proto.Unmarshal(order.SignedOrder, &signed); err != nil {
			t.Fatal(err)
		}
		edit(signed.Order)
		raw, err := proto.Marshal(&signed)
		if err != nil {
			t.Fatal(err)
		}
		order.SignedOrder = raw
		return order
	}
	valid := admissionOrder(t, taskID)
	legacy := valid
	legacy.SignedOrder = nil
	garbled := valid
	garbled.SignedOrder = []byte{0xff, 0xff}
	badTaskID := valid
	badTaskID.TaskID = "task-1"
	perTaskFailure := admissionRegistry(validBuilder, validSet)
	perTaskFailure.perTaskErr = errors.New("hub unavailable")
	perTaskTooLarge := admissionRegistry(validBuilder, validSet)
	perTaskTooLarge.buildersPerTask = 4
	setFailure := admissionRegistry(validBuilder, validSet)
	setFailure.setErr = errors.New("hub unavailable")
	withChain := func(edit func(*fakeBuilderRegistry)) *fakeBuilderRegistry {
		registry := admissionRegistry(validBuilder, validSet)
		edit(registry)
		return registry
	}
	// The request names a well-formed task_id the signed order does not derive.
	otherTaskID := valid
	otherTaskID.TaskID = hex.EncodeToString(bytes.Repeat([]byte{0x7b}, 32))

	tests := []struct {
		name     string
		registry *fakeBuilderRegistry
		self     string
		chainID  string
		order    types.Order
	}{
		{name: "missing registry", self: self, chainID: admissionChainID, order: valid},
		{name: "builder query failure", registry: &fakeBuilderRegistry{builderErr: errors.New("hub unavailable")}, self: self, chainID: admissionChainID, order: valid},
		{name: "builder address mismatch", registry: admissionRegistry(activeBuilder(addresses[1]), validSet), self: self, chainID: admissionChainID, order: valid},
		// BuilderState has no admission status; only the service key on the Builder row can be checked.
		{name: "revoked service key", registry: admissionRegistry(chaincli.BuilderState{Address: self, ServiceKeyStatus: "REVOKED"}, validSet), self: self, chainID: admissionChainID, order: valid},
		{name: "set query failure", registry: setFailure, self: self, chainID: admissionChainID, order: valid},
		{name: "no version returned", registry: withSet(func(s *chaincli.BuilderSet) { s.Epoch = 0 }), self: self, chainID: admissionChainID, order: valid},
		{name: "missing set hash", registry: withSet(func(s *chaincli.BuilderSet) { s.SetHash = "" }), self: self, chainID: admissionChainID, order: valid},
		{name: "non hash32 set hash", registry: withSet(func(s *chaincli.BuilderSet) { s.SetHash = "deadbeef" }), self: self, chainID: admissionChainID, order: valid},
		{name: "uppercase set hash", registry: withSet(func(s *chaincli.BuilderSet) { s.SetHash = strings.ToUpper(s.SetHash) }), self: self, chainID: admissionChainID, order: valid},
		{name: "set hash differs from signed order", registry: withSet(func(s *chaincli.BuilderSet) { s.SetHash = strings.Repeat("ab", 32) }), self: self, chainID: admissionChainID, order: valid},
		{name: "set id differs from signed order", registry: withSet(func(s *chaincli.BuilderSet) { s.BuilderSetID = "builder-set-8" }), self: self, chainID: admissionChainID, order: valid},
		{name: "empty set", registry: withSet(func(s *chaincli.BuilderSet) { s.Members = nil }), self: self, chainID: admissionChainID, order: valid},
		{name: "invalid member address", registry: withSet(func(s *chaincli.BuilderSet) { s.Members = builderRefs(self, "not-a-bech32-address", addresses[2]) }), self: self, chainID: admissionChainID, order: valid},
		{name: "duplicate member", registry: withSet(func(s *chaincli.BuilderSet) { s.Members = builderRefs(self, self, addresses[2]) }), self: self, chainID: admissionChainID, order: valid},
		{name: "self absent", registry: withSet(func(s *chaincli.BuilderSet) { s.Members = builderRefs(addresses[1:]...) }), self: self, chainID: admissionChainID, order: valid},
		{name: "builders_per_task failure", registry: perTaskFailure, self: self, chainID: admissionChainID, order: valid},
		{name: "builders_per_task above set size", registry: perTaskTooLarge, self: self, chainID: admissionChainID, order: valid},
		{name: "missing self", registry: admissionRegistry(validBuilder, validSet), chainID: admissionChainID, order: valid},
		{name: "missing chain", registry: admissionRegistry(validBuilder, validSet), self: self, order: valid},
		{name: "non hash32 task id", registry: admissionRegistry(validBuilder, validSet), self: self, chainID: admissionChainID, order: badTaskID},
		// A legacy JSON-envelope order has no session anchor or BuilderSet to rank under.
		{name: "no signed order", registry: admissionRegistry(validBuilder, validSet), self: self, chainID: admissionChainID, order: legacy},
		{name: "undecodable signed order", registry: admissionRegistry(validBuilder, validSet), self: self, chainID: admissionChainID, order: garbled},
		{name: "signed order for another chain", registry: admissionRegistry(validBuilder, validSet), self: self, chainID: admissionChainID, order: withOrder(func(o *taskv1.TaskOrderV3) { o.ChainId = "other-chain" })},
		{name: "signed order without anchor height", registry: admissionRegistry(validBuilder, validSet), self: self, chainID: admissionChainID, order: withOrder(func(o *taskv1.TaskOrderV3) { o.SessionAnchorHeight = 0 })},
		{name: "signed order with short anchor hash", registry: admissionRegistry(validBuilder, validSet), self: self, chainID: admissionChainID, order: withOrder(func(o *taskv1.TaskOrderV3) { o.SessionAnchorBlockHash = o.SessionAnchorBlockHash[:31] })},
		// The chain derives task_id from the signed session and sequence, not from the request.
		{name: "task id not derived by the signed order", registry: admissionRegistry(validBuilder, validSet), self: self, chainID: admissionChainID, order: otherTaskID},
		{name: "signed order for another sequence", registry: admissionRegistry(validBuilder, validSet), self: self, chainID: admissionChainID, order: withOrder(func(o *taskv1.TaskOrderV3) { o.OrderSequence = 1 })},
		// The chain refuses an anchor that is not below the executing block, or too far behind it.
		{name: "anchor not below the executing block", registry: withChain(func(r *fakeBuilderRegistry) { r.height = admissionAnchorHeight - 1 }), self: self, chainID: admissionChainID, order: valid},
		{name: "anchor older than the freshness window", registry: withChain(func(r *fakeBuilderRegistry) { r.height = admissionAnchorHeight + admissionWindow }), self: self, chainID: admissionChainID, order: valid},
		{name: "anchor block hash differs from the chain", registry: withChain(func(r *fakeBuilderRegistry) {
			r.blockHashes = map[uint64][]byte{admissionAnchorHeight: bytes.Repeat([]byte{0x9d}, 32)}
		}), self: self, chainID: admissionChainID, order: valid},
		{name: "anchor block unavailable", registry: withChain(func(r *fakeBuilderRegistry) { r.blockErr = errors.New("block pruned") }), self: self, chainID: admissionChainID, order: valid},
		{name: "latest height failure", registry: withChain(func(r *fakeBuilderRegistry) { r.heightErr = errors.New("node unavailable") }), self: self, chainID: admissionChainID, order: valid},
		{name: "freshness window failure", registry: withChain(func(r *fakeBuilderRegistry) { r.windowErr = errors.New("task params unavailable") }), self: self, chainID: admissionChainID, order: valid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var registry AdmissionRegistry
			if tt.registry != nil {
				registry = tt.registry
			}
			_, err := NewHubStage1Admission(registry, tt.self, tt.chainID).AdmitOrder(context.Background(), tt.order)
			if !errors.Is(err, ErrAdmissionUnavailable) {
				t.Fatalf("Admit error=%v want ErrAdmissionUnavailable", err)
			}
		})
	}
}

// The read-time consistency check compares descriptor version: it is the monotonic value on the
// Builder row that MsgUpdateServiceDescriptor actually advances during a read.
func TestHubStage1AdmissionRejectsBuilderIdentityChangeBetweenQueries(t *testing.T) {
	addresses := admissionTestAddresses(t, 3)
	set := admissionSet(addresses...)
	taskID := admissionTaskFor(t, bytes.Repeat([]byte{0x7a}, 32))
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
			registry := admissionRegistry(chaincli.BuilderState{}, set)
			registry.builderResponses = tt.responses
			_, err := NewHubStage1Admission(registry, addresses[0], admissionChainID).AdmitOrder(context.Background(), admissionOrder(t, taskID))
			if !errors.Is(err, ErrAdmissionUnavailable) {
				t.Fatalf("Admit error=%v want ErrAdmissionUnavailable", err)
			}
		})
	}
}

// admissionRegistry is chain state that admits admissionOrder: the latest block sits right above the
// session anchor, inside the freshness window, and the anchor's block hash is the one the order signed.
func admissionRegistry(builder chaincli.BuilderState, set chaincli.BuilderSet) *fakeBuilderRegistry {
	return &fakeBuilderRegistry{
		builder: builder, set: set, buildersPerTask: admissionPerTask,
		height: admissionAnchorHeight + 1, anchorWindow: admissionWindow,
		blockHashes: map[uint64][]byte{admissionAnchorHeight: admissionAnchorHash},
	}
}

// admissionSessions maps each test task_id to the session that derives it at admissionSequence.
var admissionSessions sync.Map

// admissionTaskFor returns the task_id a session derives at admissionSequence, and records the
// session so admissionOrder can sign it.
func admissionTaskFor(t *testing.T, session []byte) string {
	t.Helper()
	raw, err := nodecontract.DeriveTaskIDFromRawSession(session, admissionSequence)
	if err != nil {
		t.Fatal(err)
	}
	taskID := hex.EncodeToString(raw[:])
	admissionSessions.Store(taskID, append([]byte(nil), session...))
	return taskID
}

func activeBuilder(address string) chaincli.BuilderState {
	return chaincli.BuilderState{Address: address, ServiceKeyStatus: "ACTIVE", CurrentDescriptorVersion: 1}
}

func admissionSet(members ...string) chaincli.BuilderSet {
	return chaincli.BuilderSet{
		Epoch: admissionSetVersion, BuilderSetID: admissionSetID, SetHash: hex.EncodeToString(admissionSetHash),
		ActiveBuilderCount: uint32(len(members)), BodyStatus: "ACTIVE", Members: builderRefs(members...),
	}
}

// admissionOrder is an order whose SignedOrderV2 carries the fields admission ranks under.
func admissionOrder(t *testing.T, taskID string) types.Order {
	t.Helper()
	session, ok := admissionSessions.Load(taskID)
	if !ok {
		t.Fatalf("task %s has no recorded session; derive it with admissionTaskFor", taskID)
	}
	raw, err := proto.Marshal(&taskv1.SignedOrderV2{
		Order: &taskv1.TaskOrderV3{
			ChainId:                admissionChainID,
			SessionId:              session.([]byte),
			OrderSequence:          admissionSequence,
			SessionAnchorHeight:    admissionAnchorHeight,
			SessionAnchorBlockHash: admissionAnchorHash,
			BuilderSetId:           admissionSetID,
			BuilderSetHash:         admissionSetHash,
		},
		SignatureScheme: "eip712",
	})
	if err != nil {
		t.Fatal(err)
	}
	return types.Order{TaskHash: testPlaceholderTaskHash, TaskID: taskID, SignedOrder: raw}
}

// admissionTaskWhere finds a task_id whose independently computed selection order satisfies match,
// and returns it with the first admissionPerTask Builders of that order.
func admissionTaskWhere(t *testing.T, builders []string, match func([]string) bool) (string, []string) {
	t.Helper()
	for i := 0; i < 1000; i++ {
		session := sha256.Sum256([]byte(fmt.Sprintf("admission-session-%d", i)))
		taskID := admissionTaskFor(t, session[:])
		raw, _ := hex.DecodeString(taskID)
		order := independentRankOrder(t, raw, builders)
		if match(order) {
			return taskID, order[:admissionPerTask]
		}
	}
	t.Fatal("no task_id satisfies the requested selection")
	return "", nil
}

// independentRankOrder ranks builders with wirefixture's own H_FIELDS_V1 encoder rather than
// nodecontract, so the admission cases check the production path against a second implementation.
func independentRankOrder(t *testing.T, taskID []byte, builders []string) []string {
	t.Helper()
	seed := sha256.Sum256(wirefixture.HFieldsPreimage("TRUEOPEN_TASK_BUILDERS_V1",
		[]byte(admissionChainID), taskID, admissionSetHash, admissionAnchorHash))
	type ranked struct {
		address string
		raw     []byte
		rank    [32]byte
	}
	all := make([]ranked, 0, len(builders))
	for _, address := range builders {
		raw := addressBytes(t, address)
		all = append(all, ranked{address: address, raw: raw, rank: sha256.Sum256(wirefixture.HFieldsPreimage("TRUEOPEN_TASK_BUILDER_RANK_V1", seed[:], raw))})
	}
	sort.Slice(all, func(i, j int) bool {
		if c := bytes.Compare(all[i].rank[:], all[j].rank[:]); c != 0 {
			return c < 0
		}
		return bytes.Compare(all[i].raw, all[j].raw) < 0
	})
	order := make([]string, len(all))
	for i, entry := range all {
		order[i] = entry.address
	}
	return order
}

func independentSelectedHash(t *testing.T, taskID string, selected []string) string {
	t.Helper()
	rawTaskID, err := hex.DecodeString(taskID)
	if err != nil {
		t.Fatal(err)
	}
	elements := [][]byte{{0, 0, 0, byte(len(selected))}}
	for _, address := range selected {
		elements = append(elements, addressBytes(t, address))
	}
	digest := sha256.Sum256(wirefixture.HFieldsPreimage("TRUEOPEN_SELECTED_TASK_BUILDERS_V1",
		[]byte(admissionChainID), rawTaskID, []byte(admissionSetID), admissionSetHash, wirefixture.Frames(elements...)))
	return hex.EncodeToString(digest[:])
}

func addressBytes(t *testing.T, address string) []byte {
	t.Helper()
	_, raw, err := bech32.DecodeToBase256(address)
	if err != nil {
		t.Fatal(err)
	}
	return raw
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

// The freshness window is inclusive: an anchor exactly anchor_freshness_window_blocks behind the
// executing block is admitted, one more block is not.
func TestHubStage1AdmissionAnchorFreshnessBoundary(t *testing.T) {
	builders := admissionTestAddresses(t, 3)
	taskID, _ := admissionTaskWhere(t, builders, func(order []string) bool { return order[0] == builders[0] })
	for _, tt := range []struct {
		latest uint64
		admit  bool
	}{
		{latest: admissionAnchorHeight + admissionWindow - 1, admit: true},
		{latest: admissionAnchorHeight + admissionWindow, admit: false},
	} {
		registry := admissionRegistry(activeBuilder(builders[0]), admissionSet(builders...))
		registry.height = tt.latest
		_, err := NewHubStage1Admission(registry, builders[0], admissionChainID).AdmitOrder(context.Background(), admissionOrder(t, taskID))
		if (err == nil) != tt.admit {
			t.Fatalf("latest=%d admit=%v err=%v", tt.latest, tt.admit, err)
		}
	}
}
