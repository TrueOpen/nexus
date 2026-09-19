package coordinator

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/types"
)

// Asserts the core behaviour of this ticket: when BuilderState carries **neither** active_term nor
// admission status (wire v0.4.1), a Builder whose service key is ACTIVE and who is in the BuilderSet
// still seeds successfully, and builder_set_version is taken from the height-selector query result,
// not derived locally.
func TestCoordinatorSeedsBuilderSetFromHeightSelector(t *testing.T) {
	sg := coordinatorTestSigner(t)
	registry := &fakeBuilderRegistry{
		builder: chaincli.BuilderState{Address: testBuilderSelf, ServiceKeyStatus: "ACTIVE", CurrentDescriptorVersion: 1},
		height:  4242,
		set: chaincli.BuilderSet{Epoch: 7, BuilderSetID: "7", Members: []types.BuilderRef{
			{Address: testBuilderSelf, Rank: 1},
			{Address: "builder-2", Rank: 2},
			{Address: "builder-3", Rank: 3},
		}, ActiveBuilderCount: 3, BodyStatus: "ACTIVE", SetHash: strings.Repeat("ab", 32)},
	}
	c, _ := newTestCoordinator(t, WithIdentitySigner(sg), WithBuilderRegistry(registry))
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Stop(context.Background()) })

	if registry.address != testBuilderSelf {
		t.Fatalf("registry queried address=%q want builder-self", registry.address)
	}
	// Key assertion: the query uses the latest height, not any term argument.
	if registry.queriedHeight != 4242 {
		t.Fatalf("BuilderSet queried at height=%d want 4242", registry.queriedHeight)
	}
	if c.active.Epoch() != 7 || !c.active.IsActive() || len(c.active.Members()) != 3 {
		t.Fatalf("active set epoch=%d active=%v members=%+v", c.active.Epoch(), c.active.IsActive(), c.active.Members())
	}
}

func TestCoordinatorWithSignedIdentityRequiresValidHubBuilderSet(t *testing.T) {
	sg := coordinatorTestSigner(t)
	activeBuilder := chaincli.BuilderState{Address: testBuilderSelf, ServiceKeyStatus: "ACTIVE"}
	tests := []struct {
		name     string
		registry BuilderRegistry
		want     string
	}{
		{name: "missing registry", want: "builder registry is required"},
		{name: "query failure", registry: &fakeBuilderRegistry{builderErr: errors.New("hub unavailable")}, want: "query Builder"},
		// The old assertions were "no active term" / "admission status"; neither is on the wire any more,
		// so the only thing to check on the Builder row is the service key state: REVOKED must fail closed.
		{name: "revoked service key", registry: &fakeBuilderRegistry{
			builder: chaincli.BuilderState{Address: testBuilderSelf, ServiceKeyStatus: "REVOKED"}, height: 100,
		}, want: `service key status is "REVOKED"`},
		{name: "builder address mismatch", registry: &fakeBuilderRegistry{
			builder: chaincli.BuilderState{Address: "builder-other", ServiceKeyStatus: "ACTIVE"}, height: 100,
		}, want: "does not match local Builder"},
		// Latest height cannot be queried -> startup fails closed, no degrading to "guess by term".
		{name: "latest height failure", registry: &fakeBuilderRegistry{
			builder: activeBuilder, heightErr: errors.New("hub unavailable"),
		}, want: "query latest height"},
		{name: "zero latest height", registry: &fakeBuilderRegistry{
			builder: activeBuilder,
		}, want: "latest height is zero"},
		{name: "builder set failure", registry: &fakeBuilderRegistry{
			builder: activeBuilder, height: 100, setErr: errors.New("hub unavailable"),
		}, want: "query BuilderSet at height 100"},
		{name: "no version returned", registry: &fakeBuilderRegistry{
			builder: activeBuilder, height: 100,
			set: chaincli.BuilderSet{Members: []types.BuilderRef{{Address: testBuilderSelf}}},
		}, want: "returned no term"},
		{name: "empty set", registry: &fakeBuilderRegistry{
			builder: activeBuilder, height: 100, set: chaincli.BuilderSet{Epoch: 7},
		}, want: "is empty"},
		{name: "duplicate member", registry: &fakeBuilderRegistry{
			builder: activeBuilder, height: 100,
			set: chaincli.BuilderSet{Epoch: 7, Members: []types.BuilderRef{
				{Address: testBuilderSelf}, {Address: testBuilderSelf},
			}},
		}, want: "duplicate address"},
		{name: "self absent", registry: &fakeBuilderRegistry{
			builder: activeBuilder, height: 100,
			set: chaincli.BuilderSet{Epoch: 7, Members: []types.BuilderRef{{Address: "builder-2"}}},
		}, want: "does not contain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTestCoordinator(t, WithIdentitySigner(sg), WithBuilderRegistry(tt.registry))
			err := c.Start(context.Background())
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err=%v want substring %q", err, tt.want)
			}
		})
	}
}

func coordinatorTestSigner(t *testing.T) signer.Signer {
	t.Helper()
	sg, err := signer.NewFromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "trueopen")
	if err != nil {
		t.Fatal(err)
	}
	return sg
}

type fakeBuilderRegistry struct {
	address          string
	queriedHeight    uint64
	builder          chaincli.BuilderState
	builderResponses []chaincli.BuilderState
	builderCalls     int
	builderErr       error
	height           uint64
	heightErr        error
	set              chaincli.BuilderSet
	setErr           error
}

func (r *fakeBuilderRegistry) QueryBuilder(_ context.Context, address string) (chaincli.BuilderState, error) {
	r.address = address
	if len(r.builderResponses) > 0 {
		index := r.builderCalls
		if index >= len(r.builderResponses) {
			index = len(r.builderResponses) - 1
		}
		r.builderCalls++
		return r.builderResponses[index], r.builderErr
	}
	r.builderCalls++
	return r.builder, r.builderErr
}

func (r *fakeBuilderRegistry) LatestHeight(context.Context) (uint64, error) {
	return r.height, r.heightErr
}

func (r *fakeBuilderRegistry) QueryBuilderSetAtHeight(_ context.Context, height uint64) (chaincli.BuilderSet, error) {
	r.queriedHeight = height
	return r.set, r.setErr
}
