package chaincli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"strings"

	"connectrpc.com/connect"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
)

// CandidatePoolMemberKey selects one operator in one candidate pool snapshot. ModelID and
// ProfileVersion are set together to ask for the profile-specific membership and weight, or
// left zero for the plain membership.
type CandidatePoolMemberKey struct {
	SnapshotID     []byte // 32 bytes
	Operator       string
	ModelID        []byte // 32 bytes, or nil
	ProfileVersion uint32
}

// VrfKey is an operator's registered VRF public keys (hub.v1.Query/VrfKey). PendingPubKey is nil
// and PendingFromEpoch zero when no next-epoch key is registered.
type VrfKey struct {
	ActivePubKey       []byte // 32-byte ed25519 public key
	ActiveFromEpoch    uint64
	PendingPubKey      []byte
	PendingFromEpoch   uint64
	AuthorizationNonce uint64
}

// QueryCandidatePoolSnapshotMember reads one operator's membership, slot and weight inputs in a
// pool snapshot (hub.v1.Query/CandidatePoolSnapshotMember). An operator outside the pool is
// answered with in_pool false, not ErrNotFound.
func (c *client) QueryCandidatePoolSnapshotMember(ctx context.Context, key CandidatePoolMemberKey) (*hubv1.CandidatePoolSnapshotMemberViewV1, error) {
	if err := checkHash32("snapshot_id", key.SnapshotID); err != nil {
		return nil, fmt.Errorf("query candidate pool snapshot member: %w", err)
	}
	if key.Operator == "" || strings.TrimSpace(key.Operator) != key.Operator {
		return nil, fmt.Errorf("query candidate pool snapshot member: operator is empty or padded")
	}
	request := &hubv1.QueryCandidatePoolSnapshotMemberRequest{SnapshotId: key.SnapshotID, OperatorAddress: key.Operator}
	switch {
	case key.ModelID == nil && key.ProfileVersion == 0:
	case key.ModelID == nil || key.ProfileVersion == 0:
		return nil, fmt.Errorf("query candidate pool snapshot member: model_id and profile_version go together")
	default:
		if err := checkHash32("model_id", key.ModelID); err != nil {
			return nil, fmt.Errorf("query candidate pool snapshot member: %w", err)
		}
		version := key.ProfileVersion
		request.ModelId, request.ProfileVersion = key.ModelID, &version
	}
	resp, err := c.hubQuery.CandidatePoolSnapshotMember(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, applicationQueryError("candidate pool snapshot member", err)
	}
	member := resp.Msg.GetMember()
	if member == nil {
		return nil, fmt.Errorf("query candidate pool snapshot member: %w", ErrNotFound)
	}
	return member, nil
}

// QueryCandidatePoolSnapshot reads the public header of one pool snapshot. A PRUNED snapshot is
// returned as is: its status does not mean an empty pool.
func (c *client) QueryCandidatePoolSnapshot(ctx context.Context, snapshotID []byte) (*hubv1.CandidatePoolSnapshotViewV1, error) {
	if err := checkHash32("snapshot_id", snapshotID); err != nil {
		return nil, fmt.Errorf("query candidate pool snapshot: %w", err)
	}
	resp, err := c.hubQuery.CandidatePoolSnapshot(ctx, connect.NewRequest(&hubv1.QueryCandidatePoolSnapshotRequest{SnapshotId: snapshotID}))
	if err != nil {
		return nil, applicationQueryError("candidate pool snapshot", err)
	}
	snapshot, err := candidatePoolSnapshotView("candidate pool snapshot", resp.Msg.GetSnapshot())
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(snapshot.GetSnapshotId(), snapshotID) {
		return nil, fmt.Errorf("query candidate pool snapshot: response snapshot does not match request")
	}
	return snapshot, nil
}

// maxCandidatePoolMemberPages bounds one walk of a snapshot's members; a snapshot never holds more
// slots than its slot_capacity, so a walk that needs more pages is a broken cursor.
const maxCandidatePoolMemberPages = 4096

// QueryCandidatePoolMembers reads one page of a snapshot's members in ascending slot order
// (hub.v1.Query/CandidatePoolMembers); pageToken is empty for the first page and the returned
// token is empty after the last. The views carry membership only: weights and eligibility come
// per member from QueryCandidatePoolSnapshotMember.
func (c *client) QueryCandidatePoolMembers(ctx context.Context, snapshotID, pageToken []byte) ([]*hubv1.CandidatePoolMemberViewV1, []byte, error) {
	if err := checkHash32("snapshot_id", snapshotID); err != nil {
		return nil, nil, fmt.Errorf("query candidate pool members: %w", err)
	}
	resp, err := c.hubQuery.CandidatePoolMembers(ctx, connect.NewRequest(&hubv1.QueryCandidatePoolMembersRequest{
		SnapshotId: snapshotID, Page: &sharedv1.QueryPageRequestV1{PageToken: pageToken},
	}))
	if err != nil {
		return nil, nil, applicationQueryError("candidate pool members", err)
	}
	members := resp.Msg.GetMembers()
	for i, m := range members {
		if m == nil || m.GetOperatorAddress() == "" {
			return nil, nil, fmt.Errorf("query candidate pool members: member %d has no operator", i)
		}
		if i > 0 && members[i-1].GetCandidateSlot() >= m.GetCandidateSlot() {
			return nil, nil, fmt.Errorf("query candidate pool members: slots are not strictly ascending")
		}
	}
	return members, bytes.Clone(resp.Msg.GetPage().GetNextPageToken()), nil
}

// CandidatePoolMemberPager is the paged member read ListCandidatePoolMembers walks.
type CandidatePoolMemberPager interface {
	QueryCandidatePoolMembers(ctx context.Context, snapshotID, pageToken []byte) ([]*hubv1.CandidatePoolMemberViewV1, []byte, error)
}

// ListCandidatePoolMembers walks every page of a snapshot's members and returns them in strictly
// ascending slot order. A page that does not continue after the previous one, or a cursor that
// never ends, fails the walk: a partial list is never returned as the pool.
func ListCandidatePoolMembers(ctx context.Context, q CandidatePoolMemberPager, snapshotID []byte) ([]*hubv1.CandidatePoolMemberViewV1, error) {
	var out []*hubv1.CandidatePoolMemberViewV1
	var token []byte
	for page := 0; page < maxCandidatePoolMemberPages; page++ {
		members, next, err := q.QueryCandidatePoolMembers(ctx, snapshotID, token)
		if err != nil {
			return nil, err
		}
		if len(out) > 0 && len(members) > 0 && members[0].GetCandidateSlot() <= out[len(out)-1].GetCandidateSlot() {
			return nil, fmt.Errorf("list candidate pool members: page %d does not continue after slot %d", page, out[len(out)-1].GetCandidateSlot())
		}
		out = append(out, members...)
		if len(next) == 0 {
			return out, nil
		}
		if bytes.Equal(next, token) {
			return nil, fmt.Errorf("list candidate pool members: page token did not advance")
		}
		token = next
	}
	return nil, fmt.Errorf("list candidate pool members: more than %d pages", maxCandidatePoolMemberPages)
}

// QueryCurrentCandidatePool reads the one ACTIVE snapshot the chain's current-pool pointer
// resolves to; the view's epoch names the epoch it serves. No pointer is ErrNotFound.
func (c *client) QueryCurrentCandidatePool(ctx context.Context) (*hubv1.CandidatePoolSnapshotViewV1, error) {
	resp, err := c.hubQuery.CurrentCandidatePool(ctx, connect.NewRequest(&hubv1.QueryCurrentCandidatePoolRequest{}))
	if err != nil {
		return nil, applicationQueryError("current candidate pool", err)
	}
	return candidatePoolSnapshotView("current candidate pool", resp.Msg.GetSnapshot())
}

func candidatePoolSnapshotView(kind string, snapshot *hubv1.CandidatePoolSnapshotViewV1) (*hubv1.CandidatePoolSnapshotViewV1, error) {
	if snapshot == nil || len(snapshot.GetSnapshotId()) == 0 {
		return nil, fmt.Errorf("query %s: %w", kind, ErrNotFound)
	}
	if len(snapshot.GetSnapshotId()) != 32 {
		return nil, fmt.Errorf("query %s: snapshot_id is %d bytes, want 32", kind, len(snapshot.GetSnapshotId()))
	}
	return snapshot, nil
}

// QueryBuilderCompensationAccount reads a Builder's compensation account: its balance caps the
// compensation and penalties the Builder can pay. No account is ErrNotFound.
func (c *client) QueryBuilderCompensationAccount(ctx context.Context, builder string) (*hubv1.BuilderCompensationAccountState, error) {
	resp, err := c.hubQuery.BuilderCompensationAccount(ctx, connect.NewRequest(&hubv1.QueryBuilderCompensationAccountRequest{
		BuilderAddress: builder,
	}))
	if err != nil {
		return nil, applicationQueryError("builder compensation account", err)
	}
	account := resp.Msg.GetAccount()
	if account == nil || account.GetBuilderAddress() == "" {
		return nil, fmt.Errorf("query builder compensation account: %w", ErrNotFound)
	}
	if account.GetBuilderAddress() != builder {
		return nil, fmt.Errorf("query builder compensation account: response builder does not match request")
	}
	return account, nil
}

// QueryVrfKey reads an operator's VRF keys in one participant domain. The domain is always sent
// explicitly: on the wire a zero participant_type selects the Validator key.
func (c *client) QueryVrfKey(ctx context.Context, participantType, operator string) (VrfKey, error) {
	domain, err := parseParticipantType(participantType)
	if err != nil {
		return VrfKey{}, fmt.Errorf("query vrf key: %w", err)
	}
	resp, err := c.hubQuery.VrfKey(ctx, connect.NewRequest(&hubv1.QueryVrfKeyRequest{
		OperatorAddress: operator, ParticipantType: domain,
	}))
	if err != nil {
		return VrfKey{}, applicationQueryError("vrf key", err)
	}
	msg := resp.Msg
	if len(msg.GetActiveVrfPubkey()) == 0 {
		return VrfKey{}, fmt.Errorf("query vrf key: %w", ErrNotFound)
	}
	if len(msg.GetActiveVrfPubkey()) != ed25519.PublicKeySize {
		return VrfKey{}, fmt.Errorf("query vrf key: active_vrf_pubkey is %d bytes, want %d", len(msg.GetActiveVrfPubkey()), ed25519.PublicKeySize)
	}
	key := VrfKey{
		ActivePubKey:       bytes.Clone(msg.GetActiveVrfPubkey()),
		ActiveFromEpoch:    msg.GetActiveFromEpoch(),
		AuthorizationNonce: msg.GetVrfAuthorizationNonce(),
	}
	if (msg.PendingVrfPubkey == nil) != (msg.PendingFromEpoch == nil) {
		return VrfKey{}, fmt.Errorf("query vrf key: pending_vrf_pubkey and pending_from_epoch must be present together")
	}
	if msg.PendingVrfPubkey != nil {
		if len(msg.GetPendingVrfPubkey()) != ed25519.PublicKeySize {
			return VrfKey{}, fmt.Errorf("query vrf key: pending_vrf_pubkey is %d bytes, want %d", len(msg.GetPendingVrfPubkey()), ed25519.PublicKeySize)
		}
		if msg.GetPendingFromEpoch() <= msg.GetActiveFromEpoch() {
			return VrfKey{}, fmt.Errorf("query vrf key: pending_from_epoch %d is not after active_from_epoch %d",
				msg.GetPendingFromEpoch(), msg.GetActiveFromEpoch())
		}
		key.PendingPubKey = bytes.Clone(msg.GetPendingVrfPubkey())
		key.PendingFromEpoch = msg.GetPendingFromEpoch()
	}
	return key, nil
}

// QueryBeacon reads the beacon recorded at one height (hub.v1.Query/Beacon).
func (c *client) QueryBeacon(ctx context.Context, height uint64) (*hubv1.BeaconState, error) {
	if height == 0 {
		return nil, fmt.Errorf("query beacon: height must be greater than zero")
	}
	resp, err := c.hubQuery.Beacon(ctx, connect.NewRequest(&hubv1.QueryBeaconRequest{Height: height}))
	if err != nil {
		return nil, applicationQueryError("beacon", err)
	}
	beacon := resp.Msg.GetBeacon()
	if beacon == nil || beacon.GetHeight() == 0 {
		return nil, fmt.Errorf("query beacon: %w", ErrNotFound)
	}
	if beacon.GetHeight() != height {
		return nil, fmt.Errorf("query beacon: response height %d does not match request %d", beacon.GetHeight(), height)
	}
	return beacon, nil
}

func (c *stubClient) QueryCandidatePoolSnapshotMember(context.Context, CandidatePoolMemberKey) (*hubv1.CandidatePoolSnapshotMemberViewV1, error) {
	return nil, ErrNotFound
}

func (c *stubClient) QueryCandidatePoolMembers(context.Context, []byte, []byte) ([]*hubv1.CandidatePoolMemberViewV1, []byte, error) {
	return nil, nil, ErrNotFound
}

func (c *stubClient) QueryCandidatePoolSnapshot(context.Context, []byte) (*hubv1.CandidatePoolSnapshotViewV1, error) {
	return nil, ErrNotFound
}

func (c *stubClient) QueryCurrentCandidatePool(context.Context) (*hubv1.CandidatePoolSnapshotViewV1, error) {
	return nil, ErrNotFound
}

func (c *stubClient) QueryBuilderCompensationAccount(context.Context, string) (*hubv1.BuilderCompensationAccountState, error) {
	return nil, ErrNotFound
}

func (c *stubClient) QueryVrfKey(context.Context, string, string) (VrfKey, error) {
	return VrfKey{}, ErrNotFound
}

func (c *stubClient) QueryBeacon(context.Context, uint64) (*hubv1.BeaconState, error) {
	return nil, ErrNotFound
}
