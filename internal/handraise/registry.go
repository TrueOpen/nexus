// Package handraise is the standing handraise registry of direct dispatch.
//
// A Cortex node sends each Builder it serves a signed StandingHandraiseV1 over its dispatch stream:
// the profiles it can run and its free slots, valid until an expiry height and re-signed on a
// heartbeat. The registry verifies each handraise against the operator's current CORTEX service
// key and candidate pool eligibility, keeps exactly one current handraise per operator, and on a
// fixed interval signs a SignedHandraiseRootV1: a Merkle root over one admission leaf per handraise
// it holds, sorted by standing handraise digest. Every member gets the root with its own inclusion
// proof. A handraise that is held but not admitted (RTT over the public threshold, reject-rate
// suspension, or an invalid signature / eligibility) is still a leaf, so the decision is on record.
//
// Rosters are built from the latest root by the dispatcher; this package only exposes it.
package handraise

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/signer"
)

const (
	standingName = "task.v1.StandingHandraiseV1"
	rootName     = "task.v1.SignedHandraiseRootV1"

	standingSchemaVersion = 1
	signatureLen          = 64
)

// Stream error codes of a refused handraise. The text of each is the code the stream layer
// returns: ErrInvalid as InvalidArgument, ErrNotEligible as PermissionDenied. Any other error from
// Accept means the chain could not be read and the handraise may be sent again.
var (
	ErrInvalid     = errors.New("HANDRAISE_INVALID")
	ErrNotEligible = errors.New("HANDRAISE_NOT_ELIGIBLE")
)

// ServiceKeys reads current service keys from the chain.
type ServiceKeys interface {
	// CurrentCortexKey returns the operator's current ACTIVE CORTEX service public key (33-byte
	// compressed) and its authorization nonce. When it is determined that no usable key exists the
	// error wraps servicekey.ErrUnavailable; any other error means the chain could not be read.
	CurrentCortexKey(ctx context.Context, operator string) ([]byte, uint64, error)
	// CurrentBuilderNonce returns the authorization nonce of this Builder's current service key,
	// which must be the key the root signer holds.
	CurrentBuilderNonce(ctx context.Context) (uint64, error)
}

// CandidatePool answers candidate pool eligibility from the chain.
type CandidatePool interface {
	// IsEligibleMember reports whether member names the operator's slot in the current candidate
	// pool snapshot and that member is eligible for dispatch.
	IsEligibleMember(ctx context.Context, member *taskv1.CandidateMemberRefV1) (bool, error)
	// HasFreshSupport reports whether the operator holds a fresh declared support row for profile.
	HasFreshSupport(ctx context.Context, operator string, profile *taskv1.DispatchProfileV1) (bool, error)
}

// ChainHeight returns this Builder's latest observed chain height.
type ChainHeight interface {
	LatestHeight(ctx context.Context) (uint64, error)
}

// Options configures a Registry.
type Options struct {
	ChainID        string
	BuilderAddress string // this Builder's operator address
	Config         config.DispatchConfig
	Store          kv.Store
	Keys           ServiceKeys
	Pool           CandidatePool
	Height         ChainHeight
	// Signer holds this Builder's current service key; it signs every root.
	Signer signer.Signer
	// Now is the local clock of handraise TTLs; nil means time.Now.
	Now func() time.Time
	Log *slog.Logger
}

// Registry holds the current standing handraises and the issued handraise roots.
type Registry struct {
	opts Options
	now  func() time.Time
	log  *slog.Logger

	// issueMu serialises root issuance so (root_height, root_version) is never reused.
	issueMu sync.Mutex

	mu        sync.Mutex
	current   map[string]*held // operator -> current handraise
	invalid   map[string]*held // operator -> latest invalid handraise awaiting its trace leaf
	rtt       map[string]uint64
	outcomes  map[string][]outcome
	suspended map[string]uint64 // operator -> first height admitted again
	threshold RTTThresholdChange
	latest    *IssuedRoot
}

// held is one received handraise with the bytes it is stored and hashed as.
type held struct {
	msg        *taskv1.StandingHandraiseV1
	raw        []byte
	digest     [32]byte
	receivedAt time.Time
}

// New opens the registry and recovers its state from the store.
func New(opts Options) (*Registry, error) {
	switch {
	case opts.ChainID == "" || opts.BuilderAddress == "":
		return nil, fmt.Errorf("handraise registry needs the chain id and builder address")
	case opts.Store == nil || opts.Keys == nil || opts.Pool == nil || opts.Height == nil || opts.Signer == nil:
		return nil, fmt.Errorf("handraise registry needs a store, service keys, candidate pool, chain height and signer")
	}
	if err := opts.Config.Validate(); err != nil {
		return nil, err
	}
	r := &Registry{
		opts:      opts,
		now:       opts.Now,
		log:       opts.Log,
		current:   map[string]*held{},
		invalid:   map[string]*held{},
		rtt:       map[string]uint64{},
		outcomes:  map[string][]outcome{},
		suspended: map[string]uint64{},
	}
	if r.now == nil {
		r.now = time.Now
	}
	if r.log == nil {
		r.log = slog.Default()
	}
	if err := r.recover(); err != nil {
		return nil, fmt.Errorf("recover handraise registry: %w", err)
	}
	return r, nil
}

// Accept takes a standing handraise received on operator's authenticated dispatch stream.
//
// A malformed, foreign, expired, replayed or too frequent handraise is refused with ErrInvalid and
// leaves no trace. One that is well formed but fails its signature, the current key binding or
// eligibility is refused with ErrInvalid or ErrNotEligible and becomes an INVALID_HANDRAISE leaf of
// the next root; it never replaces the operator's current handraise. Resending the current
// handraise is accepted without effect.
func (r *Registry) Accept(ctx context.Context, operator string, h *taskv1.StandingHandraiseV1) error {
	got, err := r.checkShape(operator, h)
	if err != nil {
		return err
	}
	height, err := r.opts.Height.LatestHeight(ctx)
	if err != nil {
		return fmt.Errorf("read chain height: %w", err)
	}
	if h.GetExpiryHeight() < height || h.GetIssuedHeight() > height+1 {
		return fmt.Errorf("%w: handraise issued at %d expiring at %d is outside chain height %d",
			ErrInvalid, h.GetIssuedHeight(), h.GetExpiryHeight(), height)
	}
	if done, err := r.checkOrder(operator, got); done || err != nil {
		return err
	}
	if err := r.verify(ctx, operator, got); err != nil {
		if errors.Is(err, ErrInvalid) || errors.Is(err, ErrNotEligible) {
			r.mu.Lock()
			r.invalid[operator] = got
			r.mu.Unlock()
		}
		return err
	}
	return r.store(operator, got)
}

// Current returns operator's current handraise, if it has one that has not expired.
func (r *Registry) Current(operator string) (*taskv1.StandingHandraiseV1, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	h, ok := r.current[operator]
	if !ok || r.expiredLocked(h, 0) {
		return nil, false
	}
	return h.msg, true
}

// checkShape validates everything that needs no chain read and computes the standing digest.
func (r *Registry) checkShape(operator string, h *taskv1.StandingHandraiseV1) (*held, error) {
	switch {
	case h == nil || h.GetMember() == nil:
		return nil, fmt.Errorf("%w: handraise without a member", ErrInvalid)
	case h.GetSchemaVersion() != standingSchemaVersion:
		return nil, fmt.Errorf("%w: schema_version %d", ErrInvalid, h.GetSchemaVersion())
	case h.GetChainId() != r.opts.ChainID:
		return nil, fmt.Errorf("%w: handraise for chain %q", ErrInvalid, h.GetChainId())
	case h.GetBuilderAddress() != r.opts.BuilderAddress:
		return nil, fmt.Errorf("%w: handraise addressed to another Builder", ErrInvalid)
	case h.GetMember().GetOperatorAddress() != operator:
		return nil, fmt.Errorf("%w: handraise member is not the stream operator", ErrInvalid)
	case h.GetExpiryHeight() < h.GetIssuedHeight():
		return nil, fmt.Errorf("%w: expiry_height before issued_height", ErrInvalid)
	case h.GetServiceAuthorizationNonce() == 0:
		return nil, fmt.Errorf("%w: handraise without service_authorization_nonce", ErrInvalid)
	case len(h.GetServiceSignature()) != signatureLen:
		return nil, fmt.Errorf("%w: service_signature must be %d bytes", ErrInvalid, signatureLen)
	case len(h.GetProfiles()) == 0:
		return nil, fmt.Errorf("%w: handraise without profiles", ErrInvalid)
	}
	for i := 1; i < len(h.GetProfiles()); i++ {
		if compareProfiles(h.GetProfiles()[i-1], h.GetProfiles()[i]) >= 0 {
			return nil, fmt.Errorf("%w: profiles must be in strictly ascending (model_id, profile_version) order", ErrInvalid)
		}
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(h)
	if err != nil {
		return nil, fmt.Errorf("%w: encode handraise: %v", ErrInvalid, err)
	}
	digest, err := dispatch.SigningDigest(standingName, raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return &held{msg: proto.Clone(h).(*taskv1.StandingHandraiseV1), raw: raw, digest: digest, receivedAt: r.now()}, nil
}

// checkOrder applies replay protection and the re-sign rate against the current handraise.
// done reports an exact resend of the current handraise, which needs nothing further.
func (r *Registry) checkOrder(operator string, got *held) (done bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cur, ok := r.current[operator]
	if !ok {
		return false, nil
	}
	if cur.digest == got.digest {
		return true, nil
	}
	if !newer(got.msg, cur.msg) {
		return false, fmt.Errorf("%w: handraise (%d, %d) is not newer than the current (%d, %d)", ErrInvalid,
			got.msg.GetIssuedHeight(), got.msg.GetHandraiseNonce(), cur.msg.GetIssuedHeight(), cur.msg.GetHandraiseNonce())
	}
	// Half the minimum change interval tolerates jitter between the Cortex clock and arrival.
	minGap := time.Duration(r.opts.Config.HandraiseMinChangeIntervalMs) * time.Millisecond / 2
	if got.receivedAt.Sub(cur.receivedAt) < minGap {
		return false, fmt.Errorf("%w: handraise re-signed faster than handraise_min_change_interval_ms", ErrInvalid)
	}
	return false, nil
}

// verify checks the signature under the operator's current CORTEX key and pool eligibility.
func (r *Registry) verify(ctx context.Context, operator string, got *held) error {
	pub, nonce, err := r.opts.Keys.CurrentCortexKey(ctx, operator)
	if errors.Is(err, servicekey.ErrUnavailable) {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err != nil {
		return fmt.Errorf("read current CORTEX service key: %w", err)
	}
	if got.msg.GetServiceAuthorizationNonce() != nonce {
		return fmt.Errorf("%w: service_authorization_nonce %d is not the current %d", ErrInvalid,
			got.msg.GetServiceAuthorizationNonce(), nonce)
	}
	if err := dispatch.VerifyDigestSignature(pub, got.digest[:], got.msg.GetServiceSignature()); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	member, err := r.opts.Pool.IsEligibleMember(ctx, got.msg.GetMember())
	if err != nil {
		return fmt.Errorf("read candidate pool: %w", err)
	}
	if !member {
		return fmt.Errorf("%w: operator is not an eligible candidate pool member", ErrNotEligible)
	}
	for _, profile := range got.msg.GetProfiles() {
		fresh, err := r.opts.Pool.HasFreshSupport(ctx, operator, profile)
		if err != nil {
			return fmt.Errorf("read profile support: %w", err)
		}
		if !fresh {
			return fmt.Errorf("%w: no fresh support for model %x profile %d", ErrNotEligible,
				profile.GetModelId(), profile.GetProfileVersion())
		}
	}
	return nil
}

// store makes got the operator's current handraise, unless a newer one won meanwhile.
func (r *Registry) store(operator string, got *held) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur, ok := r.current[operator]; ok {
		if cur.digest == got.digest {
			return nil
		}
		if !newer(got.msg, cur.msg) {
			return fmt.Errorf("%w: a newer handraise was accepted meanwhile", ErrInvalid)
		}
	}
	if err := r.persistCurrent(operator, got); err != nil {
		return err
	}
	r.current[operator] = got
	return nil
}

// expiredLocked reports whether h passed its TTL, or its expiry height when height is non-zero.
func (r *Registry) expiredLocked(h *held, height uint64) bool {
	ttl := time.Duration(r.opts.Config.HandraiseTTLMs) * time.Millisecond
	return r.now().Sub(h.receivedAt) > ttl || height != 0 && h.msg.GetExpiryHeight() < height
}

// newer orders handraises of one member by (issued_height, handraise_nonce).
func newer(a, b *taskv1.StandingHandraiseV1) bool {
	if a.GetIssuedHeight() != b.GetIssuedHeight() {
		return a.GetIssuedHeight() > b.GetIssuedHeight()
	}
	return a.GetHandraiseNonce() > b.GetHandraiseNonce()
}

func compareProfiles(a, b *taskv1.DispatchProfileV1) int {
	if c := bytes.Compare(a.GetModelId(), b.GetModelId()); c != 0 {
		return c
	}
	switch {
	case a.GetProfileVersion() < b.GetProfileVersion():
		return -1
	case a.GetProfileVersion() > b.GetProfileVersion():
		return 1
	}
	return 0
}
