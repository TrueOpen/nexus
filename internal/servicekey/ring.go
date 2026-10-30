package servicekey

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/signer"
)

// Key is one local service key and the authorization nonce the chain binds it to.
type Key struct {
	Signer signer.Signer
	Nonce  uint64
	// Revoked marks a generation the chain revoked: it still names what it signed before, but
	// authorizes nothing new, so its Signer refuses to sign (ErrRevoked).
	Revoked bool
}

// Signer is a service signer that also knows the authorization nonce the chain binds its key to:
// signed dispatch material (roots, tickets, records) carries that nonce. Key returns the key and
// its nonce as one snapshot.
type Signer interface {
	signer.Signer
	Key() Key
}

// Static is a Signer of one key bound to a fixed nonce.
func Static(s signer.Signer, nonce uint64) Signer { return static{Signer: s, nonce: nonce} }

type static struct {
	signer.Signer
	nonce uint64
}

func (s static) Key() Key { return Key{Signer: s.Signer, Nonce: s.nonce} }

// RingView is one read of the chain's BUILDER binding matched against the local keys. A Key whose
// Signer is nil is a generation the chain names but this process does not hold.
type RingView struct {
	// Current is the generation the chain holds current; its Signer is always local. While the
	// chain shows it revoked (Current.Revoked) its key and nonce stay here, but it signs nothing.
	Current Key
	// Previous is the generation the last cutover retired at PreviousRetiredHeight (0 without
	// one). It proves only material of orders below that height.
	Previous              Key
	PreviousRetiredHeight uint64
	// Next is a registered replacement that becomes current at NextEffectiveHeight (0 without
	// one), registered at NextRegisteredHeight.
	Next                                      Key
	NextRegisteredHeight, NextEffectiveHeight uint64
}

// Pending reports whether a replacement is registered and not active yet.
func (v RingView) Pending() bool { return v.NextEffectiveHeight != 0 }

// ErrNotRefreshed refuses a signature of a Ring that has not read the chain binding yet: none of
// its local keys is known to be current.
var ErrNotRefreshed = errors.New("service key ring has not read the chain binding yet")

// ErrRevoked refuses a signature of a Ring whose current key the chain revoked: a revoked key
// proves what it signed before and authorizes nothing new, and no other key may sign until the
// chain makes a replacement current.
var ErrRevoked = errors.New("this Builder's current service key is revoked")

// RevokedError is the Refresh error of a revoked current key: ErrRevoked (and ErrUnavailable) with
// the revoked generation's nonce and, when the operator registered a replacement, its nonce and the
// height from which it is current (0 without one).
type RevokedError struct {
	Nonce                          uint64
	NextNonce, NextEffectiveHeight uint64
}

func (e *RevokedError) Error() string {
	if e.NextEffectiveHeight == 0 {
		return fmt.Sprintf("%v (nonce %d); no replacement is registered", ErrRevoked, e.Nonce)
	}
	return fmt.Sprintf("%v (nonce %d); replacement nonce %d is current from height %d", ErrRevoked, e.Nonce, e.NextNonce, e.NextEffectiveHeight)
}

func (e *RevokedError) Unwrap() []error { return []error{ErrRevoked, ErrUnavailable} }

// refusing names a local key but signs nothing: the first local key before the first read
// (ErrNotRefreshed, since the operator may have left a retired key in that slot), or a revoked
// current key (ErrRevoked).
type refusing struct {
	signer.Signer
	err error
}

func (r refusing) Sign([]byte) ([]byte, error)         { return nil, r.err }
func (r refusing) SignDigest([32]byte) ([]byte, error) { return nil, r.err }

// localKey is the key a Key's Signer names, refusing or not.
func localKey(s signer.Signer) signer.Signer {
	if r, ok := s.(refusing); ok {
		return r.Signer
	}
	return s
}

// Ring holds this Builder's local BUILDER service keys and follows the chain binding: the local
// key the chain holds current signs everything, a registered replacement held locally takes over
// once the chain makes it current (no restart), and the retired key stays at hand for messages
// that must keep its nonce. Ring is a Signer of the current key as of the latest Refresh; before
// the first successful Refresh it signs nothing (ErrNotRefreshed), and while the chain shows the
// current key revoked it signs nothing either (ErrRevoked) until a replacement is current ACTIVE.
type Ring struct {
	resolver Resolver
	prefix   string
	operator string
	local    []signer.Signer
	onSwitch func(old, current Key)

	mu      sync.Mutex
	view    RingView
	fetched bool
	// revoked is the newest generation known revoked (0: none). A revoked generation never
	// becomes ACTIVE again, so a read showing it ACTIVE lags the revocation.
	revoked uint64
}

// NewRing builds a Ring over the local keys; none signs until the first successful Refresh.
// onSwitch, when set, is called after a Refresh or ObserveEvent changed the current generation:
// another local key or another nonce became current, or the current one was revoked.
func NewRing(resolver Resolver, addressPrefix, operator string, onSwitch func(old, current Key), local ...signer.Signer) (*Ring, error) {
	if len(local) == 0 || local[0] == nil {
		return nil, fmt.Errorf("service key ring needs a local key")
	}
	for i, key := range local[1:] {
		if key == nil || bytes.Equal(key.PubKeyCompressed(), local[0].PubKeyCompressed()) {
			return nil, fmt.Errorf("service key ring: extra key %d is missing or repeats the first", i+1)
		}
	}
	return &Ring{
		resolver: resolver, prefix: addressPrefix, operator: operator, local: local, onSwitch: onSwitch,
		view: RingView{Current: Key{Signer: refusing{local[0], ErrNotRefreshed}}},
	}, nil
}

// Refresh reads the chain binding and matches it against the local keys. The chain's current key
// must be ACTIVE, consistent and held locally (ErrUnavailable otherwise; ErrAuthority when the
// chain cannot answer). A failed Refresh keeps the previous view, except a revoked one: when the
// chain answers that its current key, held locally, is revoked, the view names that generation as
// revoked and Refresh returns it with a *RevokedError.
func (r *Ring) Refresh(ctx context.Context) (RingView, error) {
	publicKey, state, err := binding(ctx, r.resolver, r.prefix, ParticipantBuilder, r.operator)
	if err != nil {
		return RingView{}, err
	}
	current := r.find(publicKey)
	if current == nil {
		return RingView{}, fmt.Errorf("the chain's current BUILDER service key is not held locally: %w", ErrUnavailable)
	}
	if state.AuthorizationNonce == 0 {
		return RingView{}, fmt.Errorf("BUILDER service binding has no authorization nonce: %w", ErrUnavailable)
	}
	view := RingView{Current: Key{Signer: current, Nonce: state.AuthorizationNonce}}
	if p := state.Previous; p != nil {
		view.Previous = Key{Signer: r.findHex(p.ServicePubKey), Nonce: p.AuthorizationNonce}
		view.PreviousRetiredHeight = p.RetiredHeight
	}
	if p := state.PendingRotation; p != nil {
		view.Next = Key{Signer: r.findHex(p.NextServicePubKey), Nonce: p.NextAuthorizationNonce}
		view.NextRegisteredHeight, view.NextEffectiveHeight = p.RegisteredHeight, p.EffectiveHeight
	}
	r.mu.Lock()
	if state.Status == StatusRevoked || view.Current.Nonce <= r.revoked {
		if state.Status != StatusRevoked {
			// A read that lags the revocation still shows the rotation it cancelled.
			view.Next, view.NextRegisteredHeight, view.NextEffectiveHeight = Key{}, 0, 0
		}
		view.Current = revokedKey(view.Current)
		r.revoked = max(r.revoked, view.Current.Nonce)
	}
	old, fetched := r.view.Current, r.fetched
	r.view, r.fetched = view, true
	r.mu.Unlock()
	if fetched {
		r.switched(old, view.Current)
	}
	if view.Current.Revoked {
		return view, &RevokedError{Nonce: view.Current.Nonce, NextNonce: view.Next.Nonce, NextEffectiveHeight: view.NextEffectiveHeight}
	}
	return view, nil
}

// ObserveEvent takes this Builder's own SERVICE_KEY_REVOKED at once, without waiting for a read:
// from then on the ring signs nothing, and the pending rotation the revocation cancelled is
// dropped from the view. An event without a nonce revokes the generation the ring signs with; one
// before the first read is applied by that read. Other events, and revocations of other
// operators, of Cortex keys or of an older generation, change nothing.
func (r *Ring) ObserveEvent(ev chaincli.ChainEvent) {
	if ev.Type != chaincli.EventHubOperational || ev.EventCode != "SERVICE_KEY_REVOKED" {
		return
	}
	revocation, ok := ev.Typed.(chaincli.ServiceKeyRevoked)
	if !ok || revocation.ParticipantType != sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER || revocation.Operator != r.operator {
		return
	}
	r.mu.Lock()
	nonce := revocation.AuthorizationNonce
	if nonce == 0 {
		nonce = r.view.Current.Nonce
	}
	r.revoked = max(r.revoked, nonce)
	if !r.fetched || r.view.Current.Revoked || nonce < r.view.Current.Nonce {
		r.mu.Unlock()
		return
	}
	old := r.view.Current
	r.view.Current = revokedKey(old)
	r.view.Next, r.view.NextRegisteredHeight, r.view.NextEffectiveHeight = Key{}, 0, 0
	current := r.view.Current
	r.mu.Unlock()
	r.switched(old, current)
}

// revokedKey is k revoked: same key and nonce, signing nothing.
func revokedKey(k Key) Key {
	return Key{Signer: refusing{localKey(k.Signer), ErrRevoked}, Nonce: k.Nonce, Revoked: true}
}

// switched calls onSwitch when the current generation changed between old and current.
func (r *Ring) switched(old, current Key) {
	if r.onSwitch != nil && (localKey(old.Signer) != localKey(current.Signer) || old.Nonce != current.Nonce || old.Revoked != current.Revoked) {
		r.onSwitch(old, current)
	}
}

// Await refreshes until the first read succeeds, every interval, or ctx ends; it returns the last
// error then. It is the startup read that lets the ring sign before any other caller refreshes it.
// A revoked current key ends it too, with its *RevokedError: the chain answered, and waiting does
// not bring a replacement sooner (the next Refresh after the cutover finds it).
func (r *Ring) Await(ctx context.Context, interval time.Duration) error {
	for {
		_, err := r.Refresh(ctx)
		if err == nil || errors.Is(err, ErrRevoked) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(interval):
		}
	}
}

// View returns the latest view; ok is false before the first successful Refresh.
func (r *Ring) View() (RingView, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.view, r.fetched
}

// Holds reports whether a key (33-byte compressed, lowercase hex) is one of the local keys.
func (r *Ring) Holds(publicKey string) bool { return r.findHex(publicKey) != nil }

func (r *Ring) find(publicKey []byte) signer.Signer {
	for _, key := range r.local {
		if bytes.Equal(key.PubKeyCompressed(), publicKey) {
			return key
		}
	}
	return nil
}

func (r *Ring) findHex(publicKey string) signer.Signer {
	raw, err := hex.DecodeString(publicKey)
	if err != nil {
		return nil
	}
	return r.find(raw)
}

// Key implements Signer: the current key and nonce of the latest Refresh. Before the first one the
// nonce is 0 and the key refuses to sign (ErrNotRefreshed); while it is revoked it refuses to sign
// too (ErrRevoked).
func (r *Ring) Key() Key {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.view.Current
}

// PubKeyCompressed implements signer.Signer with the current key.
func (r *Ring) PubKeyCompressed() []byte { return r.Key().Signer.PubKeyCompressed() }

// Address implements signer.Signer with the current key.
func (r *Ring) Address() string { return r.Key().Signer.Address() }

// Sign implements signer.Signer with the current key.
func (r *Ring) Sign(msg []byte) ([]byte, error) { return r.Key().Signer.Sign(msg) }

// SignDigest implements signer.Signer with the current key.
func (r *Ring) SignDigest(digest [32]byte) ([]byte, error) { return r.Key().Signer.SignDigest(digest) }
