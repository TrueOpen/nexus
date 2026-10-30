package servicekey

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/TrueOpen/nexus/internal/signer"
)

// Key is one local service key and the authorization nonce the chain binds it to.
type Key struct {
	Signer signer.Signer
	Nonce  uint64
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
	// Current is the generation the chain holds current; its Signer is always local.
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

// unrefreshed is the first local key before the first read: it names the key but signs nothing,
// since the operator may have left a retired key in that slot.
type unrefreshed struct{ signer.Signer }

func (unrefreshed) Sign([]byte) ([]byte, error)         { return nil, ErrNotRefreshed }
func (unrefreshed) SignDigest([32]byte) ([]byte, error) { return nil, ErrNotRefreshed }

// Ring holds this Builder's local BUILDER service keys and follows the chain binding: the local
// key the chain holds current signs everything, a registered replacement held locally takes over
// once the chain makes it current (no restart), and the retired key stays at hand for messages
// that must keep its nonce. Ring is a Signer of the current key as of the latest Refresh; before
// the first successful Refresh it signs nothing (ErrNotRefreshed).
type Ring struct {
	resolver Resolver
	prefix   string
	operator string
	local    []signer.Signer
	onSwitch func(old, current Key)

	mu      sync.Mutex
	view    RingView
	fetched bool
}

// NewRing builds a Ring over the local keys; none signs until the first successful Refresh.
// onSwitch, when set, is called after a Refresh found another local key, or another nonce, current.
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
		view: RingView{Current: Key{Signer: unrefreshed{local[0]}}},
	}, nil
}

// Refresh reads the chain binding and matches it against the local keys. The chain's current key
// must be ACTIVE, consistent and held locally (ErrUnavailable otherwise; ErrAuthority when the
// chain cannot answer). A failed Refresh keeps the previous view.
func (r *Ring) Refresh(ctx context.Context) (RingView, error) {
	publicKey, state, err := Current(ctx, r.resolver, r.prefix, ParticipantBuilder, r.operator)
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
	old, fetched := r.view.Current, r.fetched
	r.view, r.fetched = view, true
	r.mu.Unlock()
	if fetched && r.onSwitch != nil && (old.Signer != view.Current.Signer || old.Nonce != view.Current.Nonce) {
		r.onSwitch(old, view.Current)
	}
	return view, nil
}

// Await refreshes until the first read succeeds, every interval, or ctx ends; it returns the last
// error then. It is the startup read that lets the ring sign before any other caller refreshes it.
func (r *Ring) Await(ctx context.Context, interval time.Duration) error {
	for {
		_, err := r.Refresh(ctx)
		if err == nil {
			return nil
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
// nonce is 0 and the key refuses to sign (ErrNotRefreshed).
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
