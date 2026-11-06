package handraise

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/lograte"
	"github.com/TrueOpen/nexus/internal/servicekey"
)

const reasonInvalid = taskv1.AdmitRejectReasonV1_ADMIT_REJECT_REASON_V1_INVALID_HANDRAISE

// IssuedRoot is one signed handraise root and its leaves in root order. It is shared between
// readers and must not be modified.
type IssuedRoot struct {
	Root   *taskv1.SignedHandraiseRootV1
	Leaves []*taskv1.HandraiseRootLeafV1
	// Digest is the handraise_root_digest: the signing digest of Root, which tickets bind and
	// which identifies the root in challenges.
	Digest      [32]byte
	leafDigests [][32]byte
}

// Notice returns the root with operator's own inclusion proof, for its dispatch stream. When the
// operator has both a held handraise and an invalid-handraise trace in this root, the proof is
// for the held one.
func (r *IssuedRoot) Notice(operator string) (*nexusv1.HandraiseRootNoticeV1, bool) {
	index := -1
	for i, leaf := range r.Leaves {
		if leaf.GetHandraise().GetMember().GetOperatorAddress() != operator {
			continue
		}
		if index < 0 || leaf.GetAdmitRejectReason() != reasonInvalid {
			index = i
		}
	}
	if index < 0 {
		return nil, false
	}
	proof, err := r.Proof(uint32(index))
	if err != nil {
		return nil, false
	}
	return &nexusv1.HandraiseRootNoticeV1{Root: r.Root, Proof: proof}, true
}

// Proof returns the inclusion proof of the leaf at index.
func (r *IssuedRoot) Proof(index uint32) (*taskv1.HandraiseInclusionProofV1, error) {
	siblings, err := dispatch.HandraiseProof(r.leafDigests, index)
	if err != nil {
		return nil, err
	}
	out := &taskv1.HandraiseInclusionProofV1{Leaf: r.Leaves[index], LeafIndex: index, Siblings: make([][]byte, len(siblings))}
	for i := range siblings {
		out.Siblings[i] = append([]byte(nil), siblings[i][:]...)
	}
	return out, nil
}

// IssueRoot signs a new root over the handraises held now, if the leaves changed since the latest
// root or the latest root is not signed by this Builder's current service key (the key was
// rotated), and returns it; otherwise it returns nil.
// root_height is the local chain height (never below the latest root's); root_version counts up
// from 0 within one root_height.
// While this Builder's own rotation is pending, roots are still signed by the current key: the
// orders already dispatched open their next rounds on them. Such a root carries a root_height
// below the effective height, so the retired key still proves it after the cutover; at or above
// that height the current key signs none (ErrBuilderCutoverUnseen) until the chain shows the
// replacement current.
func (r *Registry) IssueRoot(ctx context.Context) (*IssuedRoot, error) {
	r.issueMu.Lock()
	defer r.issueMu.Unlock()
	height, err := r.opts.Height.LatestHeight(ctx)
	if err != nil {
		return nil, fmt.Errorf("read chain height: %w", err)
	}
	var rotation *RotationPendingError
	if err := r.opts.Keys.CheckBuilderKey(ctx); err != nil && !errors.As(err, &rotation) {
		return nil, fmt.Errorf("check Builder service key: %w", err)
	}
	r.sampleRTT()
	pending, unusable, err := r.rotationsPending(ctx)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	last := r.latest
	if last != nil && height < last.Root.GetRootHeight() {
		height = last.Root.GetRootHeight()
	}
	if rotation != nil && height >= rotation.EffectiveHeight {
		r.mu.Unlock()
		return nil, fmt.Errorf("%w: root height %d, effective height %d", ErrBuilderCutoverUnseen, height, rotation.EffectiveHeight)
	}
	r.invalidateLocked(unusable)
	entries, traces := r.collectLocked(height, pending)
	r.mu.Unlock()

	leaves, digests, err := buildLeaves(entries)
	if err != nil {
		r.restoreTraces(traces)
		return nil, err
	}
	key := r.opts.Signer.Key()
	if last == nil && len(leaves) == 0 ||
		last != nil && signedBy(last, key) && equalDigests(last.leafDigests, digests) {
		return nil, nil
	}
	var version uint64
	if last != nil && height == last.Root.GetRootHeight() {
		version = last.Root.GetRootVersion() + 1
	}
	rootHash := dispatch.HandraiseRoot(digests)
	root := &taskv1.SignedHandraiseRootV1{
		ChainId:        r.opts.ChainID,
		BuilderAddress: r.opts.BuilderAddress,
		RootHeight:     height,
		RootVersion:    version,
		LeafCount:      uint32(len(leaves)),
		Root:           rootHash[:],
	}
	raw, digest, err := signRoot(key, root)
	if err != nil {
		r.restoreTraces(traces)
		return nil, err
	}
	issued := &IssuedRoot{Root: root, Leaves: leaves, Digest: digest, leafDigests: digests}
	if err := r.persistRoot(issued, raw); err != nil {
		r.restoreTraces(traces)
		return nil, err
	}
	r.mu.Lock()
	r.latest = issued
	r.mu.Unlock()
	return issued, nil
}

// signedBy reports whether issued is signed by key under its nonce: after a rotation the same
// leaves must be signed again by the new current key.
func signedBy(issued *IssuedRoot, key servicekey.Key) bool {
	return issued.Root.GetServiceAuthorizationNonce() == key.Nonce &&
		dispatch.VerifyDigestSignature(key.Signer.PubKeyCompressed(), issued.Digest[:], issued.Root.GetBuilderServiceSignature()) == nil
}

// holders lists the operators holding a handraise.
func (r *Registry) holders() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	operators := make([]string, 0, len(r.current))
	for operator := range r.current {
		operators = append(operators, operator)
	}
	return operators
}

// rotationsPending reads which operators holding a handraise have a pending CORTEX key rotation,
// and which have no usable CORTEX key at all (servicekey.ErrUnavailable: missing, not ACTIVE,
// revoked), the same verdict that refuses a new handraise. Any other failed read fails the root: a
// root that admits a pending Cortex, or refuses one that is not, is not signed on a guess.
func (r *Registry) rotationsPending(ctx context.Context) (pending map[string]bool, unusable map[string]error, err error) {
	pending, unusable = map[string]bool{}, map[string]error{}
	for _, operator := range r.holders() {
		effective, err := r.opts.Keys.CortexRotation(ctx, operator)
		switch {
		case errors.Is(err, servicekey.ErrUnavailable):
			unusable[operator] = err
		case err != nil:
			return nil, nil, fmt.Errorf("read CORTEX key rotation of %s: %w", operator, err)
		case effective != 0:
			pending[operator] = true
		}
	}
	return pending, unusable, nil
}

// invalidateLocked drops the current handraise of every operator whose CORTEX key is unusable and
// keeps it as that operator's INVALID_HANDRAISE trace for the next root (unless a newer trace is
// waiting), as Accept does with a handraise that fails verification. The watermark stays, so the
// dropped handraise cannot come back. unusable maps each operator to why. Caller holds r.mu.
func (r *Registry) invalidateLocked(unusable map[string]error) {
	var drop []string
	for operator, why := range unusable {
		h, ok := r.current[operator]
		if !ok {
			continue
		}
		delete(r.current, operator)
		drop = append(drop, currentKey(operator))
		if _, waiting := r.invalid[operator]; !waiting {
			r.invalid[operator] = h
		}
		if errors.Is(why, chaincli.ErrMalformedBinding) {
			r.log.Warn("handraise dropped: the chain's CORTEX binding of the holder is malformed", "operator", operator, "err", why)
		} else {
			r.log.Info("handraise dropped: the holder's CORTEX service key is unusable", "operator", operator, "err", why)
		}
	}
	r.deleteKeys(drop)
}

// sampleRTT records the measured RTT of every operator holding a handraise. An operator without a
// measurement keeps its last recorded one.
func (r *Registry) sampleRTT() {
	if r.opts.RTT == nil {
		return
	}
	for _, operator := range r.holders() {
		if rtt, ok := r.opts.RTT.RTT(operator); ok {
			r.RecordRTT(operator, uint64((rtt+time.Millisecond-1)/time.Millisecond))
		}
	}
}

// issueFailureLogEvery spaces out the log line of a root issuance failure that repeats every
// interval, such as a local signer that does not hold the on-chain Builder key.
const issueFailureLogEvery = time.Minute

// Run issues a root every handraise_root_interval_ms until ctx ends, handing each new root to
// onRoot (which pushes the notices to the dispatch streams).
func (r *Registry) Run(ctx context.Context, onRoot func(*IssuedRoot)) error {
	ticker := time.NewTicker(time.Duration(r.opts.Config.HandraiseRootIntervalMs) * time.Millisecond)
	defer ticker.Stop()
	paused := ""
	failures := lograte.Limiter{Every: issueFailureLogEvery}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		issued, err := r.IssueRoot(ctx)
		if why := pauseOf(err); why != "" {
			// Expected for the whole revocation, or until the cutover is read; say so once
			// instead of every interval.
			if why != paused {
				r.log.Info(why, "error", err)
			}
			paused = why
			continue
		}
		paused = ""
		if err != nil {
			if suppressed, ok := failures.Allow(r.now()); ok {
				r.log.Warn("issue handraise root", "error", err, "suppressed", suppressed)
			}
			continue
		}
		if issued != nil && onRoot != nil {
			onRoot(issued)
		}
	}
}

// pauseOf names the expected pause an IssueRoot error is, "" for any other: the effective height
// of this Builder's own rotation reached before the chain read shows the cutover, or its revoked
// current key, signs no root until it ends.
func pauseOf(err error) string {
	switch {
	case errors.Is(err, ErrBuilderCutoverUnseen):
		return "handraise roots wait until the chain shows the Builder service key cutover"
	case errors.Is(err, servicekey.ErrRevoked):
		return "handraise roots paused while this Builder's service key is revoked"
	}
	return ""
}

// Latest returns the latest signed root and its leaves. They are shared and must not be modified.
func (r *Registry) Latest() (*taskv1.SignedHandraiseRootV1, []*taskv1.HandraiseRootLeafV1, bool) {
	issued, ok := r.LatestRoot()
	if !ok {
		return nil, nil, false
	}
	return issued.Root, issued.Leaves, true
}

// LatestRoot returns the latest issued root.
func (r *Registry) LatestRoot() (*IssuedRoot, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.latest, r.latest != nil
}

// RootByDigest returns an issued root by its handraise_root_digest.
func (r *Registry) RootByDigest(digest [32]byte) (*IssuedRoot, bool, error) {
	if latest, ok := r.LatestRoot(); ok && latest.Digest == digest {
		return latest, true, nil
	}
	return r.loadRootByDigest(digest)
}

// entry is one handraise with its admission decision.
type entry struct {
	h        *held
	admitted bool
	reason   taskv1.AdmitRejectReasonV1
	rtt      uint64
}

// collectLocked drops expired handraises and ended suspensions, then returns every held handraise
// with its decision (rotationPending names the operators whose CORTEX key rotation is pending) and
// takes the pending invalid-handraise traces.
func (r *Registry) collectLocked(height uint64, rotationPending map[string]bool) ([]entry, map[string]*held) {
	var drop []string
	for operator, h := range r.current {
		if r.expiredLocked(h, height) {
			delete(r.current, operator)
			drop = append(drop, currentKey(operator))
		}
	}
	for operator, until := range r.suspended {
		if height >= until {
			delete(r.suspended, operator)
			drop = append(drop, suspensionKey(operator))
		}
	}
	r.deleteKeys(drop)

	entries := make([]entry, 0, len(r.current)+len(r.invalid))
	for operator, h := range r.current {
		admitted, reason, rtt := r.decisionLocked(operator, height, rotationPending[operator])
		entries = append(entries, entry{h: h, admitted: admitted, reason: reason, rtt: rtt})
	}
	traces := r.invalid
	r.invalid = map[string]*held{}
	for _, h := range traces {
		entries = append(entries, entry{h: h, reason: reasonInvalid})
	}
	return entries, traces
}

// restoreTraces puts back traces of a root that was not issued, unless newer ones arrived.
func (r *Registry) restoreTraces(traces map[string]*held) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for operator, h := range traces {
		if _, ok := r.invalid[operator]; !ok {
			r.invalid[operator] = h
		}
	}
}

// buildLeaves sorts entries by standing digest, keeps one leaf per digest (a held handraise wins
// over an invalid trace of the same content) and computes the leaf digests.
func buildLeaves(entries []entry) ([]*taskv1.HandraiseRootLeafV1, [][32]byte, error) {
	sort.Slice(entries, func(i, j int) bool {
		if c := bytes.Compare(entries[i].h.digest[:], entries[j].h.digest[:]); c != 0 {
			return c < 0
		}
		return entries[i].reason != reasonInvalid && entries[j].reason == reasonInvalid
	})
	leaves := make([]*taskv1.HandraiseRootLeafV1, 0, len(entries))
	digests := make([][32]byte, 0, len(entries))
	for i, e := range entries {
		if i > 0 && entries[i-1].h.digest == e.h.digest {
			continue
		}
		leaf := &taskv1.HandraiseRootLeafV1{
			Handraise: e.h.msg, Admitted: e.admitted, AdmitRejectReason: e.reason, BuilderMeasuredRttMs: e.rtt,
		}
		if e.admitted {
			leaf.AdmitRejectReason = taskv1.AdmitRejectReasonV1_ADMIT_REJECT_REASON_V1_NONE
		}
		digest, err := dispatch.HandraiseLeafDigest(e.h.digest, leaf.Admitted, uint32(leaf.AdmitRejectReason), leaf.BuilderMeasuredRttMs)
		if err != nil {
			return nil, nil, err
		}
		leaves = append(leaves, leaf)
		digests = append(digests, digest)
	}
	return leaves, digests, nil
}

// signRoot signs root under key, with key's authorization nonce, and returns its serialized bytes and its
// handraise_root_digest.
func signRoot(key servicekey.Key, root *taskv1.SignedHandraiseRootV1) ([]byte, [32]byte, error) {
	if key.Nonce == 0 {
		return nil, [32]byte{}, fmt.Errorf("sign handraise root: the service key has no authorization nonce yet")
	}
	root.ServiceAuthorizationNonce, root.BuilderServiceSignature = key.Nonce, nil
	unsigned, err := proto.MarshalOptions{Deterministic: true}.Marshal(root)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("encode handraise root: %w", err)
	}
	digest, err := dispatch.SigningDigest(rootName, unsigned)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("handraise root signing digest: %w", err)
	}
	sig, err := key.Signer.SignDigest(digest)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("sign handraise root: %w", err)
	}
	root.BuilderServiceSignature = sig
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(root)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("encode handraise root: %w", err)
	}
	return raw, digest, nil
}

// StandingDigest is the standing_handraise_digest of h: its wire signing digest.
func StandingDigest(h *taskv1.StandingHandraiseV1) ([32]byte, error) {
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(h)
	if err != nil {
		return [32]byte{}, err
	}
	return dispatch.SigningDigest(standingName, raw)
}

// LeafDigest is the Merkle leaf value of a handraise root leaf.
func LeafDigest(leaf *taskv1.HandraiseRootLeafV1) ([32]byte, error) {
	standing, err := StandingDigest(leaf.GetHandraise())
	if err != nil {
		return [32]byte{}, err
	}
	return dispatch.HandraiseLeafDigest(standing, leaf.GetAdmitted(), uint32(leaf.GetAdmitRejectReason()), leaf.GetBuilderMeasuredRttMs())
}

func equalDigests(a, b [][32]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
