package taskdata

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/signer"
)

// evidenceScopeFixture adds two more round-1 Verifiers and two round-2 Verifiers to the
// authorizer fixture. fx.verifier stays the first round-1 Verifier.
type evidenceScopeFixture struct {
	*authorizerFixture
	peer        signer.Signer // second round-1 Verifier
	challenger  signer.Signer // round-2 Verifier
	challenger2 signer.Signer // second round-2 Verifier
	nonce       byte
}

func newEvidenceScopeFixture(t *testing.T) *evidenceScopeFixture {
	t.Helper()
	fx := &evidenceScopeFixture{
		authorizerFixture: newAuthorizerFixture(t),
		peer:              testSigner(t, 20),
		challenger:        testSigner(t, 21),
		challenger2:       testSigner(t, 22),
	}
	for _, s := range []signer.Signer{fx.peer, fx.challenger, fx.challenger2} {
		fx.authority.setServiceKey(participantServiceKey(participantTypeCortex, s.Address(), s))
	}
	fx.authority.task.VerifierRounds = []chaincli.VerifierRound{{
		VerifyRound: 1, Verifiers: []string{fx.verifier.Address(), fx.peer.Address()}, CommitDeadlineHeight: 150,
	}}
	return fx
}

// openRound2 selects the round-2 committee; its commit deadline is still ahead at height 100.
func (fx *evidenceScopeFixture) openRound2() {
	fx.authority.task.VerifierRounds = append(fx.authority.task.VerifierRounds, chaincli.VerifierRound{
		VerifyRound: 2, Verifiers: []string{fx.challenger.Address(), fx.challenger2.Address()}, CommitDeadlineHeight: 300,
	})
}

func (fx *evidenceScopeFixture) round(n uint32) *chaincli.VerifierRound {
	for i := range fx.authority.task.VerifierRounds {
		if fx.authority.task.VerifierRounds[i].VerifyRound == n {
			return &fx.authority.task.VerifierRounds[i]
		}
	}
	return nil
}

func verifierBundle(operator string, round uint32) ObjectRef {
	return ObjectRef{
		TaskHash: testTaskHash, SessionID: testSessionID, TaskID: testTaskID,
		Kind: ObjectKindEvidenceManifest, ContentHash: strings.Repeat("c", 64),
		EvidenceProducerKind: EvidenceProducerVerifier, VerifyRound: round, ProducerOperator: operator,
	}
}

func (fx *evidenceScopeFixture) fetch(t *testing.T, caller signer.Signer, key ObjectRef) error {
	t.Helper()
	digest, err := TaskDataFetchBodyDigest(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	fx.nonce++
	request := fx.fixtureRequest(t, caller, MethodFetch, key, digest[:], fx.nonce, fx.authority.height+10)
	_, err = fx.authorizer.AuthorizeFetch(context.Background(), request, nil)
	return err
}

func (fx *evidenceScopeFixture) inspect(t *testing.T, caller signer.Signer, metadata *Metadata) error {
	t.Helper()
	fx.nonce++
	request := fx.fixtureRequest(t, caller, MethodGetMetadata, metadata.Key, nil, fx.nonce, fx.authority.height+10)
	return fx.authorizer.AuthorizeMetadata(context.Background(), request, metadata)
}

func expectAccess(t *testing.T, label string, err error, allowed bool) {
	t.Helper()
	if allowed && err != nil {
		t.Fatalf("%s: %v, want allowed", label, err)
	}
	if !allowed && !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("%s: %v, want ErrUnauthorized", label, err)
	}
}

// A Verifier never reads another Verifier's bundle of its own round, before or after that round's
// commits are locked: once reveal starts the bundle adds nothing a Verifier needs, and before it
// the bundle is exactly what commit-reveal exists to hide.
func TestVerifierCannotReadSameRoundPeerEvidence(t *testing.T) {
	fx := newEvidenceScopeFixture(t)
	own, peer := verifierBundle(fx.verifier.Address(), 1), verifierBundle(fx.peer.Address(), 1)

	expectAccess(t, "own bundle", fx.fetch(t, fx.verifier, own), true)
	expectAccess(t, "peer bundle before commits locked", fx.fetch(t, fx.verifier, peer), false)
	peerMeta := Metadata{Key: peer}
	expectAccess(t, "peer bundle metadata", fx.inspect(t, fx.verifier, &peerMeta), false)

	fx.round(1).RevealDeadlineHeight = 200
	expectAccess(t, "peer bundle after reveal started", fx.fetch(t, fx.verifier, peer), false)
	fx.authority.height = 151
	expectAccess(t, "peer bundle after commit deadline", fx.fetch(t, fx.verifier, peer), false)

	// The Worker bundle is the input of every verification and stays readable.
	expectAccess(t, "worker bundle", fx.fetch(t, fx.verifier, fx.metadata[ObjectKindEvidenceManifest].Key), true)
	// A Verifier ref without producer_operator cannot be shown to be the requester's own.
	expectAccess(t, "unnamed same-round bundle", fx.fetch(t, fx.verifier, verifierBundle("", 1)), false)
}

// A round-2 Verifier reads round-1 Verifier bundles only after round 2's commits are locked,
// by either signal the chain gives: reveal has started, or the commit deadline has passed.
func TestPriorRoundEvidenceOpensOnlyAfterCommitsLocked(t *testing.T) {
	for _, tt := range []struct {
		name string
		lock func(fx *evidenceScopeFixture)
	}{
		{"reveal started", func(fx *evidenceScopeFixture) { fx.round(2).RevealDeadlineHeight = 320 }},
		{"commit deadline passed", func(fx *evidenceScopeFixture) { fx.authority.height = 301 }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fx := newEvidenceScopeFixture(t)
			fx.openRound2()
			prior := verifierBundle(fx.verifier.Address(), 1)
			expectAccess(t, "prior-round bundle before lock", fx.fetch(t, fx.challenger, prior), false)
			priorMeta := Metadata{Key: prior}
			expectAccess(t, "prior-round metadata before lock", fx.inspect(t, fx.challenger, &priorMeta), false)
			// The commit deadline itself is still inside the commit window.
			fx.authority.height = 300
			expectAccess(t, "prior-round bundle at the deadline", fx.fetch(t, fx.challenger, prior), false)
			fx.authority.height = 100

			tt.lock(fx)
			expectAccess(t, "prior-round bundle after lock", fx.fetch(t, fx.challenger, prior), true)
			priorMeta = Metadata{Key: prior}
			expectAccess(t, "prior-round metadata after lock", fx.inspect(t, fx.challenger, &priorMeta), true)
			// Round 2 is still a same-round pair after the lock.
			expectAccess(t, "round-2 peer bundle after lock",
				fx.fetch(t, fx.challenger, verifierBundle(fx.challenger2.Address(), 2)), false)
		})
	}
}

func TestRound2VerifierReadsTaskDataAndOwnBundle(t *testing.T) {
	fx := newEvidenceScopeFixture(t)
	fx.openRound2()
	for _, kind := range []ObjectKind{ObjectKindInput, ObjectKindOutput, ObjectKindEvidenceManifest} {
		expectAccess(t, fmt.Sprintf("round-2 kind %d", kind), fx.fetch(t, fx.challenger, fx.metadata[kind].Key), true)
	}
	expectAccess(t, "round-2 own bundle", fx.fetch(t, fx.challenger, verifierBundle(fx.challenger.Address(), 2)), true)
	// A round-1 Verifier gains nothing from round 2, locked or not.
	fx.round(2).RevealDeadlineHeight = 320
	expectAccess(t, "round-1 verifier reads round-2 bundle",
		fx.fetch(t, fx.verifier, verifierBundle(fx.challenger.Address(), 2)), false)
}

// Nobody outside the Verifier committees reads a Verifier bundle, and an unselected candidate
// reads no evidence at all and no per-chunk OUTPUT layout.
func TestNonVerifiersCannotReadVerifierEvidence(t *testing.T) {
	fx := newEvidenceScopeFixture(t)
	fx.round(1).RevealDeadlineHeight = 200
	bundle := verifierBundle(fx.verifier.Address(), 1)
	for _, caller := range []struct {
		name string
		s    signer.Signer
	}{{"worker", fx.worker}, {"user", fx.user}, {"candidate", fx.candidate}, {"unrelated", fx.other}} {
		expectAccess(t, caller.name+" verifier bundle", fx.fetch(t, caller.s, bundle), false)
		meta := Metadata{Key: bundle}
		expectAccess(t, caller.name+" verifier bundle metadata", fx.inspect(t, caller.s, &meta), false)
	}
	expectAccess(t, "candidate worker bundle", fx.fetch(t, fx.candidate, fx.metadata[ObjectKindEvidenceManifest].Key), false)
}

func TestCandidateOutputMetadataOmitsChunkLengths(t *testing.T) {
	fx := newEvidenceScopeFixture(t)
	streamed := func() Metadata {
		meta := fx.metadata[ObjectKindOutput]
		meta.ChunkLengths = []uint32{3, 5, 8}
		meta.OutputLeafCount = 3
		return meta
	}
	candidateView := streamed()
	expectAccess(t, "candidate output metadata", fx.inspect(t, fx.candidate, &candidateView), true)
	if candidateView.ChunkLengths != nil {
		t.Fatalf("candidate got chunk_lengths %v", candidateView.ChunkLengths)
	}
	for _, caller := range []struct {
		name string
		s    signer.Signer
	}{{"verifier", fx.verifier}, {"worker", fx.worker}, {"user", fx.user}} {
		view := streamed()
		expectAccess(t, caller.name+" output metadata", fx.inspect(t, caller.s, &view), true)
		if len(view.ChunkLengths) != 3 {
			t.Fatalf("%s lost chunk_lengths: %v", caller.name, view.ChunkLengths)
		}
	}
}

// A Verifier uploads its bundle only under a round it was selected in.
func TestVerifierUploadsOnlyItsOwnRound(t *testing.T) {
	fx := newEvidenceScopeFixture(t)
	fx.openRound2()
	permissions, err := permissionsFor(fx.authority.task, fx.verifier.Address(), fx.authority.height)
	if err != nil {
		t.Fatal(err)
	}
	if !permissions.canUpload(verifierBundle(fx.verifier.Address(), 1), fx.verifier.Address()) {
		t.Fatal("round-1 verifier cannot upload its round-1 bundle")
	}
	if permissions.canUpload(verifierBundle(fx.verifier.Address(), 2), fx.verifier.Address()) {
		t.Fatal("round-1 verifier uploaded a round-2 bundle")
	}
}
