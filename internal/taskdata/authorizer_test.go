package taskdata

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

const (
	testChainID = "trueopen-task-test"
	// All three Hash32 values are canonical lowercase 64-hex: the object ref and the §5.14 preimage
	// both need the raw 32 bytes, so the fixture can no longer use a placeholder like "session-1".
	testTaskID    = "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a"
	testSessionID = "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"
	testTaskHash  = "3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c"
	testContent   = "4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d"
	// A second Task: the capacity and tombstone cases need two different objects.
	testOtherTaskID = "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e"
	testBuilder     = "trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man"
	// The numeric chainId of the EIP-712 domain: the USER path requires it and the chain_id string to
	// match at the same time.
	testEVMChainID = uint64(424242)
)

type fakeAuthority struct {
	height uint64
	task   chaincli.OnChainTask
	// keys is keyed by "<participant type>|<operator address>"; an unregistered combination returns
	// chaincli.ErrNotFound — querying the wrong participant type must find nothing and must not fall
	// back to another one.
	keys map[string]chaincli.ServiceKeyState
	// profile is the locked Verification Profile; it is returned only when the key matches, and
	// querying the wrong (model, version) must be NotFound.
	profile chaincli.ProfileState
	err     error
}

func (f *fakeAuthority) LatestHeight(context.Context) (uint64, error) {
	if f.err != nil {
		return 0, f.err
	}
	return f.height, nil
}

func (f *fakeAuthority) QueryTask(context.Context, chaincli.TaskKey) (chaincli.OnChainTask, error) {
	if f.err != nil {
		return chaincli.OnChainTask{}, f.err
	}
	return f.task, nil
}

func (f *fakeAuthority) QueryCurrentServiceKey(_ context.Context, participantType, operator string) (chaincli.ServiceKeyState, error) {
	if f.err != nil {
		return chaincli.ServiceKeyState{}, f.err
	}
	state, found := f.keys[participantType+"|"+operator]
	if !found {
		return chaincli.ServiceKeyState{}, chaincli.ErrNotFound
	}
	return state, nil
}

func (f *fakeAuthority) QueryProfile(_ context.Context, modelID string, profileVersion uint32) (chaincli.ProfileState, error) {
	if f.err != nil {
		return chaincli.ProfileState{}, f.err
	}
	if f.profile.ModelID != modelID || f.profile.ProfileVersion != profileVersion {
		return chaincli.ProfileState{}, chaincli.ErrNotFound
	}
	return f.profile, nil
}

func (f *fakeAuthority) setServiceKey(state chaincli.ServiceKeyState) {
	if f.keys == nil {
		f.keys = map[string]chaincli.ServiceKeyState{}
	}
	f.keys[state.ParticipantType+"|"+state.OperatorAddress] = state
}

type authorizerFixture struct {
	authority *fakeAuthority
	backend   kv.Store
	service   signer.Signer
	worker    signer.Signer
	verifier  signer.Signer
	user      signer.Signer
	candidate signer.Signer
	other     signer.Signer
	// workerService / verifierService are the current service keys these two Cortex Nodes registered
	// under the CORTEX participant type — different keys from their operator keys, which is exactly
	// what this group of tests distinguishes.
	workerService   signer.Signer
	verifierService signer.Signer
	metadata        map[ObjectKind]Metadata
	authorizer      *Authorizer
}

type rejectReplayScanStore struct {
	kv.Store
}

func (s rejectReplayScanStore) Scan(namespace kv.Namespace, fn func(string, []byte) bool) error {
	if namespace == kv.NSTaskDataReplay {
		return errors.New("live replay namespace must use point lookups")
	}
	return s.Store.Scan(namespace, fn)
}

func newAuthorizerFixture(t *testing.T) *authorizerFixture {
	t.Helper()
	service := testSigner(t, 10)
	worker := testSigner(t, 11)
	verifier := testSigner(t, 12)
	user := testSigner(t, 13)
	candidate := testSigner(t, 14)
	other := testSigner(t, 15)
	workerService := testSigner(t, 16)
	verifierService := testSigner(t, 17)
	workerSet, err := nodecontract.CanonicalWorkerHandraiseSet([]nodecontract.WorkerHandraiseV1{{
		SchemaVersion: nodecontract.WorkerHandraiseSchemaV1, WorkerOperatorAddress: candidate.Address(),
		TaskID: testTaskID, TaskHash: "task-hash", CandidateSnapshotID: "snapshot",
		ExpiryHeight: 200, ServiceSignature: "signature",
	}})
	if err != nil {
		t.Fatal(err)
	}
	verifierCandidates, err := nodecontract.CanonicalVerifierHandraiseList([]nodecontract.VerifierHandraiseV1{{
		SchemaVersion: nodecontract.VerifierHandraiseSchemaV1, VerifierOperatorAddress: candidate.Address(),
		TaskID: testTaskID, InferReceiptHash: strings.Repeat("1", 64), OutputHash: strings.Repeat("2", 64),
		CandidateSnapshotID: "snapshot", MembershipProof: "proof", ExpiryHeight: 200, ServiceSignature: "signature",
	}})
	if err != nil {
		t.Fatal(err)
	}
	authority := &fakeAuthority{
		height: 100,
		task: chaincli.OnChainTask{
			SessionID: testSessionID, TaskID: testTaskID, Verifiers: []string{verifier.Address()},
			Assignment: chaincli.TaskAssignmentState{
				UserAddress: ethAddressOf(t, user), SelectedWorkerOperatorAddress: worker.Address(), WorkerHandraiseSet: workerSet,
			},
			VerifierAssignment: chaincli.VerifierAssignmentState{VerifierHandraiseList: verifierCandidates},
		},
	}
	setServiceKey(authority, service)
	// The current service keys of Worker / Verifier are registered under the CORTEX participant type —
	// WORKER / VERIFIER are sender_roles, not participant types, and do not exist on chain.
	authority.setServiceKey(participantServiceKey(participantTypeCortex, worker.Address(), workerService))
	authority.setServiceKey(participantServiceKey(participantTypeCortex, verifier.Address(), verifierService))
	// The candidate and the unrelated party are Cortex Nodes too: they also authenticate with their
	// own service key, and they are rejected by authorization (the on-chain role), not by the
	// signature check — the two must stay distinguishable.
	authority.setServiceKey(participantServiceKey(participantTypeCortex, candidate.Address(), candidate))
	authority.setServiceKey(participantServiceKey(participantTypeCortex, other.Address(), other))
	backend := kv.NewMemStore()
	a, err := NewAuthorizer(AuthorizerConfig{
		ChainID: testChainID, EVMChainID: testEVMChainID, BuilderAddress: testBuilder, AddressPrefix: "trueopen",
		RequestTTLBlocks: 20, RetentionLeaseBlocks: 50,
	}, backend, authority, service)
	if err != nil {
		t.Fatal(err)
	}
	return &authorizerFixture{
		authority: authority, backend: backend, service: service, worker: worker, verifier: verifier,
		user: user, candidate: candidate, other: other, authorizer: a,
		workerService: workerService, verifierService: verifierService,
		metadata: map[ObjectKind]Metadata{
			ObjectKindInput: readyMetadata(ObjectKindInput), ObjectKindOutput: readyMetadata(ObjectKindOutput),
			ObjectKindEvidenceManifest: readyMetadata(ObjectKindEvidenceManifest),
		},
	}
}

func TestAuthorizerPermissionMatrix(t *testing.T) {
	fx := newAuthorizerFixture(t)
	tests := []struct {
		name     string
		caller   signer.Signer
		kind     ObjectKind
		metadata bool
		download bool
		upload   bool
	}{
		{name: "candidate input metadata only", caller: fx.candidate, kind: ObjectKindInput, metadata: true},
		{name: "candidate output metadata only", caller: fx.candidate, kind: ObjectKindOutput, metadata: true},
		{name: "selected worker input", caller: fx.worker, kind: ObjectKindInput, metadata: true, download: true},
		{name: "selected worker output", caller: fx.worker, kind: ObjectKindOutput, metadata: true, upload: true},
		{name: "selected worker evidence", caller: fx.worker, kind: ObjectKindEvidenceManifest, metadata: true, upload: true},
		{name: "formal verifier input", caller: fx.verifier, kind: ObjectKindInput, metadata: true, download: true},
		{name: "formal verifier output", caller: fx.verifier, kind: ObjectKindOutput, metadata: true, download: true},
		// The manifest in the fixture is a Worker bundle: a Verifier can read it but cannot upload it
		// in the Worker's name.
		{name: "formal verifier evidence", caller: fx.verifier, kind: ObjectKindEvidenceManifest, metadata: true, download: true},
		{name: "original user output", caller: fx.user, kind: ObjectKindOutput, metadata: true, download: true},
		{name: "original user input denied", caller: fx.user, kind: ObjectKindInput},
		{name: "unrelated caller denied", caller: fx.other, kind: ObjectKindOutput},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := fx.metadata[tt.kind]
			request := fx.fixtureRequest(t, tt.caller, MethodGetMetadata, meta.Key, nil, byte(i+1), 110)
			err := fx.authorizer.AuthorizeMetadata(context.Background(), request, &meta)
			if tt.metadata {
				if err != nil {
					t.Fatalf("metadata: %v", err)
				}
			} else if !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("metadata error = %v, want ErrUnauthorized", err)
			}

			// Authorization compares the requester declared in the request: the ordering user is an
			// eth_secp256k1 account, so its on-chain address is the keccak-derived one, not the Cortex
			// one.
			requester := tt.caller.Address()
			if requester == fx.user.Address() {
				requester = ethAddressOf(t, tt.caller)
			}
			permissions, err := permissionsFor(fx.authority.task, requester, fx.authority.height)
			if err != nil {
				t.Fatal(err)
			}
			if got := permissions.canDownload(tt.kind); got != tt.download {
				t.Fatalf("download permission = %t, want %t", got, tt.download)
			}
			if got := permissions.canUpload(meta.Key, requester); got != tt.upload {
				t.Fatalf("upload permission = %t, want %t", got, tt.upload)
			}
		})
	}
}

// Upload rights for an evidence bundle are decided by the producer in the ref: the manifest and the
// artifacts follow the same rule, Worker and Verifier can each upload only their own producer_kind,
// and producer_operator, when given, must be the requester itself.
// canUpload previously allowed no EVIDENCE_ARTIFACT at all, so Cortex got stuck on the first artifact
// right after uploading the OUTPUT.
func TestCanUploadEvidenceByProducer(t *testing.T) {
	fx := newAuthorizerFixture(t)
	worker, verifier := fx.worker.Address(), fx.verifier.Address()
	key := func(kind ObjectKind, producer EvidenceProducerKind, operator string) ObjectRef {
		return ObjectRef{TaskHash: testTaskHash, SessionID: testSessionID, TaskID: testTaskID, Kind: kind,
			ContentHash: strings.Repeat("a", 64), EvidenceProducerKind: producer, VerifyRound: 1, ProducerOperator: operator}
	}
	for _, tt := range []struct {
		name      string
		requester string
		key       ObjectRef
		want      bool
	}{
		{"worker manifest", worker, key(ObjectKindEvidenceManifest, EvidenceProducerWorker, worker), true},
		{"worker artifact", worker, key(ObjectKindEvidenceArtifact, EvidenceProducerWorker, worker), true},
		{"worker artifact without operator", worker, key(ObjectKindEvidenceArtifact, EvidenceProducerWorker, ""), true},
		{"verifier manifest", verifier, key(ObjectKindEvidenceManifest, EvidenceProducerVerifier, verifier), true},
		{"verifier artifact", verifier, key(ObjectKindEvidenceArtifact, EvidenceProducerVerifier, verifier), true},
		{"worker posing as verifier", worker, key(ObjectKindEvidenceArtifact, EvidenceProducerVerifier, worker), false},
		{"verifier posing as worker", verifier, key(ObjectKindEvidenceManifest, EvidenceProducerWorker, verifier), false},
		{"worker under another operator", worker, key(ObjectKindEvidenceArtifact, EvidenceProducerWorker, verifier), false},
		{"verifier uploads output", verifier, key(ObjectKindOutput, EvidenceProducerUnspecified, ""), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			permissions, err := permissionsFor(fx.authority.task, tt.requester, fx.authority.height)
			if err != nil {
				t.Fatal(err)
			}
			if got := permissions.canUpload(tt.key, tt.requester); got != tt.want {
				t.Fatalf("canUpload = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestAuthorizerRequestValidationReplayAndOutage(t *testing.T) {
	t.Run("signature and bindings", func(t *testing.T) {
		fx := newAuthorizerFixture(t)
		meta := fx.metadata[ObjectKindInput]
		valid := fx.fixtureRequest(t, fx.worker, MethodGetMetadata, meta.Key, nil, 1, 110)
		badSignature := valid
		badSignature.Signature = append([]byte(nil), valid.Signature...)
		badSignature.Signature[0] ^= 1
		if err := fx.authorizer.AuthorizeMetadata(context.Background(), badSignature, &meta); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("bad signature error = %v", err)
		}
		crossChain := valid
		crossChain.ChainID = "other-chain"
		if err := fx.authorizer.AuthorizeMetadata(context.Background(), crossChain, &meta); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("cross-chain error = %v", err)
		}
		// The object ref enters the body digest: change any field of the ref and the body_digest the
		// caller claims no longer matches the one we recompute from the new ref. Here only the ref is
		// swapped, keeping the original signature and body_digest.
		crossKind := valid
		crossKind.Key = fx.metadata[ObjectKindOutput].Key
		if err := fx.authorizer.AuthorizeMetadata(context.Background(), crossKind, &meta); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("cross-kind error = %v", err)
		}
	})

	t.Run("expiry replay and ttl", func(t *testing.T) {
		fx := newAuthorizerFixture(t)
		meta := fx.metadata[ObjectKindInput]
		expired := fx.fixtureRequest(t, fx.worker, MethodGetMetadata, meta.Key, nil, 1, 99)
		if err := fx.authorizer.AuthorizeMetadata(context.Background(), expired, &meta); !errors.Is(err, ErrExpired) {
			t.Fatalf("expired error = %v", err)
		}
		tooFar := fx.fixtureRequest(t, fx.worker, MethodGetMetadata, meta.Key, nil, 2, 121)
		if err := fx.authorizer.AuthorizeMetadata(context.Background(), tooFar, &meta); !errors.Is(err, ErrExpired) {
			t.Fatalf("ttl error = %v", err)
		}
		valid := fx.fixtureRequest(t, fx.worker, MethodGetMetadata, meta.Key, nil, 3, 110)
		if err := fx.authorizer.AuthorizeMetadata(context.Background(), valid, &meta); err != nil {
			t.Fatal(err)
		}
		if err := fx.authorizer.AuthorizeMetadata(context.Background(), valid, &meta); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("replay error = %v", err)
		}
	})

	t.Run("authority outage fails closed", func(t *testing.T) {
		fx := newAuthorizerFixture(t)
		meta := fx.metadata[ObjectKindInput]
		fx.authority.err = errors.New("node offline")
		request := fx.fixtureRequest(t, fx.worker, MethodGetMetadata, meta.Key, nil, 4, 110)
		if err := fx.authorizer.AuthorizeMetadata(context.Background(), request, &meta); !errors.Is(err, ErrAuthorityUnavailable) {
			t.Fatalf("outage error = %v", err)
		}
	})
}

func TestAuthorizerReplaySurvivesRestart(t *testing.T) {
	fx := newAuthorizerFixture(t)
	meta := fx.metadata[ObjectKindInput]
	request := fx.fixtureRequest(t, fx.worker, MethodGetMetadata, meta.Key, nil, 31, 110)
	if err := fx.authorizer.AuthorizeMetadata(context.Background(), request, &meta); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewAuthorizer(fx.authorizer.cfg, fx.backend, fx.authority, fx.service)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.AuthorizeMetadata(context.Background(), request, &meta); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("replayed request after restart error = %v", err)
	}
}

func TestAuthorizerReplayCheckDoesNotScanLiveNonceRecords(t *testing.T) {
	fx := newAuthorizerFixture(t)
	guarded := rejectReplayScanStore{Store: fx.backend}
	authorizer, err := NewAuthorizer(fx.authorizer.cfg, guarded, fx.authority, fx.service)
	if err != nil {
		t.Fatal(err)
	}
	metadata := fx.metadata[ObjectKindInput]
	request := fx.fixtureRequest(t, fx.worker, MethodGetMetadata, metadata.Key, nil, 32, 110)
	if err := authorizer.AuthorizeMetadata(context.Background(), request, &metadata); err != nil {
		t.Fatalf("first request: %v", err)
	}
	if err := authorizer.AuthorizeMetadata(context.Background(), request, &metadata); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("replayed request error = %v", err)
	}
}

func TestAuthorizerOpenTaskHeightAndReplaySurviveRestart(t *testing.T) {
	fx := newAuthorizerFixture(t)
	ctx := context.Background()
	if err := fx.authorizer.AuthorizeOpenTaskRequest(ctx, fx.user.Address(), bytes.Repeat([]byte{1}, 16), 99); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired OpenTask error = %v", err)
	}
	if err := fx.authorizer.AuthorizeOpenTaskRequest(ctx, fx.user.Address(), bytes.Repeat([]byte{2}, 16), 121); !errors.Is(err, ErrExpired) {
		t.Fatalf("overlong OpenTask error = %v", err)
	}
	nonce := bytes.Repeat([]byte{3}, 16)
	if err := fx.authorizer.AuthorizeOpenTaskRequest(ctx, fx.user.Address(), nonce, 110); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewAuthorizer(fx.authorizer.cfg, fx.backend, fx.authority, fx.service)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.AuthorizeOpenTaskRequest(ctx, fx.user.Address(), nonce, 110); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("replayed OpenTask after restart error = %v", err)
	}
}

// Contract §2.2: a range request is self-signed, authorization looks only at on-chain roles and
// there are no pre-signed download credentials any more, so rotating the Builder service key no
// longer affects downloads already in flight.
func TestAuthorizeFetchReplayAndRoleChange(t *testing.T) {
	fx := newAuthorizerFixture(t)
	meta := fx.metadata[ObjectKindInput]
	rangeRequestRange := &ByteRange{Offset: 0, Length: 64}
	rangeRequest := fx.fixtureFetch(t, fx.worker, meta.Key, rangeRequestRange, 2, 110)
	if _, err := fx.authorizer.AuthorizeFetch(context.Background(), rangeRequest, rangeRequestRange); err != nil {
		t.Fatalf("authorize download: %v", err)
	}
	restarted, err := NewAuthorizer(fx.authorizer.cfg, fx.backend, fx.authority, fx.service)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.AuthorizeFetch(context.Background(), rangeRequest, rangeRequestRange); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("range replay error = %v", err)
	}

	roleChangedRange := &ByteRange{Offset: 0, Length: 64}
	roleChanged := fx.fixtureFetch(t, fx.worker, meta.Key, roleChangedRange, 3, 110)
	fx.authority.task.Assignment.SelectedWorkerOperatorAddress = fx.other.Address()
	if _, err := fx.authorizer.AuthorizeFetch(context.Background(), roleChanged, roleChangedRange); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("changed role error = %v", err)
	}
	fx.authority.task.Assignment.SelectedWorkerOperatorAddress = fx.worker.Address()

	// The request is bound to the object ref: after switching to another object the same signature
	// must become invalid — object_kind is the 4th field of the ref, so it enters the body digest and
	// therefore the request signature.
	crossKindRange := &ByteRange{Offset: 0, Length: 64}
	crossKind := fx.fixtureFetch(t, fx.worker, meta.Key, crossKindRange, 4, 110)
	crossKind.Key = fx.metadata[ObjectKindOutput].Key
	if _, err := fx.authorizer.AuthorizeFetch(context.Background(), crossKind, crossKindRange); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("cross-kind range error = %v", err)
	}

	// A caller that was not selected cannot download even with a valid signature.
	unrelatedRange := &ByteRange{Offset: 0, Length: 64}
	unrelated := fx.fixtureFetch(t, fx.other, meta.Key, unrelatedRange, 5, 110)
	if _, err := fx.authorizer.AuthorizeFetch(context.Background(), unrelated, unrelatedRange); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unrelated caller error = %v", err)
	}
}

// §6.3a: the storage confirmation is issued after the data is ready and covers the object ref
// itself; the signature is made over the digest directly.
func TestSignStorageConfirmation(t *testing.T) {
	fx := newAuthorizerFixture(t)
	output := fx.metadata[ObjectKindOutput]
	confirmation, err := fx.authorizer.SignStorageConfirmation(context.Background(), output, 0)
	if err != nil {
		t.Fatalf("sign confirmation: %v", err)
	}
	if confirmation.SchemaVersion != StorageConfirmationSchemaVersionV1 || confirmation.ChainID != testChainID ||
		confirmation.Ref != output.Key || confirmation.SizeBytes != output.SizeBytes ||
		confirmation.BuilderOperator != testBuilder || confirmation.RetentionUntilHeight != output.RetainUntilHeight {
		t.Fatalf("unexpected confirmation: %#v", confirmation)
	}
	if confirmation.ServiceAuthorizationNonce == 0 {
		t.Fatal("confirmation must carry the non-zero nonce of the currently ACTIVE service binding")
	}
	if confirmation.ArtifactTotalSizeBytes != 0 {
		t.Fatal("OUTPUT confirmation must not carry artifact_total_size_bytes")
	}
	digest, err := BuilderStorageConfirmationDigest(confirmation)
	if err != nil {
		t.Fatal(err)
	}
	if !signer.VerifyDigestSig(fx.service.PubKeyCompressed(), digest[:], confirmation.Signature) {
		t.Fatal("confirmation signature must verify under the current Builder service key")
	}

	// The confirmation of an EVIDENCE_MANIFEST carries the checked sum of the artifact sizes in the
	// bundle.
	evidence := fx.metadata[ObjectKindEvidenceManifest]
	evidenceConfirmation, err := fx.authorizer.SignStorageConfirmation(context.Background(), evidence, 4096)
	if err != nil {
		t.Fatalf("sign evidence confirmation: %v", err)
	}
	if evidenceConfirmation.Ref != evidence.Key || evidenceConfirmation.ArtifactTotalSizeBytes != 4096 {
		t.Fatalf("unexpected evidence confirmation: %#v", evidenceConfirmation)
	}

	// No confirmation may be issued for an object that is not ready.
	prepared := output
	prepared.State = StatePrepared
	if _, err := fx.authorizer.SignStorageConfirmation(context.Background(), prepared, 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("prepared object confirmation error = %v", err)
	}
}

func TestAuthorizerRejectsServiceSignerMismatch(t *testing.T) {
	fx := newAuthorizerFixture(t)
	meta := fx.metadata[ObjectKindOutput]
	wrong := testSigner(t, 40)
	a, err := NewAuthorizer(AuthorizerConfig{
		ChainID: testChainID, EVMChainID: testEVMChainID, BuilderAddress: testBuilder, AddressPrefix: "trueopen",
		RequestTTLBlocks: 20, RetentionLeaseBlocks: 50,
	}, fx.backend, fx.authority, wrong)
	if err != nil {
		t.Fatal(err)
	}
	// The storage confirmation must be signed with the current Builder service key on the Hub
	// (contract §5): when the local signer does not match the chain it must fail closed. The fetch
	// path no longer issues credentials, so a signer mismatch is visible only when a confirmation is
	// issued.
	if _, err := a.SignStorageConfirmation(context.Background(), meta, 0); !errors.Is(err, ErrServiceKeyUnavailable) {
		t.Fatalf("signer mismatch error = %v", err)
	}
	if err := fx.authorizer.AuthorizeMetadata(context.Background(),
		fx.fixtureRequest(t, fx.worker, MethodGetMetadata, meta.Key, nil, 1, 110), &meta); err != nil {
		t.Fatalf("metadata path must not depend on the Builder service key: %v", err)
	}
}

func TestAuthorizerValidatesOutputReceipt(t *testing.T) {
	fx := newAuthorizerFixture(t)
	meta := fx.metadata[ObjectKindOutput]
	receipt := validReceipt(t, fx, meta)
	header := UploadHeader{
		Key: meta.Key, SizeBytes: meta.SizeBytes, SemanticHash: meta.SemanticHash,
		MediaType: meta.MediaType, Receipt: &receipt,
	}
	digest, err := UploadBodyDigest(header)
	if err != nil {
		t.Fatal(err)
	}
	request := fx.fixtureRequest(t, fx.worker, MethodUpload, meta.Key, digest[:], 1, 110)
	if acceptedHash, _, err := fx.authorizer.AuthorizeUploadObject(context.Background(), request, header); err != nil || acceptedHash != "" {
		t.Fatalf("pre-chain receipt upload = %q, %v", acceptedHash, err)
	}

	tampered := header
	tamperedReceipt := receipt
	tamperedReceipt.OutputSizeBytes++
	tampered.Receipt = &tamperedReceipt
	tamperedDigest, err := UploadBodyDigest(tampered)
	if err != nil {
		t.Fatal(err)
	}
	tamperedRequest := fx.fixtureRequest(t, fx.worker, MethodUpload, meta.Key, tamperedDigest[:], 2, 110)
	if _, _, err := fx.authorizer.AuthorizeUploadObject(context.Background(), tamperedRequest, tampered); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("tampered receipt error = %v", err)
	}

	// The on-chain InferReceiptState still has its pre-freeze shape (rewriting the node's keeper/query
	// belongs to the Task slice): only facts whose meaning is unchanged on both sides can be compared,
	// see receiptMatchesChain.
	fx.authority.task.InferReceipt = chaincli.InferReceiptState{
		WorkerOperatorAddress: receipt.WorkerOperatorAddress, OutputHash: receipt.OutputHash,
		ServiceSignature: receipt.ServiceSignature, AcceptedItemHash: "accepted-hash",
	}
	acceptedRequest := fx.fixtureRequest(t, fx.worker, MethodUpload, meta.Key, digest[:], 3, 110)
	if acceptedHash, _, err := fx.authorizer.AuthorizeUploadObject(context.Background(), acceptedRequest, header); err != nil || acceptedHash != "accepted-hash" {
		t.Fatalf("accepted receipt match: %q, %v", acceptedHash, err)
	}
	fx.authority.task.InferReceipt.OutputHash = strings.Repeat("f", 64)
	mismatchRequest := fx.fixtureRequest(t, fx.worker, MethodUpload, meta.Key, digest[:], 4, 110)
	if _, _, err := fx.authorizer.AuthorizeUploadObject(context.Background(), mismatchRequest, header); !errors.Is(err, ErrConflict) {
		t.Fatalf("accepted receipt mismatch error = %v", err)
	}
}

func TestAuthorizerDerivesAcceptedReceiptHashFromCurrentChainState(t *testing.T) {
	fx := newAuthorizerFixture(t)
	metadata := fx.metadata[ObjectKindOutput]
	receipt := validReceipt(t, fx, metadata)
	metadata.Receipt = &receipt
	fx.authority.task.InferReceipt = chaincli.InferReceiptState{
		WorkerOperatorAddress: receipt.WorkerOperatorAddress, OutputHash: receipt.OutputHash,
		ServiceSignature: receipt.ServiceSignature, AcceptedItemHash: "accepted-current",
	}
	request := fx.fixtureRequest(t, fx.verifier, MethodGetMetadata, metadata.Key, nil, 41, 110)
	if err := fx.authorizer.AuthorizeMetadata(context.Background(), request, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.AcceptedReceiptHash != "accepted-current" {
		t.Fatalf("accepted receipt hash = %q", metadata.AcceptedReceiptHash)
	}
}

func TestAuthorizerReportsDeletedMetadata(t *testing.T) {
	fx := newAuthorizerFixture(t)
	metadata := fx.metadata[ObjectKindInput]
	metadata.State = ""
	metadata.RetentionStatus = RetentionDeleted
	request := fx.fixtureRequest(t, fx.worker, MethodGetMetadata, metadata.Key, nil, 42, 110)
	if err := fx.authorizer.AuthorizeMetadata(context.Background(), request, &metadata); err != nil {
		t.Fatalf("deleted metadata: %v", err)
	}
}

func TestServicePersistsAuthorizedUploader(t *testing.T) {
	fx := newAuthorizerFixture(t)
	store, _, _ := newTestStore(t, manifestStoreConfig())
	service, err := NewService(store, fx.authorizer)
	if err != nil {
		t.Fatal(err)
	}
	// The content_hash of an EVIDENCE_MANIFEST is the evidence_bundle_hash and the bytes must be a
	// canonical manifest — arbitrary bytes can no longer get through this path.
	ref := ObjectKey{
		TaskHash: testTaskHash, SessionID: testSessionID, TaskID: testTaskID, Kind: ObjectKindEvidenceManifest,
		EvidenceProducerKind: EvidenceProducerVerifier, VerifyRound: 1, ProducerOperator: fx.verifier.Address(),
	}
	body := buildManifest(t, ref, strings.Repeat("7", 64), []EvidenceArtifact{{
		ArtifactID: "aggregate_proof", ContentHash: strings.Repeat("6", 64), SizeBytes: 487,
	}})
	bundle := EvidenceBundleHash(body)
	ref.ContentHash = hex.EncodeToString(bundle[:])
	header := UploadHeader{
		Key:       ref,
		SizeBytes: uint64(len(body)), SemanticHash: ref.ContentHash, MediaType: "application/json",
	}
	bodyDigest, err := UploadBodyDigest(header)
	if err != nil {
		t.Fatal(err)
	}
	request := fx.fixtureRequest(t, fx.verifier, MethodUpload, header.Key, bodyDigest[:], 8, 110)
	upload, err := service.BeginUpload(context.Background(), request, header)
	if err != nil {
		t.Fatal(err)
	}
	if err := upload.WriteChunk(body[:4]); err != nil {
		t.Fatal(err)
	}
	if err := upload.WriteChunk(body[4:]); err != nil {
		t.Fatal(err)
	}
	metadata, err := service.CommitUpload(context.Background(), upload)
	if err != nil {
		t.Fatal(err)
	}
	// An upload commits only up to STORED: READY and the storage confirmation both wait for Finalize
	// (§5.5).
	if metadata.State != StateStored {
		t.Fatalf("state = %s, want STORED", metadata.State)
	}
	if metadata.Uploader != fx.verifier.Address() {
		t.Fatalf("uploader = %q, want %q", metadata.Uploader, fx.verifier.Address())
	}
}

func TestServiceRejectsDownloadWhenChainAcceptsDifferentOutputReceipt(t *testing.T) {
	fx := newAuthorizerFixture(t)
	store, _, _ := newTestStore(t, testStoreConfig())
	service, err := NewService(store, fx.authorizer)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("abcdefgh")
	header := testHeader(body)
	header.Key.Kind = ObjectKindOutput
	header.Uploader = fx.worker.Address()
	receiptMetadata := Metadata{Key: header.Key, SemanticHash: header.SemanticHash, SizeBytes: header.SizeBytes}
	receipt := validReceipt(t, fx, receiptMetadata)
	header.Receipt = &receipt
	metadata := prepareObject(t, store, header, body)
	if _, err := store.MarkReady(context.Background(), metadata.Key); err != nil {
		t.Fatal(err)
	}

	request := fx.fixtureRequest(t, fx.verifier, MethodGetMetadata, metadata.Key, nil, 61, 110)
	if _, found, err := service.GetMetadata(context.Background(), request); err != nil || !found {
		t.Fatalf("pre-chain metadata found = %t, err = %v", found, err)
	}
	fx.authority.task.InferReceipt = chaincli.InferReceiptState{
		WorkerOperatorAddress: receipt.WorkerOperatorAddress, OutputHash: receipt.OutputHash,
		ServiceSignature: receipt.ServiceSignature, AcceptedItemHash: "accepted-receipt",
	}
	rangeRequestRange := &ByteRange{Offset: 0, Length: 4}
	rangeRequest := fx.fixtureFetch(t, fx.verifier, metadata.Key, rangeRequestRange, 62, 110)
	reader, _, _, err := service.OpenFetch(context.Background(), rangeRequest, rangeRequestRange)
	if err != nil {
		t.Fatalf("download after matching chain acceptance: %v", err)
	}
	if downloaded, readErr := io.ReadAll(reader); readErr != nil || !bytes.Equal(downloaded, body[:4]) {
		t.Fatalf("downloaded output = %q, %v", downloaded, readErr)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}

	fx.authority.task.InferReceipt.OutputHash = strings.Repeat("f", 64)
	fx.authority.task.InferReceipt.AcceptedItemHash = "different-accepted-receipt"
	rangeRequestRange = &ByteRange{Offset: 0, Length: 4}
	rangeRequest = fx.fixtureFetch(t, fx.verifier, metadata.Key, rangeRequestRange, 63, 110)
	reader, _, _, err = service.OpenFetch(context.Background(), rangeRequest, rangeRequestRange)
	if reader != nil {
		_ = reader.Close()
	}
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("download after conflicting chain acceptance error = %v", err)
	}
	// The metadata path must reject as well once the chain has accepted a different receipt.
	metadataRequest := fx.fixtureRequest(t, fx.verifier, MethodGetMetadata, metadata.Key, nil, 64, 110)
	if _, _, err := service.GetMetadata(context.Background(), metadataRequest); !errors.Is(err, ErrConflict) {
		t.Fatalf("metadata after conflicting chain acceptance error = %v", err)
	}
}

// Since wire v0.4.1 the upload body digest is TRUEOPEN_TASK_DATA_UPLOAD_BODY_V1, committing to
// object_ref, size and media_type; the receipt no longer enters the upload body — it is committed by
// the body domain of FinalizeTaskResult. This test pins the new commitment scope: changing any of the
// three must change the digest, while changing the receipt must not.
func TestUploadBodyDigestBindsRefSizeAndMediaType(t *testing.T) {
	fx := newAuthorizerFixture(t)
	meta := fx.metadata[ObjectKindOutput]
	receipt := validReceipt(t, fx, meta)
	base := UploadHeader{
		Key: meta.Key, SizeBytes: meta.SizeBytes, SemanticHash: meta.SemanticHash,
		MediaType: meta.MediaType, Receipt: &receipt,
	}
	want, err := UploadBodyDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*UploadHeader){
		"size":       func(h *UploadHeader) { h.SizeBytes++ },
		"media type": func(h *UploadHeader) { h.MediaType = "text/plain" },
		"task hash":  func(h *UploadHeader) { h.Key.TaskHash = strings.Repeat("9", 64) },
		"verify round": func(h *UploadHeader) {
			h.Key.Kind = ObjectKindEvidenceManifest
			h.Key.EvidenceProducerKind = EvidenceProducerWorker
			h.Key.VerifyRound = 2
		},
	} {
		t.Run(name, func(t *testing.T) {
			header := base
			mutate(&header)
			got, err := UploadBodyDigest(header)
			if err != nil {
				t.Fatal(err)
			}
			if got == want {
				t.Fatalf("%s is not covered by the upload body digest", name)
			}
		})
	}

	// The receipt does not enter the upload body: changing it must not affect the digest.
	withOtherReceipt := base
	other := receipt
	other.ExpiryHeight++
	withOtherReceipt.Receipt = &other
	got, err := UploadBodyDigest(withOtherReceipt)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatal("receipt must not enter the upload body digest — it is committed by FinalizeTaskResult")
	}
}

func readyMetadata(kind ObjectKind) Metadata {
	// A different content hash per kind; the ref's content_hash and SemanticHash must be the same
	// value.
	contentHash := strings.Repeat(fmt.Sprintf("%x", byte(kind)), 64)
	key := ObjectKey{
		TaskHash: testTaskHash, SessionID: testSessionID, TaskID: testTaskID,
		Kind: kind, ContentHash: contentHash,
	}
	if kind == ObjectKindEvidenceManifest {
		key.EvidenceProducerKind = EvidenceProducerWorker
		key.VerifyRound = 1
	}
	return Metadata{
		Key: key, SemanticHash: contentHash, SizeBytes: 1024,
		MediaType: "application/octet-stream", State: StateReady, RetentionStatus: RetentionActive, RetainUntilHeight: 180,
	}
}

func testSigner(t *testing.T, value byte) signer.Signer {
	t.Helper()
	raw := make([]byte, 32)
	raw[31] = value
	s, err := signer.NewFromBytes(raw, "trueopen")
	if err != nil {
		t.Fatal(err)
	}
	testKeys.Lock()
	testKeys.byAddress[s.Address()] = raw
	testKeys.Unlock()
	return s
}

// testKeys remembers the private key of every test signer for fixtures that need to "sign the digest
// directly": the Signer interface only offers Sign(preimage), while a frozen digest must be signed
// without further hashing.
var testKeys = struct {
	sync.Mutex
	byAddress map[string][]byte
}{byAddress: map[string][]byte{}}

func setServiceKey(authority *fakeAuthority, service signer.Signer) {
	authority.setServiceKey(participantServiceKey(participantTypeBuilder, testBuilder, service))
}

func participantServiceKey(participantType, operator string, service signer.Signer) chaincli.ServiceKeyState {
	return chaincli.ServiceKeyState{
		ParticipantType: participantType, OperatorAddress: operator, ServiceAddress: service.Address(),
		ServicePubKey: hex.EncodeToString(service.PubKeyCompressed()), AuthorizationNonce: 1,
		UpdatedHeight: 100, Status: "ACTIVE",
	}
}

// validReceipt models the contract: the receipt records the Worker's operator address, but the
// service_signature is issued by that Node's current service key under the CORTEX participant type.
func validReceipt(t *testing.T, fx *authorizerFixture, metadata Metadata) SignedInferReceipt {
	t.Helper()
	return receiptSignedBy(t, fx.worker.Address(), fx.workerService, metadata)
}

// receiptSignedBy builds a receipt in the frozen §5.14 shape and signs the H_FIELDS_V1 digest
// (nodecontract.InferReceiptSigningDigest; the old 11-field decimal preimage was removed).
func receiptSignedBy(t *testing.T, workerOperator string, service signer.Signer, metadata Metadata) SignedInferReceipt {
	t.Helper()
	receipt := SignedInferReceipt{
		SchemaVersion: nodecontract.InferReceiptSchemaVersionV2, ChainID: testChainID,
		TaskID: metadata.Key.TaskID, TaskHash: strings.Repeat("a", 64),
		WorkerOperatorAddress: workerOperator, ServiceAuthorizationNonce: 7,
		GenerationParamsDigest: strings.Repeat("b", 64), OutputHash: metadata.SemanticHash,
		OutputSizeBytes: metadata.SizeBytes,
		EvidenceCommitments: []EvidenceCommitment{{
			Kind:             uint32(sharedv1.EvidenceKind_EVIDENCE_KIND_WORKER_VALUE_OPENING),
			HashOrRoot:       strings.Repeat("c", 64),
			EncodedSizeBytes: 4096,
		}},
		ExpiryHeight: 1200,
		// Start with a placeholder signature of a valid shape so that the 64-byte check in
		// receiptSubmission passes; the digest does not cover service_signature, so replacing it with
		// the real signature afterwards does not change the digest.
		ServiceSignature: strings.Repeat("0", 128),
	}
	digest, err := receiptDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	// Sign the digest directly, with no further hashing — this is the convention of both the chain's
	// VerifyStrictSecp256k1Digest and the Cortex signer. Using service.Sign(digest) would add another
	// hashing layer, and such a fixture would only verify nexus's own wrong algorithm.
	receipt.ServiceSignature = hex.EncodeToString(signDigestForTest(t, service, digest[:]))
	return receipt
}

// signDigestForTest reproduces the Worker-side signature over the frozen digest: the digest is the
// ECDSA message.
func signDigestForTest(t *testing.T, service signer.Signer, digest []byte) []byte {
	t.Helper()
	testKeys.Lock()
	raw, ok := testKeys.byAddress[service.Address()]
	testKeys.Unlock()
	if !ok {
		t.Fatalf("signer %s was not built by testSigner, its private key is unavailable", service.Address())
	}
	priv := secp256k1.PrivKeyFromBytes(raw)
	sig := ecdsa.Sign(priv, digest)
	r, s := sig.R(), sig.S()
	rb, sb := r.Bytes(), s.Bytes()
	out := make([]byte, 64)
	copy(out[:32], rb[:])
	copy(out[32:], sb[:])
	return out
}

// fixtureRequest picks the path from the caller's real identity: an operator with a registered
// CORTEX service key signs with that service key, and everyone else (the original User, unrelated
// parties) uses the USER EIP-712 path.
// This is the shape of the production path — the fixture should not have a third "operator
// self-signing" shortcut.
func (f *authorizerFixture) fixtureRequest(
	t *testing.T, caller signer.Signer, method RequestMethod, key ObjectKey, body []byte, nonce byte, expiry uint64,
) RequestAuth {
	t.Helper()
	// The body of a metadata request is the object ref itself; when the fixture is passed nil it fills
	// it in per the contract, so that every call site does not have to write it out.
	if body == nil && method == MethodGetMetadata {
		digest, err := TaskDataMetadataBodyDigest(key)
		if err != nil {
			t.Fatal(err)
		}
		body = digest[:]
	}
	switch caller.Address() {
	case f.worker.Address():
		return signedRequestAs(t, f.worker.Address(), f.workerService, method, key, body, nonce, expiry)
	case f.verifier.Address():
		return signedRequestAs(t, f.verifier.Address(), f.verifierService, method, key, body, nonce, expiry)
	case f.user.Address():
		// Only the ordering user is an eth_secp256k1 account and uses EIP-712; everyone else is a
		// Cortex Node.
		return userSignedRequest(t, caller, method, key, body, nonce, expiry)
	default:
		return signedRequestAs(t, caller.Address(), caller, method, key, body, nonce, expiry)
	}
}

// ethAddressOf derives the address the eth_secp256k1 way: the last 20 bytes of
// keccak(uncompressed public key). This is what the USER path recovers from the signature, so the
// user address recorded on chain must be this value too.
func ethAddressOf(t *testing.T, caller signer.Signer) string {
	t.Helper()
	testKeys.Lock()
	raw, ok := testKeys.byAddress[caller.Address()]
	testKeys.Unlock()
	if !ok {
		t.Fatalf("no raw key for %s", caller.Address())
	}
	priv := secp256k1.PrivKeyFromBytes(raw)
	sum := keccak256(priv.PubKey().SerializeUncompressed()[1:])
	encoded, err := bech32.ConvertAndEncode("trueopen", sum[12:])
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// metadataBody is the body digest of a metadata request: the object ref itself.
func metadataBody(t *testing.T, key ObjectKey) []byte {
	t.Helper()
	digest, err := TaskDataMetadataBodyDigest(key)
	if err != nil {
		t.Fatal(err)
	}
	return digest[:]
}

// fixtureFetch builds a fetch request: the range is no longer signed separately, it is the second
// field of the fetch body domain.
func (f *authorizerFixture) fixtureFetch(
	t *testing.T, caller signer.Signer, key ObjectKey, byteRange *ByteRange, nonce byte, expiry uint64,
) RequestAuth {
	t.Helper()
	digest, err := TaskDataFetchBodyDigest(key, byteRange)
	if err != nil {
		t.Fatal(err)
	}
	return f.fixtureRequest(t, caller, MethodFetch, key, digest[:], nonce, expiry)
}

// userSignedRequest builds a request on the USER path: EIP-712 v4, 65-byte R||S||V, and
// service_authorization_nonce must be 0.
func userSignedRequest(
	t *testing.T, caller signer.Signer, method RequestMethod, key ObjectKey, body []byte, nonce byte, expiry uint64,
) RequestAuth {
	t.Helper()
	bodyDigest := make([]byte, sha256.Size)
	copy(bodyDigest, body)
	request := RequestAuth{
		SchemaVersion: 1, ChainID: testChainID, BuilderOperatorAddress: testBuilder,
		RPCMethod: rpcMethodPath(method), BodyDigest: hex.EncodeToString(bodyDigest),
		RequesterKind: RequesterKindUser, RequesterAddress: ethAddressOf(t, caller),
		ServiceAuthorizationNonce: 0,
		RequestNonce:              bytes.Repeat([]byte{nonce}, 32),
		ExpiryHeight:              expiry,
		Key:                       key,
	}
	digest, err := UserTaskDataRequestDigest(request, testEVMChainID)
	if err != nil {
		t.Fatal(err)
	}
	request.Signature = signRecoverableForTest(t, caller, digest)
	return request
}

// signRecoverableForTest produces the 65-byte R||S||V (V in {27,28}) that EIP-712 requires.
// The dcrec compact layout is [V R S] and a compressed public key adds 4 to V; here an uncompressed
// public key is recovered, so that bit is removed.
func signRecoverableForTest(t *testing.T, caller signer.Signer, digest [32]byte) []byte {
	t.Helper()
	testKeys.Lock()
	raw, ok := testKeys.byAddress[caller.Address()]
	testKeys.Unlock()
	if !ok {
		t.Fatalf("no raw key for %s", caller.Address())
	}
	priv := secp256k1.PrivKeyFromBytes(raw)
	compact := ecdsa.SignCompact(priv, digest[:], false)
	out := make([]byte, 65)
	copy(out, compact[1:])
	v := compact[0]
	if v >= 31 {
		v -= 4
	}
	out[64] = v
	return out
}

// signedRequestAs decouples the signing key from the declared requester operator address: on the
// CORTEX service key path the two differ by design.
//
// The signature is made over the 32 bytes of CortexTaskDataRequestDigest itself, with no second
// hashing — this is the convention of the chain's strict verifier, and a fixture that used another
// convention would only verify our own wrong algorithm.
func signedRequestAs(
	t *testing.T, requester string, caller signer.Signer, method RequestMethod,
	key ObjectKey, body []byte, nonce byte, expiry uint64,
) RequestAuth {
	t.Helper()
	bodyDigest := make([]byte, sha256.Size)
	copy(bodyDigest, body)
	request := RequestAuth{
		SchemaVersion: 1, ChainID: testChainID, BuilderOperatorAddress: testBuilder,
		RPCMethod: rpcMethodPath(method), BodyDigest: hex.EncodeToString(bodyDigest),
		RequesterKind: RequesterKindCortexService, RequesterAddress: requester,
		ServiceAuthorizationNonce: 1,
		RequestNonce:              bytes.Repeat([]byte{nonce}, 32),
		ExpiryHeight:              expiry,
		Key:                       key,
	}
	digest, err := CortexTaskDataRequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	request.Signature = signDigestForTest(t, caller, digest[:])
	return request
}

// fetchRequest builds a fetch request. Since wire v0.4.1 a fetch shares TaskDataRequestAuthV1 with
// upload and metadata: the range is no longer signed separately, it is the second field of the body
// domain.
// A nil byteRange means reading the whole object — which is not the same as a present range with
// offset and length both zero.
func fetchRequest(
	t *testing.T, caller signer.Signer, key ObjectKey, byteRange *ByteRange, nonce byte, expiry uint64,
) RequestAuth {
	t.Helper()
	return fetchRequestAs(t, caller.Address(), caller, key, byteRange, nonce, expiry)
}

func fetchRequestAs(
	t *testing.T, requester string, caller signer.Signer, key ObjectKey,
	byteRange *ByteRange, nonce byte, expiry uint64,
) RequestAuth {
	t.Helper()
	digest, err := TaskDataFetchBodyDigest(key, byteRange)
	if err != nil {
		t.Fatal(err)
	}
	return signedRequestAs(t, requester, caller, MethodFetch, key, digest[:], nonce, expiry)
}

// Task Data Interface Design §6.2: media_type is only an optional transport hint and may be empty in
// the upload body; the codec of EVIDENCE_ARTIFACT is defined solely by the evidence schema, so its
// media_type must be empty.
// Cortex uploads evidence with an empty media_type, and this test pins that Nexus must not reject it
// as MALFORMED.
func TestUploadBodyDigestMediaTypeOptional(t *testing.T) {
	fx := newAuthorizerFixture(t)
	meta := fx.metadata[ObjectKindOutput]
	header := UploadHeader{Key: meta.Key, SizeBytes: meta.SizeBytes, SemanticHash: meta.SemanticHash}
	if _, err := UploadBodyDigest(header); err != nil {
		t.Fatalf("OUTPUT with empty media_type must be accepted: %v", err)
	}
	if _, err := validateUploadHeader(withUploader(header), Config{MaxBlobBytes: 1 << 20}); err != nil {
		t.Fatalf("OUTPUT upload header with empty media_type must be accepted: %v", err)
	}

	artifact := header
	artifact.Key.Kind = ObjectKindEvidenceArtifact
	artifact.Key.EvidenceProducerKind = EvidenceProducerWorker
	artifact.Key.VerifyRound = 1
	artifact.Key.ProducerOperator = fx.worker.Address()
	if _, err := UploadBodyDigest(artifact); err != nil {
		t.Fatalf("EVIDENCE_ARTIFACT with empty media_type must be accepted: %v", err)
	}
	if _, err := validateUploadHeader(withUploader(artifact), Config{MaxBlobBytes: 1 << 20}); err != nil {
		t.Fatalf("EVIDENCE_ARTIFACT upload header with empty media_type must be accepted: %v", err)
	}
	artifact.MediaType = "application/octet-stream"
	if _, err := UploadBodyDigest(artifact); !errors.Is(err, ErrMalformed) {
		t.Fatalf("EVIDENCE_ARTIFACT with non-empty media_type must be rejected, got %v", err)
	}
	if _, err := validateUploadHeader(withUploader(artifact), Config{MaxBlobBytes: 1 << 20}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("EVIDENCE_ARTIFACT upload header with non-empty media_type must be rejected, got %v", err)
	}

	padded := header
	padded.MediaType = " text/plain"
	if _, err := UploadBodyDigest(padded); !errors.Is(err, ErrMalformed) {
		t.Fatalf("non-canonical media_type must be rejected, got %v", err)
	}
}

func withUploader(header UploadHeader) UploadHeader {
	header.Uploader = "worker"
	return header
}

// The chainId of the EIP-712 domain comes from the Hub parameter phase0.evm_chain_id; with 0 every
// USER request fails signature verification, so the Authorizer refuses to be constructed with 0 (if
// the app cannot read it at startup, the service does not start).
func TestNewAuthorizerRejectsZeroEVMChainID(t *testing.T) {
	fx := newAuthorizerFixture(t)
	_, err := NewAuthorizer(AuthorizerConfig{
		ChainID: testChainID, BuilderAddress: testBuilder, AddressPrefix: "trueopen",
		RequestTTLBlocks: 20, RetentionLeaseBlocks: 50,
	}, fx.backend, fx.authority, fx.service)
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("error = %v, want ErrMalformed", err)
	}
}
