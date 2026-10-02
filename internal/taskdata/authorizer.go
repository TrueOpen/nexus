package taskdata

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/types"
)

const (
	participantTypeBuilder = servicekey.ParticipantBuilder
	// Worker and Verifier are both Task duties (sender_role) of a Cortex Node, and their current
	// service key is registered under the CORTEX participant type; there is no WORKER / VERIFIER
	// participant type.
	participantTypeCortex = servicekey.ParticipantCortex
)

const replayPruneLimit = 64

type Authority interface {
	LatestHeight(context.Context) (uint64, error)
	QueryTask(context.Context, chaincli.TaskKey) (chaincli.OnChainTask, error)
	QueryCurrentServiceKey(context.Context, string, string) (chaincli.ServiceKeyState, error)
	// QueryProfile reads the locked Verification Profile. Finalize uses its evidence_schema_hash to
	// decide whether a manifest belongs to this schema.
	QueryProfile(ctx context.Context, modelID string, profileVersion uint32) (chaincli.ProfileState, error)
}

type AuthorizerConfig struct {
	// EVMChainID is the numeric chainId of the EIP-712 domain (from the chain's Hub
	// parameters). It and the ChainID string must both match the current chain: checking only one of
	// them would let the same USER signature from another chain be replayed here.
	EVMChainID     uint64
	ChainID        string
	BuilderAddress string
	AddressPrefix  string
	// RequestTTLBlocks bounds an OpenTask chain-height expiry above the current height.
	RequestTTLBlocks uint64
	// MaxRequestExpiryBlocks bounds a Task data request's expiry_height above the current height:
	// the Hub parameter service.max_service_material_expiry_blocks. 0 falls back to RequestTTLBlocks.
	MaxRequestExpiryBlocks uint64
	// RefreshMaxRequestExpiryBlocks, when set, re-reads MaxRequestExpiryBlocks from the chain at
	// most once per RequestExpiryRefreshInterval (default 10 minutes), so a governance change takes
	// effect without a restart. A failed read keeps the last value.
	RefreshMaxRequestExpiryBlocks func(context.Context) (uint64, error)
	RequestExpiryRefreshInterval  time.Duration
	// UserRequestsPerMinute caps the requests one USER account may make per minute, checked after
	// the signature and before the nonce is stored. 0 disables the cap.
	UserRequestsPerMinute uint32
	// RetentionLeaseBlocks is the fallback length of the retention window for
	// retention_until_height in a storage confirmation (extending the retention
	// window is managed through a retention lease and does not modify the original confirmation).
	RetentionLeaseBlocks uint64
	// SessionGrants verifies session grants on USER requests: the chain reads (current height,
	// account keys) and the network's max_session_grant_blocks.
	SessionGrants SessionGrantEnv
	// Log receives authorization notices; nil discards them.
	Log *slog.Logger
}

type Authorizer struct {
	cfg       AuthorizerConfig
	log       *slog.Logger
	backend   kv.Store
	authority Authority
	signer    signer.Signer

	replayMu sync.Mutex

	expiryMu        sync.Mutex
	expiryBlocks    uint64
	expiryRefreshed time.Time

	userRate userRateLimiter
}

type metadataAccess struct {
	height       uint64
	inferReceipt chaincli.InferReceiptState
}

func NewAuthorizer(cfg AuthorizerConfig, backend kv.Store, authority Authority, serviceSigner signer.Signer) (*Authorizer, error) {
	if !canonicalText(cfg.ChainID) || !canonicalText(cfg.BuilderAddress) || !canonicalText(cfg.AddressPrefix) ||
		cfg.RequestTTLBlocks == 0 || cfg.RetentionLeaseBlocks == 0 {
		return nil, fmt.Errorf("%w: authorizer configuration", ErrMalformed)
	}
	// With a chainId of 0 in the EIP-712 domain every USER Task data request fails signature
	// verification; the value comes from the Hub parameter phase0.evm_chain_id, and the service
	// should not start if it was not read.
	if cfg.EVMChainID == 0 {
		return nil, fmt.Errorf("%w: authorizer configuration: evm_chain_id is zero", ErrMalformed)
	}
	if backend == nil || authority == nil || serviceSigner == nil {
		return nil, fmt.Errorf("%w: authorizer dependencies", ErrMalformed)
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Authorizer{
		cfg: cfg, log: log, backend: backend, authority: authority, signer: serviceSigner,
		expiryBlocks: cfg.MaxRequestExpiryBlocks, expiryRefreshed: time.Now(),
		userRate: userRateLimiter{limit: cfg.UserRequestsPerMinute, counts: map[string]uint32{}},
	}, nil
}

// AuthorizeMetadata establishes the current caller role before disclosing
// whether an object exists. This method returns no content, locator or download
// authorization.
func (a *Authorizer) AuthorizeMetadata(ctx context.Context, request RequestAuth, metadata *Metadata) error {
	access, err := a.verifyMetadataRequest(ctx, request)
	if err != nil {
		return err
	}
	return a.finishMetadata(request, access, metadata)
}

func (a *Authorizer) verifyMetadataRequest(ctx context.Context, request RequestAuth) (metadataAccess, error) {
	// The body digest pins the request to this one object ref. Without this step a metadata request
	// signed for A could be used unchanged to query B — the signature would still be valid, because
	// the ref does not enter the request preimage.
	digest, err := TaskDataMetadataBodyDigest(request.Key)
	if err != nil {
		return metadataAccess{}, formatErr(request, err)
	}
	if err := serviceBodyBound(request, true, digest, "metadata"); err != nil {
		return metadataAccess{}, err
	}
	task, height, err := a.verifyRequest(ctx, request, MethodGetMetadata, digest)
	if err != nil {
		return metadataAccess{}, err
	}
	permissions := permissionsFor(task, request.RequesterAddress, height)
	if !permissions.canInspect(request.Key, request.RequesterAddress) {
		return metadataAccess{}, fmt.Errorf("%w: metadata role", roleDenied(request))
	}
	if !a.acceptedInputVersion(task, request) {
		return metadataAccess{}, fmt.Errorf("%w: input version is not the accepted one", roleDenied(request))
	}
	return metadataAccess{height: height, inferReceipt: task.InferReceipt}, nil
}

func (a *Authorizer) finishMetadata(request RequestAuth, access metadataAccess, metadata *Metadata) error {
	if metadata != nil && metadata.Key.Kind == ObjectKindOutput && metadata.Receipt != nil {
		if access.inferReceipt.InferReceiptHash != "" || access.inferReceipt.AcceptedItemHash != "" {
			if !receiptMatchesChain(*metadata.Receipt, access.inferReceipt) {
				return fmt.Errorf("%w: accepted infer receipt differs", ErrConflict)
			}
			metadata.AcceptedReceiptHash = access.inferReceipt.AcceptedItemHash
		} else {
			metadata.AcceptedReceiptHash = ""
		}
	}
	return a.consumeRequestNonce(request, access.height)
}

func (a *Authorizer) AuthorizeUploadObject(ctx context.Context, request RequestAuth, header UploadHeader) (string, uint64, error) {
	digest, err := UploadBodyDigest(header)
	if err != nil {
		return "", 0, formatErr(request, err)
	}
	if err := serviceBodyBound(request, request.Key == header.Key, digest, "upload"); err != nil {
		return "", 0, err
	}
	task, height, err := a.verifyRequest(ctx, request, MethodUpload, digest)
	if err != nil {
		return "", 0, err
	}
	if request.Key != header.Key {
		return "", 0, fmt.Errorf("%w: upload object ref is not the one the request signed", ErrInvalidSignature)
	}
	permissions := permissionsFor(task, request.RequesterAddress, height)
	if !permissions.canUpload(request.Key, request.RequesterAddress) {
		return "", 0, fmt.Errorf("%w: upload role", ErrUnauthorized)
	}
	acceptedReceiptHash := ""
	if header.Key.Kind == ObjectKindOutput {
		if err := a.verifyOutputReceipt(ctx, task, header); err != nil {
			return "", 0, err
		}
		acceptedReceiptHash = task.InferReceipt.AcceptedItemHash
	}
	return acceptedReceiptHash, height, nil
}

// AuthorizeOutputStream authorizes the streamed upload Header: the request signature and body binding follow the whole-object upload; only the
// Task's selected Worker is allowed; task_hash must equal the accepted_task_hash accepted on chain;
// the task must be in ASSIGNED / VERIFYING (otherwise DeadlineExceeded).
// It also returns the Worker's current service key for per-frame signature verification; the same
// stream reuses it instead of querying the chain per frame.
func (a *Authorizer) AuthorizeOutputStream(ctx context.Context, request RequestAuth, key ObjectKey, taskHash string) (chaincli.OnChainTask, uint64, []byte, error) {
	digest, err := OutputStreamBodyDigest(key)
	if err != nil {
		return chaincli.OnChainTask{}, 0, nil, formatErr(request, err)
	}
	if err := serviceBodyBound(request, request.Key == key, digest, "output stream header"); err != nil {
		return chaincli.OnChainTask{}, 0, nil, err
	}
	task, height, err := a.verifyRequest(ctx, request, MethodUploadStream, digest)
	if err != nil {
		return chaincli.OnChainTask{}, 0, nil, err
	}
	if request.Key != key {
		return chaincli.OnChainTask{}, 0, nil, fmt.Errorf("%w: output stream object ref is not the one the request signed", ErrInvalidSignature)
	}
	if task.Assignment.SelectedWorkerOperatorAddress == "" || task.Assignment.SelectedWorkerOperatorAddress != request.RequesterAddress {
		return chaincli.OnChainTask{}, 0, nil, fmt.Errorf("%w: output stream uploader is not the selected worker", ErrUnauthorized)
	}
	if !canonicalSHA256(taskHash) || task.Assignment.AcceptedTaskHash != taskHash {
		return chaincli.OnChainTask{}, 0, nil, fmt.Errorf("%w: output stream task_hash does not match accepted_task_hash", ErrUnauthorized)
	}
	if task.State != types.Assigned && task.State != types.Verifying {
		return chaincli.OnChainTask{}, 0, nil, fmt.Errorf("%w: task is not in ASSIGNED or VERIFYING", ErrExpired)
	}
	workerPublicKey, _, err := a.currentParticipantServiceKey(ctx, participantTypeCortex, request.RequesterAddress)
	if err != nil {
		return chaincli.OnChainTask{}, 0, nil, err
	}
	return task, height, workerPublicKey, nil
}

// AuthorizeFetch authorizes a fetch. A fetch uses the same TaskDataRequestAuthV1
// as upload and metadata: there is no separate range signature any more and no pre-signed download
// credential — the range is committed by body_digest as part of the body domain.
//
// Authorization looks only at on-chain roles: selected Worker -> INPUT, selected Verifier ->
// INPUT/OUTPUT/Worker bundle and the Verifier bundles canReadEvidence admits, original User ->
// OUTPUT. A role the requester claims does not count.
//
// The returned grant carries what the Builder keeps as the requester's fetch receipt: the
// height the request was authorized at and, for CORTEX_SERVICE, the service key the signature
// verified against.
func (a *Authorizer) AuthorizeFetch(
	ctx context.Context, request RequestAuth, byteRange *ByteRange,
) (FetchGrant, error) {
	digest, err := TaskDataFetchBodyDigest(request.Key, byteRange)
	if err != nil {
		return FetchGrant{}, formatErr(request, err)
	}
	if err := serviceBodyBound(request, true, digest, "fetch"); err != nil {
		return FetchGrant{}, err
	}
	task, height, requesterKey, err := a.verifyRequestKey(ctx, request, MethodFetch, digest)
	if err != nil {
		return FetchGrant{}, err
	}
	permissions := permissionsFor(task, request.RequesterAddress, height)
	if !permissions.canDownload(request.Key, request.RequesterAddress) {
		return FetchGrant{}, fmt.Errorf("%w: download role", roleDenied(request))
	}
	if !a.acceptedInputVersion(task, request) {
		return FetchGrant{}, fmt.Errorf("%w: input version is not the accepted one", roleDenied(request))
	}
	if err := a.consumeRequestNonce(request, height); err != nil {
		return FetchGrant{}, err
	}
	return FetchGrant{Task: task, Height: height, RequesterKey: requesterKey}, nil
}

// acceptedInputVersion reports whether a request for an INPUT names the chain's accepted version:
// accepted_task_hash, and accepted_input_hash once the chain query carries it. Only selected
// Workers and Verifiers may read INPUT and they exist only after acceptance, so a correct request
// always names it; another version this Builder may hold is not served. Other kinds pass.
func (a *Authorizer) acceptedInputVersion(task chaincli.OnChainTask, request RequestAuth) bool {
	if request.Key.Kind != ObjectKindInput {
		return true
	}
	accepted := task.Assignment
	if accepted.AcceptedTaskHash != "" && request.Key.TaskHash == accepted.AcceptedTaskHash &&
		(accepted.AcceptedInputHash == "" || request.Key.ContentHash == accepted.AcceptedInputHash) {
		return true
	}
	a.log.Info("task input request names a version the chain did not accept",
		"session_id", request.Key.SessionID, "task_id", request.Key.TaskID, "requester", request.RequesterAddress,
		"task_hash", request.Key.TaskHash, "accepted_task_hash", accepted.AcceptedTaskHash,
		"content_hash", request.Key.ContentHash, "accepted_input_hash", accepted.AcceptedInputHash)
	return false
}

// FetchGrant is an authorized FetchTaskData request.
type FetchGrant struct {
	Task   chaincli.OnChainTask
	Height uint64
	// RequesterKey is the Cortex service key the request signature verified against; nil for
	// a USER request, whose address is recovered from the signature.
	RequesterKey []byte
}

// SignStorageConfirmation issues a BuilderStorageConfirmationV1
// after the data has been fully persisted and verified. The confirmation covers the object ref
// itself and contains no locator.
//
// artifactTotalSizeBytes is meaningful only for EVIDENCE_MANIFEST and is the checked sum of all
// artifact sizes in the manifest; pass 0 for INPUT/OUTPUT. That sum is computed by the caller when
// it parses the manifest strictly — Nexus does not reinterpret manifest semantics here.
func (a *Authorizer) SignStorageConfirmation(ctx context.Context, metadata Metadata, artifactTotalSizeBytes uint64) (StorageConfirmation, error) {
	if metadata.State != StateReady || metadata.RetentionStatus == RetentionDeleted {
		return StorageConfirmation{}, fmt.Errorf("%w: confirmation object state", ErrConflict)
	}
	currentPub, nonce, err := a.currentBuilderServiceBinding(ctx)
	if err != nil {
		return StorageConfirmation{}, err
	}
	retention := metadata.RetainUntilHeight
	if retention == 0 {
		height, err := a.authority.LatestHeight(ctx)
		if err != nil || height == 0 {
			return StorageConfirmation{}, fmt.Errorf("%w: latest height", ErrAuthorityUnavailable)
		}
		if height > math.MaxUint64-a.cfg.RetentionLeaseBlocks {
			return StorageConfirmation{}, fmt.Errorf("%w: retention height", ErrExpired)
		}
		retention = height + a.cfg.RetentionLeaseBlocks
	}
	confirmation := StorageConfirmation{
		SchemaVersion:             StorageConfirmationSchemaVersionV1,
		ChainID:                   a.cfg.ChainID,
		BuilderOperator:           a.cfg.BuilderAddress,
		ServiceAuthorizationNonce: nonce,
		Ref:                       metadata.Key,
		SizeBytes:                 metadata.SizeBytes,
		ArtifactTotalSizeBytes:    artifactTotalSizeBytes,
		RetentionUntilHeight:      retention,
	}
	digest, err := BuilderStorageConfirmationDigest(confirmation)
	if err != nil {
		return StorageConfirmation{}, err
	}
	if !bytes.Equal(currentPub, a.signer.PubKeyCompressed()) {
		return StorageConfirmation{}, fmt.Errorf("%w: local signer does not match Hub", ErrServiceKeyUnavailable)
	}
	confirmation.Signature, err = a.signer.SignDigest(digest)
	if err != nil {
		return StorageConfirmation{}, fmt.Errorf("%w: sign storage confirmation", ErrServiceKeyUnavailable)
	}
	return confirmation, nil
}

// verifyRequest performs request authentication: requester_kind alone decides the
// verification path, sniffing by signature length is not allowed and neither is trying the other
// path after one fails; neither path accepts a public key supplied by the caller — CORTEX_SERVICE
// reads the current service key from the chain by (CORTEX, requester_address), and USER recovers the
// address from the 65-byte signature.
// roleDenied is the error for a verified requester without the Task duty: DATA_ACCESS_DENIED for a
// USER, the Nexus code the CORTEX_SERVICE path has always returned otherwise.
func roleDenied(request RequestAuth) error {
	if request.RequesterKind == RequesterKindUser {
		return ErrDenied
	}
	return ErrUnauthorized
}

// formatErr reports a USER request that fails the format step under NEXUS_INGRESS_MALFORMED, the
// code of step 1; the CORTEX_SERVICE path keeps NEXUS_DATA_MALFORMED.
func formatErr(request RequestAuth, err error) error {
	return UserFormatErr(request.RequesterKind == RequesterKindUser, err)
}

// UserFormatErr turns a NEXUS_DATA_MALFORMED error of a USER request into NEXUS_INGRESS_MALFORMED;
// anything else is returned unchanged.
func UserFormatErr(user bool, err error) error {
	if !user || !errors.Is(err, ErrMalformed) {
		return err
	}
	return fmt.Errorf("%w: %s", ErrRequestMalformed, strings.TrimPrefix(err.Error(), ErrMalformed.Error()+": "))
}

// serviceBodyBound refuses a CORTEX_SERVICE request whose signed body_digest (or object ref) is not
// the body the verifier recomputed. A USER request needs no separate check: the verifier rebuilds
// its signed digest with the recomputed body, so a mismatch fails at the signature step.
func serviceBodyBound(request RequestAuth, sameKey bool, body [32]byte, label string) error {
	if request.RequesterKind == RequesterKindUser {
		return nil
	}
	if !sameKey || request.BodyDigest != hex.EncodeToString(body[:]) {
		return fmt.Errorf("%w: %s body binding", ErrUnauthorized, label)
	}
	return nil
}

func (a *Authorizer) verifyRequest(ctx context.Context, request RequestAuth, method RequestMethod, body [32]byte) (chaincli.OnChainTask, uint64, error) {
	task, height, _, err := a.verifyRequestKey(ctx, request, method, body)
	return task, height, err
}

// verifyRequestKey is verifyRequest that also returns the CORTEX_SERVICE key the signature
// verified against (nil on the USER path). body is the body digest the verifier recomputed.
//
// A USER request runs the five steps in order and stops at the first failure: format (including
// rpc_method naming the called method) -> NEXUS_INGRESS_MALFORMED; the session method set, the
// grant and the signature (VerifyUserTaskDataRequest); then builder_operator_address ->
// DATA_ACCESS_DENIED, expiry -> NEXUS_DATA_EXPIRED, replay -> NEXUS_DATA_REPLAY. The caller checks
// the Task duty last.
func (a *Authorizer) verifyRequestKey(ctx context.Context, request RequestAuth, method RequestMethod, body [32]byte) (chaincli.OnChainTask, uint64, []byte, error) {
	var requesterKey []byte
	switch request.RequesterKind {
	case RequesterKindCortexService:
		if request.ChainID != a.cfg.ChainID || request.BuilderOperatorAddress != a.cfg.BuilderAddress ||
			request.RPCMethod != rpcMethodPath(method) {
			return chaincli.OnChainTask{}, 0, nil, fmt.Errorf("%w: request binding", ErrUnauthorized)
		}
		if len(request.Signature) != 64 {
			return chaincli.OnChainTask{}, 0, nil, fmt.Errorf("%w: CORTEX_SERVICE signature must be exactly 64 bytes", ErrMalformed)
		}
		digest, err := CortexTaskDataRequestDigest(request)
		if err != nil {
			return chaincli.OnChainTask{}, 0, nil, err
		}
		publicKey, state, err := servicekey.Current(
			ctx, a.authority, a.cfg.AddressPrefix, participantTypeCortex, request.RequesterAddress)
		if err != nil {
			if errors.Is(err, servicekey.ErrAuthority) {
				return chaincli.OnChainTask{}, 0, nil, fmt.Errorf("%w: request identity: %v", ErrAuthorityUnavailable, err)
			}
			return chaincli.OnChainTask{}, 0, nil, fmt.Errorf("%w: request identity: %v", ErrUnauthorized, err)
		}
		// service_authorization_nonce pins the signature to this generation of the service key: after
		// a rotation requests with the old nonce are no longer valid and the old key expires with
		// them.
		if request.ServiceAuthorizationNonce == 0 || request.ServiceAuthorizationNonce != state.AuthorizationNonce {
			return chaincli.OnChainTask{}, 0, nil, fmt.Errorf("%w: stale service_authorization_nonce", ErrUnauthorized)
		}
		if !signer.VerifyDigestSig(publicKey, digest[:], request.Signature) {
			return chaincli.OnChainTask{}, 0, nil, fmt.Errorf("%w: request signature", ErrUnauthorized)
		}
		requesterKey = publicKey
	case RequesterKindUser:
		if request.RPCMethod != rpcMethodPath(method) {
			return chaincli.OnChainTask{}, 0, nil, fmt.Errorf("%w: rpc_method %q is not the called method %q",
				ErrRequestMalformed, request.RPCMethod, rpcMethodPath(method))
		}
		env := a.cfg.SessionGrants
		env.AddressPrefix = a.cfg.AddressPrefix
		env.ChainID = a.cfg.ChainID
		env.BodyDigest = hex.EncodeToString(body[:])
		if err := VerifyUserTaskDataRequest(ctx, request, a.cfg.EVMChainID, env); err != nil {
			return chaincli.OnChainTask{}, 0, nil, formatErr(request, err)
		}
		if request.BuilderOperatorAddress != a.cfg.BuilderAddress {
			return chaincli.OnChainTask{}, 0, nil, fmt.Errorf("%w: the request is for Builder %q", ErrDenied, request.BuilderOperatorAddress)
		}
		// The nonce of a signed request is stored before the Task duty is checked (wire order), so an
		// account may not store nonces faster than the cap.
		if !a.userRate.allow(request.RequesterAddress, time.Now()) {
			return chaincli.OnChainTask{}, 0, nil, fmt.Errorf("%w: too many Task data requests from %q", ErrCapacity, request.RequesterAddress)
		}
	default:
		return chaincli.OnChainTask{}, 0, nil, formatErr(request, fmt.Errorf("%w: requester_kind", ErrMalformed))
	}
	height, task, err := a.currentTask(ctx, request.Key)
	if err != nil {
		return chaincli.OnChainTask{}, 0, nil, err
	}
	if err := validateExpiry(height, request.ExpiryHeight, a.requestExpiryBlocks(ctx)); err != nil {
		return chaincli.OnChainTask{}, 0, nil, err
	}
	if request.RequesterKind == RequesterKindUser {
		// A USER nonce is consumed here, before the Task duty is checked; consumeRequestNonce is a
		// no-op for it afterwards.
		if err := a.consumeNonce("request", request.RequesterAddress, request.RequestNonce, request.ExpiryHeight, height); err != nil {
			return chaincli.OnChainTask{}, 0, nil, err
		}
	}
	return task, height, requesterKey, nil
}

// requestExpiryBlocks is the Task data request expiry window, re-read from the chain once per
// refresh interval when a reader is configured.
func (a *Authorizer) requestExpiryBlocks(ctx context.Context) uint64 {
	interval := a.cfg.RequestExpiryRefreshInterval
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	a.expiryMu.Lock()
	refresh := a.cfg.RefreshMaxRequestExpiryBlocks != nil && time.Since(a.expiryRefreshed) >= interval
	if refresh {
		a.expiryRefreshed = time.Now() // one reader per interval; the others keep the current value
	}
	a.expiryMu.Unlock()
	if refresh {
		if blocks, err := a.cfg.RefreshMaxRequestExpiryBlocks(ctx); err == nil && blocks != 0 {
			a.expiryMu.Lock()
			a.expiryBlocks = blocks
			a.expiryMu.Unlock()
		}
	}
	a.expiryMu.Lock()
	defer a.expiryMu.Unlock()
	if a.expiryBlocks != 0 {
		return a.expiryBlocks
	}
	return a.cfg.RequestTTLBlocks
}

// userRateLimiter counts USER requests per account in one-minute windows.
type userRateLimiter struct {
	mu     sync.Mutex
	limit  uint32
	window time.Time
	counts map[string]uint32
}

func (l *userRateLimiter) allow(account string, now time.Time) bool {
	if l.limit == 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.window) >= time.Minute {
		l.window = now
		clear(l.counts)
	}
	if l.counts[account] >= l.limit {
		return false
	}
	l.counts[account]++
	return true
}

// verifyRequesterKey confirms that the presented pubkey really represents the operator address the
// requester claims. There are two legitimate paths and both are needed:
//
//   - operator self-signing: the address derived from the pubkey == requester. An original User only
//     holds their own wallet key and must use this path; a Cortex Node may also keep self-signing
//     with its operator key, but that is no longer the only path.
//   - Cortex service key: look up the requester's current service key under the CORTEX participant
//     type and require it to be ACTIVE, byte-for-byte equal to the presented pubkey, and to derive an
//     address equal to the on-chain ServiceAddress. This path lets a Cortex Node sign task data
//     requests with its service key without keeping the operator private key online (aligned with
//     ingress's verifyParticipantRoleSignature).
//
// This only settles "is this key this operator's"; authorization still looks only at on-chain roles —
// permissionsFor compares the requester against the on-chain assignment, and a role the requester
// claims does not count.
func (a *Authorizer) verifyRequesterKey(ctx context.Context, requester string, pubKey []byte, label string) error {
	address, err := signer.AddressFromPubKey(a.cfg.AddressPrefix, pubKey)
	if err != nil {
		return fmt.Errorf("%w: %s identity", ErrUnauthorized, label)
	}
	if address == requester {
		return nil
	}
	if _, err := servicekey.VerifyPresented(
		ctx, a.authority, a.cfg.AddressPrefix, participantTypeCortex, requester, pubKey,
	); err != nil {
		// A failed chain query leaves no way to decide, so report the chain lookup as unavailable and
		// fail closed; silently degrading to "no service key" is not allowed.
		if errors.Is(err, servicekey.ErrAuthority) {
			return fmt.Errorf("%w: %s identity: %v", ErrAuthorityUnavailable, label, err)
		}
		return fmt.Errorf("%w: %s identity", ErrUnauthorized, label)
	}
	return nil
}

// consumeRequestNonce consumes a CORTEX_SERVICE request nonce, reporting a replay as
// NEXUS_DATA_UNAUTHORIZED as before. A USER nonce was already consumed by verifyRequestKey.
func (a *Authorizer) consumeRequestNonce(request RequestAuth, height uint64) error {
	if request.RequesterKind == RequesterKindUser {
		return nil
	}
	err := a.consumeNonce("request", request.RequesterAddress, request.RequestNonce, request.ExpiryHeight, height)
	if errors.Is(err, ErrReplay) {
		return fmt.Errorf("%w: request replay", ErrUnauthorized)
	}
	return err
}

// AuthorizeOpenTaskRequest checks the OpenTask request window, the signed order's expiry and the
// request nonce, in that order.
//
// An order past its order_expire_height is refused before the nonce is used, with the chain's
// boundary: the chain admits a new task while height <= order_expire_height. The observed height
// only lags the chain, so this check can refuse a block or two late but never refuses an order the
// chain still admits; a late order that gets through is refused by chain admission and the task
// fails on the existing path.
func (a *Authorizer) AuthorizeOpenTaskRequest(ctx context.Context, requester string, nonce []byte, expiry, orderExpireHeight uint64) error {
	if !canonicalText(requester) || len(nonce) < 16 {
		return fmt.Errorf("%w: OpenTask requester or nonce", ErrMalformed)
	}
	height, err := a.authority.LatestHeight(ctx)
	if err != nil || height == 0 {
		return fmt.Errorf("%w: latest height", ErrAuthorityUnavailable)
	}
	if err := validateExpiry(height, expiry, a.cfg.RequestTTLBlocks); err != nil {
		return err
	}
	if height > orderExpireHeight {
		return fmt.Errorf("%w: height %d is past order_expire_height %d", ErrOrderExpired, height, orderExpireHeight)
	}
	return a.consumeNonce("sdk_open_task", requester, nonce, expiry, height)
}

// currentTask queries the chain using only the Task identity in the key, so validation goes only
// that far: a stream still in transfer has no content_hash yet, and validating the full object ref
// would shut the stream out. Object-level shape validation is already done in each body digest
// derivation.
func (a *Authorizer) currentTask(ctx context.Context, key ObjectKey) (uint64, chaincli.OnChainTask, error) {
	if err := validateStreamKeyScope(key); err != nil {
		return 0, chaincli.OnChainTask{}, err
	}
	height, err := a.authority.LatestHeight(ctx)
	if err != nil || height == 0 {
		return 0, chaincli.OnChainTask{}, fmt.Errorf("%w: latest height", ErrAuthorityUnavailable)
	}
	task, err := a.authority.QueryTask(ctx, chaincli.TaskKey{SessionID: key.SessionID, TaskID: key.TaskID})
	if err != nil || task.SessionID != key.SessionID || task.TaskID != key.TaskID {
		return 0, chaincli.OnChainTask{}, fmt.Errorf("%w: current task", ErrAuthorityUnavailable)
	}
	return height, task, nil
}

// validateExpiry requires current_height <= expiry <= current_height + window, with checked addition.
func validateExpiry(height, expiry, window uint64) error {
	if expiry < height || height > math.MaxUint64-window || expiry > height+window {
		return fmt.Errorf("%w: request height", ErrExpired)
	}
	return nil
}

func (a *Authorizer) consumeNonce(domain, requester string, nonce []byte, expiry, height uint64) error {
	keyBytes, _ := frame4([]byte(domain), []byte(a.cfg.ChainID), []byte(requester), nonce)
	digest := sha256.Sum256(keyBytes)
	key := hex.EncodeToString(digest[:])
	a.replayMu.Lock()
	defer a.replayMu.Unlock()
	raw, found, err := a.backend.GetWithError(kv.NSTaskDataReplay, key)
	if err != nil {
		return fmt.Errorf("%w: read replay record", ErrStorage)
	}
	if found {
		if len(raw) != 8 {
			return fmt.Errorf("%w: decode replay record", ErrStorage)
		}
		previousExpiry := binary.BigEndian.Uint64(raw)
		if previousExpiry >= height {
			return fmt.Errorf("%w: request nonce already used", ErrReplay)
		}
		if err := a.backend.Delete(kv.NSTaskDataReplay, key); err != nil {
			return fmt.Errorf("%w: delete expired replay record", ErrStorage)
		}
		if err := a.backend.Delete(kv.NSTaskDataReplayExpiry, replayExpiryKey(previousExpiry, key)); err != nil {
			return fmt.Errorf("%w: delete expired replay index", ErrStorage)
		}
	}
	if err := a.pruneExpiredReplayRecords(height); err != nil {
		return err
	}
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], expiry)
	if err := a.backend.Set(kv.NSTaskDataReplay, key, encoded[:]); err != nil {
		return fmt.Errorf("%w: persist replay record", ErrStorage)
	}
	if err := a.backend.Set(kv.NSTaskDataReplayExpiry, replayExpiryKey(expiry, key), nil); err != nil {
		_ = a.backend.Delete(kv.NSTaskDataReplay, key)
		return fmt.Errorf("%w: persist replay expiry index", ErrStorage)
	}
	return nil
}

func (a *Authorizer) pruneExpiredReplayRecords(height uint64) error {
	type expiredReplayRecord struct {
		indexKey  string
		replayKey string
	}
	var expired []expiredReplayRecord
	var scanErr error
	if err := a.backend.Scan(kv.NSTaskDataReplayExpiry, func(indexKey string, _ []byte) bool {
		expiry, replayKey, err := parseReplayExpiryKey(indexKey)
		if err != nil {
			scanErr = err
			return false
		}
		if expiry >= height {
			return false
		}
		expired = append(expired, expiredReplayRecord{indexKey: indexKey, replayKey: replayKey})
		return len(expired) < replayPruneLimit
	}); err != nil {
		return fmt.Errorf("%w: scan replay expiry index", ErrStorage)
	}
	if scanErr != nil {
		return scanErr
	}
	for _, record := range expired {
		raw, found, err := a.backend.GetWithError(kv.NSTaskDataReplay, record.replayKey)
		if err != nil {
			return fmt.Errorf("%w: read indexed replay record", ErrStorage)
		}
		if found {
			if len(raw) != 8 {
				return fmt.Errorf("%w: decode indexed replay record", ErrStorage)
			}
			expiry := binary.BigEndian.Uint64(raw)
			if expiry >= height {
				if err := a.backend.Delete(kv.NSTaskDataReplayExpiry, record.indexKey); err != nil {
					return fmt.Errorf("%w: prune stale replay expiry index", ErrStorage)
				}
				continue
			}
			if err := a.backend.Delete(kv.NSTaskDataReplay, record.replayKey); err != nil {
				return fmt.Errorf("%w: prune replay record", ErrStorage)
			}
			if err := a.backend.Delete(kv.NSTaskDataReplayExpiry, record.indexKey); err != nil {
				return fmt.Errorf("%w: prune replay expiry index", ErrStorage)
			}
			continue
		}
		if err := a.backend.Delete(kv.NSTaskDataReplayExpiry, record.indexKey); err != nil {
			return fmt.Errorf("%w: prune orphan replay expiry index", ErrStorage)
		}
	}
	return nil
}

func replayExpiryKey(expiry uint64, replayKey string) string {
	return fmt.Sprintf("%020d:%s", expiry, replayKey)
}

func parseReplayExpiryKey(key string) (uint64, string, error) {
	expiryText, replayKey, found := strings.Cut(key, ":")
	if !found || len(expiryText) != 20 || !canonicalSHA256(replayKey) {
		return 0, "", fmt.Errorf("%w: decode replay expiry index", ErrStorage)
	}
	expiry, err := strconv.ParseUint(expiryText, 10, 64)
	if err != nil {
		return 0, "", fmt.Errorf("%w: decode replay expiry index", ErrStorage)
	}
	return expiry, replayKey, nil
}

func (a *Authorizer) currentBuilderServiceKey(ctx context.Context) ([]byte, error) {
	publicKey, _, err := a.currentBuilderServiceBinding(ctx)
	return publicKey, err
}

// currentBuilderServiceBinding returns this Builder's currently ACTIVE service key and its
// authorization nonce. A storage confirmation signs that nonce in, so the public key alone is not
// enough.
func (a *Authorizer) currentBuilderServiceBinding(ctx context.Context) ([]byte, uint64, error) {
	publicKey, state, err := a.currentParticipantServiceKey(ctx, participantTypeBuilder, a.cfg.BuilderAddress)
	if err != nil {
		return nil, 0, err
	}
	if state.ServiceAddress != a.signer.Address() || !bytes.Equal(publicKey, a.signer.PubKeyCompressed()) {
		return nil, 0, fmt.Errorf("%w: local signer does not match Hub", ErrServiceKeyUnavailable)
	}
	if state.AuthorizationNonce == 0 {
		return nil, 0, fmt.Errorf("%w: builder service authorization nonce", ErrServiceKeyUnavailable)
	}
	return publicKey, state.AuthorizationNonce, nil
}

func (a *Authorizer) currentParticipantServiceKey(ctx context.Context, participantType, operator string) ([]byte, chaincli.ServiceKeyState, error) {
	publicKey, state, err := servicekey.Current(ctx, a.authority, a.cfg.AddressPrefix, participantType, operator)
	if err != nil {
		if errors.Is(err, servicekey.ErrAuthority) {
			return nil, chaincli.ServiceKeyState{}, fmt.Errorf("%w: %v", ErrAuthorityUnavailable, err)
		}
		return nil, chaincli.ServiceKeyState{}, fmt.Errorf("%w: %v", ErrServiceKeyUnavailable, err)
	}
	return publicKey, state, nil
}

func (a *Authorizer) verifyOutputReceipt(ctx context.Context, task chaincli.OnChainTask, header UploadHeader) error {
	receipt := header.Receipt
	if receipt == nil || receipt.TaskID != header.Key.TaskID || receipt.WorkerOperatorAddress != task.Assignment.SelectedWorkerOperatorAddress ||
		receipt.WorkerOperatorAddress == "" || receipt.OutputHash != header.SemanticHash || receipt.OutputSizeBytes != header.SizeBytes {
		return fmt.Errorf("%w: output receipt binding", ErrUnauthorized)
	}
	if _, err := receiptFrame(*receipt); err != nil {
		return err
	}
	// chain_id is field 2 of the receipt signing preimage: the receipt must claim this chain, otherwise it is a
	// cross-chain replay.
	if receipt.ChainID != a.cfg.ChainID {
		return fmt.Errorf("%w: infer receipt chain_id", ErrUnauthorized)
	}
	if receipt.SchemaVersion != nodecontract.InferReceiptSchemaVersionV3 {
		return fmt.Errorf("%w: infer receipt schema_version", ErrUnauthorized)
	}
	// infer_receipt_hash is always derived locally: wire defines it as the same value as
	// infer_receipt_signing_digest, and the wire carries no self-declared copy to compare against
	// (the old 11-field decimal preimage was removed).
	digest, err := receiptDigest(*receipt)
	if err != nil {
		return fmt.Errorf("%w: infer receipt: %v", ErrUnauthorized, err)
	}
	// The receipt is signed by the Worker's Cortex Node service key: the participant type queried is
	// CORTEX, not the sender_role WORKER carried in the message.
	workerPublicKey, _, err := a.currentParticipantServiceKey(ctx, participantTypeCortex, receipt.WorkerOperatorAddress)
	if err != nil {
		return err
	}
	// digest is the InferReceiptV3 signing digest; the chain verifies the signature against the
	// digest directly, so the same convention must be used here.
	signature, err := hex.DecodeString(receipt.ServiceSignature)
	if err != nil || !signer.VerifyDigestSig(workerPublicKey, digest[:], signature) {
		return fmt.Errorf("%w: infer receipt service signature", ErrUnauthorized)
	}
	if (task.InferReceipt.InferReceiptHash != "" || task.InferReceipt.AcceptedItemHash != "") &&
		!receiptMatchesChain(*receipt, task.InferReceipt) {
		return fmt.Errorf("%w: accepted infer receipt differs", ErrConflict)
	}
	return nil
}

// receiptMatchesChain compares the local receipt against the InferReceiptState accepted on chain.
//
// The on-chain query state (InferReceiptState in proto/task/v1/open_verify.proto) still has its
// pre-freeze shape — the node's keeper and query have not moved to InferReceiptV2 yet (node
// only redirected the preimage to H_FIELDS_V1; rewriting the handler/query belongs to the Task
// slice), so it still carries trace/checkpoint/batch/token_count/work_unit, which the new receipt
// does not have.
//
// This therefore compares only facts that exist on both sides and whose meaning has not changed:
// worker, output hash/size and the Worker signature.
// **Hash values are deliberately not compared**: the on-chain infer_receipt_hash /
// accepted_item_hash are still computed by the pre-freeze keeper from the old decimal preimage and
// necessarily differ from the local H_FIELDS_V1 digest, so comparing them would flag a correct
// receipt as a conflict. Once the node's Task slice moves the keeper to InferReceiptSigningDigest,
// this should become a direct accepted.InferReceiptHash == hex(digest) comparison — which is
// stronger than a field-by-field comparison, because the digest covers all 11 preimage fields.
func receiptMatchesChain(receipt SignedInferReceipt, accepted chaincli.InferReceiptState) bool {
	return receipt.WorkerOperatorAddress == accepted.WorkerOperatorAddress &&
		receipt.OutputHash == accepted.OutputHash &&
		receipt.ServiceSignature == accepted.ServiceSignature
}

func verifyAcceptedOutputMetadata(metadata Metadata, accepted chaincli.InferReceiptState) error {
	if metadata.Key.Kind != ObjectKindOutput || (accepted.InferReceiptHash == "" && accepted.AcceptedItemHash == "") {
		return nil
	}
	if metadata.Receipt == nil {
		return fmt.Errorf("%w: accepted infer receipt differs", ErrConflict)
	}
	if !receiptMatchesChain(*metadata.Receipt, accepted) {
		return fmt.Errorf("%w: accepted infer receipt differs", ErrConflict)
	}
	return nil
}

// rolePermissions is the requester's on-chain standing for one Task, evaluated at one height.
// A requester may hold several roles at once, and each role grants its own access.
//
// Candidates hold no role here: the metadata a candidate Worker/Verifier needs is broadcast in
// ORDER_BROADCAST / OPEN_VERIFY, and a candidate reads nothing through the data interface —
// not content, not metadata.
type rolePermissions struct {
	worker bool
	user   bool
	// seats lists every verification round in which the requester is a selected Verifier. Phase 0
	// excludes earlier participants from later rounds, so in practice there is at most one.
	seats []verifierSeat
}

// verifierSeat is one round in which the requester is a selected Verifier, with whether that
// round's commit set was locked at the evaluation height.
type verifierSeat struct {
	round         uint32
	commitsLocked bool
}

func permissionsFor(task chaincli.OnChainTask, address string, height uint64) rolePermissions {
	permissions := rolePermissions{
		worker: task.Assignment.SelectedWorkerOperatorAddress == address,
		user:   task.Assignment.UserAddress == address,
	}
	for _, round := range task.VerifierRounds {
		for _, verifier := range round.Verifiers {
			if verifier == address {
				permissions.seats = append(permissions.seats, verifierSeat{
					round: round.VerifyRound, commitsLocked: round.CommitsLocked(height),
				})
				break
			}
		}
	}
	return permissions
}

func (p rolePermissions) verifier() bool {
	return len(p.seats) > 0
}

// canInspect decides GetTaskDataMetadata. Evidence metadata follows the same rule as evidence
// download.
func (p rolePermissions) canInspect(key ObjectRef, requester string) bool {
	switch key.Kind {
	case ObjectKindInput:
		return p.worker || p.verifier()
	case ObjectKindOutput:
		return p.worker || p.verifier() || p.user
	case ObjectKindEvidenceManifest, ObjectKindEvidenceArtifact:
		if key.EvidenceProducerKind == EvidenceProducerWorker && p.worker {
			// The Worker checks the storage state of its own bundle while uploading it.
			return true
		}
		return p.canReadEvidence(key, requester)
	}
	return false
}

// canDownload decides FetchTaskData: the selected Worker reads INPUT, the original User reads
// OUTPUT, a selected Verifier of any round reads INPUT and OUTPUT, and evidence follows
// canReadEvidence.
func (p rolePermissions) canDownload(key ObjectRef, requester string) bool {
	switch key.Kind {
	case ObjectKindInput:
		return p.worker || p.verifier()
	case ObjectKindOutput:
		return p.user || p.verifier()
	case ObjectKindEvidenceManifest, ObjectKindEvidenceArtifact:
		return p.canReadEvidence(key, requester)
	}
	return false
}

// canReadEvidence scopes evidence by (round, producer, phase):
//
//   - The Worker bundle (verify_round 1) is readable by a selected Verifier of any round: it is
//     the input of every verification.
//   - A Verifier bundle is readable by its own producer in its own round.
//   - A Verifier bundle of an earlier round is readable by a selected Verifier of a later round
//     only once that later round's commits are locked, so it cannot be copied into a commit.
//   - Nobody else reads a Verifier bundle: not another Verifier of the same round, not the
//     Worker, the User or a candidate.
//
// A Verifier ref that does not name its producer_operator cannot be proven to be the
// requester's own, so only the earlier-round rule can admit it.
func (p rolePermissions) canReadEvidence(key ObjectRef, requester string) bool {
	switch key.EvidenceProducerKind {
	case EvidenceProducerWorker:
		return p.verifier()
	case EvidenceProducerVerifier:
		for _, seat := range p.seats {
			if key.VerifyRound == seat.round && key.ProducerOperator == requester {
				return true
			}
			if key.VerifyRound < seat.round && seat.commitsLocked {
				return true
			}
		}
	}
	return false
}

// canUpload: only the selected Worker may upload an OUTPUT; an evidence bundle (the manifest plus
// the artifacts it lists) is uploaded by the producer declared in the ref itself — producer_kind must
// agree with the on-chain role, a Verifier bundle's verify_round must be a round the requester was
// selected in, and producer_operator, if given, must be the requester.
func (p rolePermissions) canUpload(key ObjectRef, requester string) bool {
	switch key.Kind {
	case ObjectKindOutput:
		return p.worker
	case ObjectKindEvidenceManifest, ObjectKindEvidenceArtifact:
		if key.ProducerOperator != "" && key.ProducerOperator != requester {
			return false
		}
		switch key.EvidenceProducerKind {
		case EvidenceProducerWorker:
			return p.worker
		case EvidenceProducerVerifier:
			for _, seat := range p.seats {
				if key.VerifyRound == seat.round {
					return true
				}
			}
		}
	}
	return false
}
