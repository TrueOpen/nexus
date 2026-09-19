package taskdata

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"

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
	// EVMChainID is the numeric chainId of the EIP-712 domain (the Genesis/account contract
	// mapping). It and the ChainID string must both match the current chain: checking only one of
	// them would let the same USER signature from another chain be replayed here.
	EVMChainID       uint64
	ChainID          string
	BuilderAddress   string
	AddressPrefix    string
	RequestTTLBlocks uint64
	// RetentionLeaseBlocks is the fallback length of the retention window for
	// retention_until_height in a storage confirmation (contract §5: extending the retention
	// window is managed through a retention lease and does not modify the original confirmation).
	RetentionLeaseBlocks uint64
}

type Authorizer struct {
	cfg       AuthorizerConfig
	backend   kv.Store
	authority Authority
	signer    signer.Signer

	replayMu sync.Mutex
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
	return &Authorizer{
		cfg: cfg, backend: backend, authority: authority, signer: serviceSigner,
	}, nil
}

// AuthorizeMetadata establishes the current caller role before disclosing
// whether an object exists. Contract §2.3: this method returns no content, locator or download
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
		return metadataAccess{}, err
	}
	if request.BodyDigest != hex.EncodeToString(digest[:]) {
		return metadataAccess{}, fmt.Errorf("%w: metadata body binding", ErrUnauthorized)
	}
	task, height, err := a.verifyRequest(ctx, request, MethodGetMetadata)
	if err != nil {
		return metadataAccess{}, err
	}
	permissions, err := permissionsFor(task, request.RequesterAddress, height)
	if err != nil {
		return metadataAccess{}, err
	}
	if !permissions.canInspect(request.Key.Kind) {
		return metadataAccess{}, fmt.Errorf("%w: metadata role", ErrUnauthorized)
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
		return "", 0, err
	}
	if request.Key != header.Key || request.BodyDigest != hex.EncodeToString(digest[:]) {
		return "", 0, fmt.Errorf("%w: upload body binding", ErrUnauthorized)
	}
	task, height, err := a.verifyRequest(ctx, request, MethodUpload)
	if err != nil {
		return "", 0, err
	}
	permissions, err := permissionsFor(task, request.RequesterAddress, height)
	if err != nil {
		return "", 0, err
	}
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

// AuthorizeOutputStream authorizes the streamed upload Header (streamed output delivery design
// §5.3, Header row): the request signature and body binding follow the whole-object upload; only the
// Task's selected Worker is allowed; task_hash must equal the accepted_task_hash accepted on chain;
// the task must be in ASSIGNED / VERIFYING (otherwise DeadlineExceeded).
// It also returns the Worker's current service key for per-frame signature verification; the same
// stream reuses it instead of querying the chain per frame.
func (a *Authorizer) AuthorizeOutputStream(ctx context.Context, request RequestAuth, key ObjectKey, taskHash string) (chaincli.OnChainTask, uint64, []byte, error) {
	digest, err := OutputStreamBodyDigest(key)
	if err != nil {
		return chaincli.OnChainTask{}, 0, nil, err
	}
	if request.Key != key || request.BodyDigest != hex.EncodeToString(digest[:]) {
		return chaincli.OnChainTask{}, 0, nil, fmt.Errorf("%w: output stream header binding", ErrUnauthorized)
	}
	task, height, err := a.verifyRequest(ctx, request, MethodUploadStream)
	if err != nil {
		return chaincli.OnChainTask{}, 0, nil, err
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

// AuthorizeFetch authorizes a fetch. Since wire v0.4.1 a fetch uses the same TaskDataRequestAuthV1
// as upload and metadata: there is no separate range signature any more and no pre-signed download
// credential — the range is committed by body_digest as part of the body domain.
//
// Authorization looks only at on-chain roles: selected Worker -> INPUT, selected Verifier ->
// INPUT/OUTPUT/Worker bundle, original User -> OUTPUT. A role the requester claims does not count.
func (a *Authorizer) AuthorizeFetch(
	ctx context.Context, request RequestAuth, byteRange *ByteRange,
) (chaincli.OnChainTask, error) {
	digest, err := TaskDataFetchBodyDigest(request.Key, byteRange)
	if err != nil {
		return chaincli.OnChainTask{}, err
	}
	if request.BodyDigest != hex.EncodeToString(digest[:]) {
		return chaincli.OnChainTask{}, fmt.Errorf("%w: fetch body binding", ErrUnauthorized)
	}
	task, height, err := a.verifyRequest(ctx, request, MethodFetch)
	if err != nil {
		return chaincli.OnChainTask{}, err
	}
	permissions, err := permissionsFor(task, request.RequesterAddress, height)
	if err != nil {
		return chaincli.OnChainTask{}, err
	}
	if !permissions.canDownload(request.Key.Kind) {
		return chaincli.OnChainTask{}, fmt.Errorf("%w: download role", ErrUnauthorized)
	}
	if err := a.consumeRequestNonce(request, height); err != nil {
		return chaincli.OnChainTask{}, err
	}
	return task, nil
}

// SignStorageConfirmation issues a BuilderStorageConfirmationV1 (Task Data Interface Design §6.3a)
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

// verifyRequest performs wire v0.4.1 request authentication: requester_kind alone decides the
// verification path, sniffing by signature length is not allowed and neither is trying the other
// path after one fails; neither path accepts a public key supplied by the caller — CORTEX_SERVICE
// reads the current service key from the chain by (CORTEX, requester_address), and USER recovers the
// address from the 65-byte signature.
func (a *Authorizer) verifyRequest(ctx context.Context, request RequestAuth, method RequestMethod) (chaincli.OnChainTask, uint64, error) {
	if request.ChainID != a.cfg.ChainID || request.BuilderOperatorAddress != a.cfg.BuilderAddress ||
		request.RPCMethod != rpcMethodPath(method) {
		return chaincli.OnChainTask{}, 0, fmt.Errorf("%w: request binding", ErrUnauthorized)
	}
	switch request.RequesterKind {
	case RequesterKindCortexService:
		if len(request.Signature) != 64 {
			return chaincli.OnChainTask{}, 0, fmt.Errorf("%w: CORTEX_SERVICE signature must be exactly 64 bytes", ErrMalformed)
		}
		digest, err := CortexTaskDataRequestDigest(request)
		if err != nil {
			return chaincli.OnChainTask{}, 0, err
		}
		publicKey, state, err := servicekey.Current(
			ctx, a.authority, a.cfg.AddressPrefix, participantTypeCortex, request.RequesterAddress)
		if err != nil {
			if errors.Is(err, servicekey.ErrAuthority) {
				return chaincli.OnChainTask{}, 0, fmt.Errorf("%w: request identity: %v", ErrAuthorityUnavailable, err)
			}
			return chaincli.OnChainTask{}, 0, fmt.Errorf("%w: request identity: %v", ErrUnauthorized, err)
		}
		// service_authorization_nonce pins the signature to this generation of the service key: after
		// a rotation requests with the old nonce are no longer valid and the old key expires with
		// them.
		if request.ServiceAuthorizationNonce == 0 || request.ServiceAuthorizationNonce != state.AuthorizationNonce {
			return chaincli.OnChainTask{}, 0, fmt.Errorf("%w: stale service_authorization_nonce", ErrUnauthorized)
		}
		if !signer.VerifyDigestSig(publicKey, digest[:], request.Signature) {
			return chaincli.OnChainTask{}, 0, fmt.Errorf("%w: request signature", ErrUnauthorized)
		}
	case RequesterKindUser:
		if err := VerifyUserTaskDataRequest(request, a.cfg.EVMChainID); err != nil {
			return chaincli.OnChainTask{}, 0, err
		}
	default:
		return chaincli.OnChainTask{}, 0, fmt.Errorf("%w: requester_kind", ErrMalformed)
	}
	height, task, err := a.currentTask(ctx, request.Key)
	if err != nil {
		return chaincli.OnChainTask{}, 0, err
	}
	if err := a.validateExpiry(height, request.ExpiryHeight); err != nil {
		return chaincli.OnChainTask{}, 0, err
	}
	return task, height, nil
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

func (a *Authorizer) consumeRequestNonce(request RequestAuth, height uint64) error {
	return a.consumeNonce("request", request.RequesterAddress, request.RequestNonce, request.ExpiryHeight, height)
}

func (a *Authorizer) AuthorizeOpenTaskRequest(ctx context.Context, requester string, nonce []byte, expiry uint64) error {
	if !canonicalText(requester) || len(nonce) < 16 {
		return fmt.Errorf("%w: OpenTask requester or nonce", ErrMalformed)
	}
	height, err := a.authority.LatestHeight(ctx)
	if err != nil || height == 0 {
		return fmt.Errorf("%w: latest height", ErrAuthorityUnavailable)
	}
	if err := a.validateExpiry(height, expiry); err != nil {
		return err
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

func (a *Authorizer) validateExpiry(height, expiry uint64) error {
	if expiry < height || height > math.MaxUint64-a.cfg.RequestTTLBlocks || expiry > height+a.cfg.RequestTTLBlocks {
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
			return fmt.Errorf("%w: request replay", ErrUnauthorized)
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
	// chain_id is field 2 of the §5.14 preimage: the receipt must claim this chain, otherwise it is a
	// cross-chain replay.
	if receipt.ChainID != a.cfg.ChainID {
		return fmt.Errorf("%w: infer receipt chain_id", ErrUnauthorized)
	}
	if receipt.SchemaVersion != nodecontract.InferReceiptSchemaVersionV2 {
		return fmt.Errorf("%w: infer receipt schema_version", ErrUnauthorized)
	}
	// infer_receipt_hash is always derived locally: §5.14 defines it as the same value as
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
	// digest is the frozen signing digest of §5.14; the chain verifies the signature against the
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

type rolePermissions struct {
	candidate bool
	worker    bool
	verifier  bool
	user      bool
}

func permissionsFor(task chaincli.OnChainTask, address string, height uint64) (rolePermissions, error) {
	permissions := rolePermissions{
		worker: task.Assignment.SelectedWorkerOperatorAddress == address,
		user:   task.Assignment.UserAddress == address,
	}
	for _, verifier := range task.Verifiers {
		if verifier == address {
			permissions.verifier = true
			break
		}
	}
	if permissions.worker || permissions.verifier || permissions.user {
		return permissions, nil
	}
	workerCandidate, err := workerCandidateContains(task.Assignment.WorkerHandraiseSet, task.TaskID, address, height)
	if err != nil {
		return rolePermissions{}, err
	}
	verifierCandidate, err := verifierCandidateContains(task.VerifierAssignment.VerifierHandraiseList, task.TaskID, address, height)
	if err != nil {
		return rolePermissions{}, err
	}
	permissions.candidate = workerCandidate || verifierCandidate
	return permissions, nil
}

func (p rolePermissions) canInspect(kind ObjectKind) bool {
	return p.candidate || p.worker || p.verifier || (p.user && kind == ObjectKindOutput)
}

func (p rolePermissions) canDownload(kind ObjectKind) bool {
	return p.verifier || (p.worker && kind == ObjectKindInput) || (p.user && kind == ObjectKindOutput)
}

// canUpload: only the selected Worker may upload an OUTPUT; an evidence bundle (the manifest plus
// the artifacts it lists) is uploaded by the producer declared in the ref itself — producer_kind must
// agree with the on-chain role, and producer_operator, if given, must be the requester.
// Task Data Interface Design §6.2.
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
			return p.verifier
		}
	}
	return false
}

func workerCandidateContains(raw, taskID, address string, height uint64) (bool, error) {
	if raw == "" {
		return false, nil
	}
	var candidates []nodecontract.WorkerHandraiseV1
	if err := json.Unmarshal([]byte(raw), &candidates); err != nil {
		return false, fmt.Errorf("%w: worker candidate set", ErrAuthorityUnavailable)
	}
	canonical, err := nodecontract.CanonicalWorkerHandraiseSet(candidates)
	if err != nil || canonical != raw {
		return false, fmt.Errorf("%w: worker candidate set", ErrAuthorityUnavailable)
	}
	for _, candidate := range candidates {
		if candidate.TaskID != taskID {
			return false, fmt.Errorf("%w: worker candidate task", ErrAuthorityUnavailable)
		}
		if candidate.WorkerOperatorAddress == address && candidate.ExpiryHeight >= height {
			return true, nil
		}
	}
	return false, nil
}

func verifierCandidateContains(raw, taskID, address string, height uint64) (bool, error) {
	if raw == "" {
		return false, nil
	}
	var candidates []nodecontract.VerifierHandraiseV1
	if err := json.Unmarshal([]byte(raw), &candidates); err != nil {
		return false, fmt.Errorf("%w: verifier candidate set", ErrAuthorityUnavailable)
	}
	canonical, err := nodecontract.CanonicalVerifierHandraiseList(candidates)
	if err != nil || canonical != raw {
		return false, fmt.Errorf("%w: verifier candidate set", ErrAuthorityUnavailable)
	}
	for _, candidate := range candidates {
		if candidate.TaskID != taskID {
			return false, fmt.Errorf("%w: verifier candidate task", ErrAuthorityUnavailable)
		}
		if candidate.VerifierOperatorAddress == address && candidate.ExpiryHeight >= height {
			return true, nil
		}
	}
	return false, nil
}
