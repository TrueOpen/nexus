// Package supportrelay relays Cortex model support confirmations to the chain: it accepts a
// service-key-signed hub.v1.ModelSupportConfirmationV1 through IngressAPI, keeps it until it is
// settled on chain, and submits it in MsgBatchConfirmModelSupport batches signed and paid for by
// the Builder account.
//
// A confirmation is accepted only after it is checked against current chain state: the current
// epoch, a registered Cortex operator, its current service key and nonce, the signature over the
// TRUEOPEN_DAILY_SUPPORT_CONFIRMATION_V1 digest, the expiry window, a service bond that can still
// refresh support (recoverable jail can; unbonding, exited and tombstoned cannot) and the Hub
// batch limits. Stale model support rows do not matter: renewing them is the point. One
// (operator, epoch) slot holds one signed material, locally and on chain; the same digest and
// signature again is an idempotent retry, anything else conflicts.
//
// Acceptance is not an on-chain refresh. Accepted confirmations are kept in the local store, so a
// restart does not lose them, and leave it only once the chain holds their DailySupport row or
// once they can no longer be included and an authoritative read found no row.
package supportrelay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/signer"
)

// Refusal classes; every Submit error wraps exactly one of them.
var (
	// ErrMalformed: the payload is not one canonical confirmation.
	ErrMalformed = errors.New("support confirmation is malformed")
	// ErrInvalidSignature: the signature does not verify under the operator's current service key.
	ErrInvalidSignature = errors.New("support confirmation signature is invalid")
	// ErrStale: the epoch, service key, nonce or expiry is not current, or the operator cannot
	// refresh support.
	ErrStale = errors.New("support confirmation is not valid now")
	// ErrConflict: the operator's slot of the epoch holds other signed material, queued here or
	// accepted on chain.
	ErrConflict = errors.New("support confirmation conflicts with the material held for its operator and epoch")
	// ErrLimit: the confirmation exceeds a Hub batch limit, or the relay queue is full.
	ErrLimit = errors.New("support confirmation exceeds a relay limit")
	// ErrUnavailable: chain state or the local store could not be read or written.
	ErrUnavailable = errors.New("support relay state is unavailable")
)

// errChainRefuses marks an ErrStale the chain itself enforces from now on (the epoch ended, the
// expiry passed, the nonce or key changed): no transaction, even one already in flight, can get
// the confirmation accepted any more.
var errChainRefuses = errors.New("the chain refuses it from now on")

// Chain is the chain state the relay reads; chaincli's client implements it.
type Chain interface {
	LatestHeight(ctx context.Context) (uint64, error)
	QuerySupportParams(ctx context.Context) (chaincli.SupportParams, error)
	QueryCortexNode(ctx context.Context, operator string) (chaincli.CortexNodeState, error)
	QueryCurrentServiceKey(ctx context.Context, participantType, operator string) (chaincli.ServiceKeyState, error)
	QueryServiceBond(ctx context.Context, operator string) (*hubv1.ServiceBondState, error)
	QueryDailySupport(ctx context.Context, operator string, epoch uint64) (*hubv1.DailySupportState, error)
	QueryTx(ctx context.Context, txHash []byte) (chaincli.TxResult, error)
}

// Submitter signs and broadcasts a batch from the Builder account (coordinator.SupportSubmitter).
type Submitter interface {
	SubmitBatchConfirmModelSupport(ctx context.Context, msg *hubv1.MsgBatchConfirmModelSupport, gasLimit uint64) (chaincli.TxResult, error)
}

// Config configures a Relay.
type Config struct {
	ChainID       string
	AddressPrefix string
	// SubmitterAddress is the Builder account that signs and pays for the batches.
	SubmitterAddress string
	// FlushInterval bounds how long an accepted confirmation waits before it is batched;
	// FlushItems queued confirmations start a batch at once.
	FlushInterval time.Duration
	FlushItems    int
	// MaxQueued bounds the confirmations held; one more is refused with ErrLimit.
	MaxQueued int
	// InclusionMarginBlocks is how many blocks above the current height a confirmation must stay
	// includable (not past its expiry, still in its epoch) to be accepted or sent; at least 1.
	InclusionMarginBlocks uint64
	// GasBase, GasPerConfirmation and GasPerModel give a batch its gas limit.
	GasBase            uint64
	GasPerConfirmation uint64
	GasPerModel        uint64
	// TxWait bounds the wait for a sent batch's block result.
	TxWait chaincli.TxWait
}

func (c Config) validate() error {
	switch {
	case c.ChainID == "" || c.AddressPrefix == "" || c.SubmitterAddress == "":
		return fmt.Errorf("support relay: chain id, address prefix and submitter address are required")
	case c.FlushInterval <= 0 || c.FlushItems <= 0 || c.MaxQueued <= 0 || c.InclusionMarginBlocks == 0:
		return fmt.Errorf("support relay: flush interval, flush items, max queued and inclusion margin must be positive")
	case c.GasBase == 0 || c.GasPerConfirmation == 0 || c.GasPerModel == 0:
		return fmt.Errorf("support relay: gas base, per confirmation and per model must be positive")
	case c.TxWait.Timeout <= 0:
		return fmt.Errorf("support relay: tx wait timeout must be positive")
	}
	return nil
}

// Ack answers an accepted confirmation.
type Ack struct {
	// Digest is the confirmation signing digest.
	Digest [32]byte
	// Idempotent is true when the same signed material was already queued here or accepted on
	// chain.
	Idempotent bool
}

// Relay accepts confirmations and batches them to the chain.
type Relay struct {
	cfg    Config
	log    *slog.Logger
	chain  Chain
	submit Submitter
	store  kv.Store
	now    func() time.Time

	mu      sync.Mutex
	entries map[string]*entry
	kick    chan struct{}

	stop chan struct{}
	done chan struct{}
}

// New builds a Relay and loads the confirmations a previous run left in store.
func New(cfg Config, log *slog.Logger, chain Chain, submit Submitter, store kv.Store) (*Relay, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if chain == nil || submit == nil || store == nil {
		return nil, fmt.Errorf("support relay: chain, submitter and store are required")
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	r := &Relay{
		cfg: cfg, log: log, chain: chain, submit: submit, store: store, now: time.Now,
		entries: map[string]*entry{}, kick: make(chan struct{}, 1),
	}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

// Submit checks the confirmation raw (protobuf ModelSupportConfirmationV1) for epoch against
// current chain state and queues it for relay. An error acknowledges nothing.
func (r *Relay) Submit(ctx context.Context, epoch uint64, raw []byte) (Ack, error) {
	c, err := Decode(raw, r.cfg.AddressPrefix)
	if err != nil {
		return Ack{}, err
	}
	v, err := r.readView(ctx)
	if err != nil {
		return Ack{}, err
	}
	digest, err := r.check(ctx, v, epoch, c)
	if err != nil {
		return Ack{}, err
	}
	key := r.slotKey(epoch, c.OperatorRaw)
	r.mu.Lock()
	held, ok := r.entries[key]
	r.mu.Unlock()
	if ok {
		return held.answer(digest, c.Signature)
	}
	row, err := r.chain.QueryDailySupport(ctx, c.Operator, epoch)
	switch {
	case err == nil:
		if !sameMaterial(row, c) {
			return Ack{}, fmt.Errorf("%w: the chain accepted other material for %s in epoch %d", ErrConflict, c.Operator, epoch)
		}
		return Ack{Digest: digest, Idempotent: true}, nil
	case !errors.Is(err, chaincli.ErrNotFound):
		return Ack{}, fmt.Errorf("%w: daily support: %v", ErrUnavailable, err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if held, ok := r.entries[key]; ok {
		return held.answer(digest, c.Signature)
	}
	if len(r.entries) >= r.cfg.MaxQueued {
		return Ack{}, fmt.Errorf("%w: the relay queue holds %d confirmations", ErrLimit, len(r.entries))
	}
	e := &entry{Epoch: epoch, Digest: digest[:], QueuedAtMs: r.now().UnixMilli(), c: c}
	if err := r.save(key, e); err != nil {
		return Ack{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	r.entries[key] = e
	if len(r.entries) >= r.cfg.FlushItems {
		select {
		case r.kick <- struct{}{}:
		default:
		}
	}
	return Ack{Digest: digest}, nil
}

// answer compares material for the slot of e: the same digest and signature is an idempotent
// retry, anything else conflicts.
func (e *entry) answer(digest [32]byte, signature []byte) (Ack, error) {
	if !bytes.Equal(e.Digest, digest[:]) || !bytes.Equal(e.c.Signature, signature) {
		return Ack{}, fmt.Errorf("%w: other material is queued for %s in epoch %d", ErrConflict, e.c.Operator, e.Epoch)
	}
	return Ack{Digest: digest, Idempotent: true}, nil
}

// sameMaterial reports whether a chain-accepted row holds c: the row keeps the supported models
// hash and SHA-256 of the raw signature.
func sameMaterial(row *hubv1.DailySupportState, c Confirmation) bool {
	models, err := nodecontract.SupportedModelsHash(c.Models)
	if err != nil {
		return false
	}
	signature := sha256.Sum256(c.Signature)
	return bytes.Equal(row.GetSupportedModelsHash(), models[:]) && bytes.Equal(row.GetSignatureDigest(), signature[:])
}

// view is the chain state a round of checks shares.
type view struct {
	height uint64
	epoch  uint64
	params chaincli.SupportParams
}

func (r *Relay) readView(ctx context.Context) (view, error) {
	height, err := r.chain.LatestHeight(ctx)
	if err != nil {
		return view{}, fmt.Errorf("%w: latest height: %v", ErrUnavailable, err)
	}
	params, err := r.chain.QuerySupportParams(ctx)
	if err != nil {
		return view{}, fmt.Errorf("%w: hub params: %v", ErrUnavailable, err)
	}
	return view{height: height, epoch: height / params.EpochLengthBlocks, params: params}, nil
}

// check validates c for epoch against v and the operator's live chain state, the way the chain
// will when it executes the batch at a later height, and returns the signing digest.
func (r *Relay) check(ctx context.Context, v view, epoch uint64, c Confirmation) ([32]byte, error) {
	if epoch != v.epoch {
		err := fmt.Errorf("%w: epoch %d is not the current epoch %d", ErrStale, epoch, v.epoch)
		if epoch < v.epoch {
			err = fmt.Errorf("%w: %w", err, errChainRefuses)
		}
		return [32]byte{}, err
	}
	if err := r.checkLimits(v.params, epoch, c); err != nil {
		return [32]byte{}, err
	}
	// The batch executes at a height above v.height: the expiry must not have passed by then, nor
	// lie more than the service material window above it, and the epoch must not have ended.
	next := v.height + 1
	if c.ExpiryHeight < next {
		return [32]byte{}, fmt.Errorf("%w: expiry_height %d has passed (height %d): %w", ErrStale, c.ExpiryHeight, v.height, errChainRefuses)
	}
	if c.ExpiryHeight-next > v.params.MaxServiceMaterialExpiryBlocks {
		return [32]byte{}, fmt.Errorf("%w: expiry_height %d is more than %d blocks above the next height %d",
			ErrStale, c.ExpiryHeight, v.params.MaxServiceMaterialExpiryBlocks, next)
	}
	lastUsable := min(c.ExpiryHeight, (epoch+1)*v.params.EpochLengthBlocks-1)
	if lastUsable < v.height+r.cfg.InclusionMarginBlocks {
		return [32]byte{}, fmt.Errorf("%w: the confirmation is includable only up to height %d, less than %d blocks above height %d",
			ErrStale, lastUsable, r.cfg.InclusionMarginBlocks, v.height)
	}
	node, err := r.chain.QueryCortexNode(ctx, c.Operator)
	switch {
	case errors.Is(err, chaincli.ErrNotFound):
		return [32]byte{}, fmt.Errorf("%w: %s is not a registered Cortex operator: %w", ErrStale, c.Operator, errChainRefuses)
	case err != nil:
		return [32]byte{}, fmt.Errorf("%w: cortex node: %v", ErrUnavailable, err)
	}
	// Only the operator's current ACTIVE service key counts, read from the chain: never a key the
	// caller presents, never a previous generation.
	publicKey, key, err := servicekey.Current(ctx, r.chain, r.cfg.AddressPrefix, servicekey.ParticipantCortex, c.Operator)
	switch {
	case errors.Is(err, servicekey.ErrAuthority):
		return [32]byte{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	case err != nil:
		return [32]byte{}, fmt.Errorf("%w: %v: %w", ErrStale, err, errChainRefuses)
	}
	if c.Nonce != node.ServiceAuthorizationNonce || c.Nonce != key.AuthorizationNonce {
		return [32]byte{}, fmt.Errorf("%w: service_authorization_nonce %d is not the current binding nonce %d: %w",
			ErrStale, c.Nonce, node.ServiceAuthorizationNonce, errChainRefuses)
	}
	digest, err := c.Digest(r.cfg.ChainID, epoch)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if !signer.VerifyDigestSig(publicKey, digest[:], c.Signature) {
		return [32]byte{}, fmt.Errorf("%w: not signed by the current service key of %s", ErrInvalidSignature, c.Operator)
	}
	bond, err := r.chain.QueryServiceBond(ctx, c.Operator)
	switch {
	case errors.Is(err, chaincli.ErrNotFound):
		return [32]byte{}, fmt.Errorf("%w: %s has no service bond", ErrStale, c.Operator)
	case err != nil:
		return [32]byte{}, fmt.Errorf("%w: service bond: %v", ErrUnavailable, err)
	}
	switch bond.GetStatus() {
	case hubv1.ServiceBondStatus_SERVICE_BOND_STATUS_UNBONDING, hubv1.ServiceBondStatus_SERVICE_BOND_STATUS_EXITED,
		hubv1.ServiceBondStatus_SERVICE_BOND_STATUS_TOMBSTONED, hubv1.ServiceBondStatus_SERVICE_BOND_STATUS_UNSPECIFIED:
		return [32]byte{}, fmt.Errorf("%w: service bond of %s is %s and cannot refresh support", ErrStale, c.Operator, bond.GetStatus())
	}
	return digest, nil
}

// checkLimits applies the Hub limits one confirmation must meet: its model count, and a batch of
// it alone, with this relay as submitter, within the item and byte bounds.
func (r *Relay) checkLimits(p chaincli.SupportParams, epoch uint64, c Confirmation) error {
	models := uint64(len(c.Models))
	switch {
	case models > uint64(p.MaxSupportedModelsPerOperator):
		return fmt.Errorf("%w: %d models, the Hub allows %d per operator", ErrLimit, models, p.MaxSupportedModelsPerOperator)
	case models > uint64(p.MaxItemsPerBatch):
		return fmt.Errorf("%w: %d models, the Hub allows %d per batch", ErrLimit, models, p.MaxItemsPerBatch)
	}
	if size := r.batchBytes(epoch, []Confirmation{c}); uint64(size) > p.MaxBatchBytes {
		return fmt.Errorf("%w: a batch of this confirmation alone is %d bytes, the Hub allows %d", ErrLimit, size, p.MaxBatchBytes)
	}
	return nil
}

// batchMsg is the batch carrying cs for epoch, submitted by this relay.
func (r *Relay) batchMsg(epoch uint64, cs []Confirmation) *hubv1.MsgBatchConfirmModelSupport {
	msg := &hubv1.MsgBatchConfirmModelSupport{EpochIndex: epoch, SubmitterAddress: r.cfg.SubmitterAddress}
	for _, c := range cs {
		msg.Confirmations = append(msg.Confirmations, c.Proto())
	}
	return msg
}

// batchBytes is the encoded size the chain bounds by max_daily_support_batch_bytes.
func (r *Relay) batchBytes(epoch uint64, cs []Confirmation) int {
	return proto.Size(r.batchMsg(epoch, cs))
}
