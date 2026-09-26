// Package builderreg reconciles the local Builder identity against Hub state.
package builderreg

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"time"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/coordinator"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/signer"
)

// The participant type domain is defined in exactly one place, servicekey: it must be constructible into
// the hub.v1.ParticipantType enum, and every package writing its own literal is exactly where the
// "CORTEX_NODE" defect came from.
const participantTypeBuilder = servicekey.ParticipantBuilder

// initialServiceKeyNonce is the service_authorization_nonce used at first registration. It never goes on
// the wire and only scopes the TRUEOPEN_SERVICE_REGISTRATION_V1 PoP; the keeper fixes its value at 1.
const initialServiceKeyNonce = uint64(1)

// The Phase 0 BuilderBond is fixed at zero and creates no bonded stake or unbonding record (Staking and Slashing
// Protocol), and wire v0.4.1 has no Builder bond query or message either, so there is no bond step here:
// registration = MsgRegisterBuilder (identity + service key + descriptor), with admission fixed by
// governance or genesis.
var (
	ErrPendingRegistration = errors.New("builder registration outcome is pending chain reconciliation")
	// ErrNotRegistered / ErrDescriptorStale are the two outcomes of `nexus start`, which only checks and
	// never submits: changing the descriptor is an explicit operator-key action by the operator (ADR-0015),
	// submitted by `nexus builder register`.
	ErrNotRegistered   = errors.New("builder is not registered on the authority chain")
	ErrDescriptorStale = errors.New("on-chain service descriptor differs from the local configuration")
)

// StateReader is the read-only Hub surface the registrar needs. A descriptor update no longer needs the
// service key authorization nonce (the frozen-contract MsgUpdateServiceDescriptor carries no detached
// authorization signature), so QueryCurrentServiceKey is no longer required here.
type StateReader interface {
	QueryBuilder(context.Context, string) (chaincli.BuilderState, error)
	QueryServiceDescriptor(context.Context, string, string, uint64) (chaincli.ServiceDescriptorState, error)
	LatestHeight(context.Context) (uint64, error)
}

type Registrar struct {
	log           *slog.Logger
	store         kv.Store
	state         StateReader
	submit        coordinator.BuilderSubmitter
	accountSigner signer.Signer
	serviceSigner signer.Signer
	identity      config.IdentityConfig
	tlsPubKeyHash string // public key hash of the ingress self-signed certificate; empty for plaintext ingress
	// The polling cadence for waiting on a broadcast descriptor update to be committed; the update must be
	// in effect by the time `nexus builder register` returns, otherwise the operator's immediately
	// following `nexus start` (which only checks and never submits) would be rejected.
	descriptorPollInterval time.Duration
	descriptorWaitTimeout  time.Duration
	authority              config.BuilderAuthority
}

type desiredState struct {
	ChainID         string
	Builder         string
	ServicePubKey   string
	ServiceKeyProof string
	// Endpoints is already canonicalized: sorted ascending by (kind, uri), with each kind unique.
	Endpoints []chaincli.ServiceEndpoint
	Height    uint64
}

type observation struct {
	ChainID           string `json:"chain_id"`
	Builder           string `json:"builder"`
	Height            uint64 `json:"height"`
	ServiceKeyStatus  string `json:"service_key_status"`
	DescriptorVersion uint64 `json:"descriptor_version"`
	DescriptorHash    string `json:"descriptor_hash"`
}

func New(
	log *slog.Logger,
	store kv.Store,
	state StateReader,
	submit coordinator.BuilderSubmitter,
	accountSigner signer.Signer,
	serviceSigner signer.Signer,
	identity config.IdentityConfig,
	authority config.BuilderAuthority,
	opts ...Option,
) *Registrar {
	if log == nil {
		log = slog.Default()
	}
	r := &Registrar{
		log: log, store: store, state: state, submit: submit,
		accountSigner: accountSigner, serviceSigner: serviceSigner,
		identity: identity, authority: authority,
	}
	r.descriptorPollInterval = defaultDescriptorPollInterval
	r.descriptorWaitTimeout = defaultDescriptorWaitTimeout
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Option adjusts the optional inputs of a Registrar.
type Option func(*Registrar)

// WithTLSPubKeyHash supplies the public key hash of the local ingress certificate, which is written into the descriptor endpoints (see ServiceEndpoints).
func WithTLSPubKeyHash(hash string) Option {
	return func(r *Registrar) { r.tlsPubKeyHash = strings.TrimSpace(hash) }
}

// WithDescriptorWait adjusts the polling interval and the upper bound for waiting on a descriptor update to be committed (500ms / 60s by default).
func WithDescriptorWait(interval, timeout time.Duration) Option {
	return func(r *Registrar) {
		if interval > 0 {
			r.descriptorPollInterval = interval
		}
		if timeout > 0 {
			r.descriptorWaitTimeout = timeout
		}
	}
}

const (
	defaultDescriptorPollInterval = 500 * time.Millisecond
	defaultDescriptorWaitTimeout  = 60 * time.Second
)

// Start only checks that the on-chain registration state and descriptor match the local configuration and
// sends no transaction at all; registering and changing the descriptor go through `nexus builder register`
// (Ensure).
// When the chain is temporarily unreachable: without TLS it logs a WARN and continues starting; with TLS it
// refuses to start, because the fingerprint cannot be checked and the TLS port must not be opened.
func (r *Registrar) Start(ctx context.Context) error {
	err := r.Check(ctx)
	if err == nil {
		return nil
	}
	if r.tlsPubKeyHash == "" && isDeferredSubmitError(err) {
		r.log.Warn("builder registration check deferred pending Hub reconciliation",
			"authority_chain_id", r.authority.Chain.ChainID, "err", err)
		return nil
	}
	return err
}

// Check verifies that the Builder is registered, that its service key is ACTIVE, and that the current
// descriptor matches the local configuration (endpoints, tls_pubkey_hash). On success it saves an observation.
func (r *Registrar) Check(ctx context.Context) error {
	if r.accountSigner == nil {
		r.log.Warn("builder registration check skipped: signer not configured")
		return nil
	}
	if r.serviceSigner == nil {
		return fmt.Errorf("builder service signer is required")
	}
	if r.state == nil || r.store == nil {
		return fmt.Errorf("builder registration state reader and store are required")
	}
	height, err := r.state.LatestHeight(ctx)
	if err != nil {
		return fmt.Errorf("builder registration check: latest Hub height: %w", err)
	}
	desired, err := r.desired(height)
	if err != nil {
		return err
	}
	builder, err := r.state.QueryBuilder(ctx, desired.Builder)
	switch {
	case errors.Is(err, chaincli.ErrNotFound):
		return fmt.Errorf("%w: %s; run `nexus builder register` with the operator key", ErrNotRegistered, desired.Builder)
	case err != nil:
		return fmt.Errorf("builder registration check: query Builder: %w", err)
	}
	if err := validateBuilderOperational(builder); err != nil {
		return err
	}
	if builder.CurrentDescriptorVersion == 0 {
		return fmt.Errorf("%w: current descriptor version is zero", ErrDescriptorStale)
	}
	descriptor, err := r.state.QueryServiceDescriptor(ctx, participantTypeBuilder, desired.Builder, builder.CurrentDescriptorVersion)
	if err != nil {
		return fmt.Errorf("builder registration check: query ServiceDescriptor: %w", err)
	}
	if !r.descriptorMatches(descriptor, desired) {
		return fmt.Errorf("%w (version %d): %s; run `nexus builder register` with the operator key",
			ErrDescriptorStale, descriptor.DescriptorVersion, describeDescriptorDiff(descriptor, desired))
	}
	return r.saveObservation(desired, builder, descriptor)
}

// describeDescriptorDiff spells out where the mismatch is: the fingerprint (tls_pubkey_hash) or the endpoints themselves.
func describeDescriptorDiff(current chaincli.ServiceDescriptorState, desired desiredState) string {
	onChain := map[string]chaincli.ServiceEndpoint{}
	for _, endpoint := range current.Endpoints {
		onChain[endpoint.Kind.String()+"|"+endpoint.URI] = endpoint
	}
	for _, want := range desired.Endpoints {
		got, ok := onChain[want.Kind.String()+"|"+want.URI]
		if !ok {
			return fmt.Sprintf("endpoint %s %s is not on chain", want.Kind.String(), want.URI)
		}
		if got.TLSPubKeyHash != want.TLSPubKeyHash {
			return fmt.Sprintf("endpoint %s tls_pubkey_hash on chain is %q, local certificate is %q",
				want.URI, got.TLSPubKeyHash, want.TLSPubKeyHash)
		}
		if got.ProtocolVersion != want.ProtocolVersion {
			return fmt.Sprintf("endpoint %s protocol_version on chain is %q, configured %q", want.URI, got.ProtocolVersion, want.ProtocolVersion)
		}
	}
	return "endpoint set differs"
}

func (r *Registrar) Stop(context.Context) error { return nil }

func (r *Registrar) Ensure(ctx context.Context) error {
	if r.accountSigner == nil {
		r.log.Warn("builder auto-registration skipped: signer not configured")
		return nil
	}
	if r.serviceSigner == nil {
		return fmt.Errorf("builder service signer is required")
	}
	if r.state == nil || r.submit == nil || r.store == nil {
		return fmt.Errorf("builder registration state reader, submitter, and store are required")
	}
	height, err := r.state.LatestHeight(ctx)
	if err != nil {
		return fmt.Errorf("builder registration: latest Hub height: %w", err)
	}
	desired, err := r.desired(height)
	if err != nil {
		return err
	}

	builder, err := r.state.QueryBuilder(ctx, desired.Builder)
	switch {
	case err == nil:
		if err := validateBuilderOperational(builder); err != nil {
			return err
		}
	case errors.Is(err, chaincli.ErrNotFound):
		builder, err = r.register(ctx, desired)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("builder registration: query Builder: %w", err)
	}

	descriptor, err := r.ensureDescriptor(ctx, desired, builder)
	if err != nil {
		return err
	}
	return r.saveObservation(desired, builder, descriptor)
}

func (r *Registrar) register(ctx context.Context, desired desiredState) (chaincli.BuilderState, error) {
	_, submitErr := r.submit.SubmitRegisterBuilder(ctx, chaincli.RegisterBuilderTx{
		Builder: desired.Builder, ServicePubKey: desired.ServicePubKey,
		ServiceKeyProof: desired.ServiceKeyProof, AuthorizationNonce: initialServiceKeyNonce,
		Endpoints: desired.Endpoints,
	})
	queried, queryErr := r.state.QueryBuilder(ctx, desired.Builder)
	if queryErr == nil {
		if err := validateBuilderOperational(queried); err != nil {
			return chaincli.BuilderState{}, err
		}
		return queried, nil
	}
	if submitErr != nil {
		if errors.Is(queryErr, chaincli.ErrNotFound) && isUnknownBroadcast(submitErr) {
			return chaincli.BuilderState{}, fmt.Errorf("%w: %v", ErrPendingRegistration, submitErr)
		}
		return chaincli.BuilderState{}, fmt.Errorf("builder registration: submit RegisterBuilder: %w", submitErr)
	}
	if !errors.Is(queryErr, chaincli.ErrNotFound) {
		return chaincli.BuilderState{}, fmt.Errorf("builder registration: confirm Builder: %w", queryErr)
	}
	// BroadcastTx is synchronous CheckTx. The state may not be committed until
	// the next block, but version 1 facts are fixed by MsgRegisterBuilder: the
	// registered service key is ACTIVE by construction. This assumes a just-broadcast transaction will be
	// committed; the next Check / Query is the authoritative one.
	return chaincli.BuilderState{
		Address: desired.Builder, ServiceKeyStatus: "ACTIVE",
		CurrentDescriptorVersion: 1,
	}, nil
}

func (r *Registrar) ensureDescriptor(ctx context.Context, desired desiredState, builder chaincli.BuilderState) (chaincli.ServiceDescriptorState, error) {
	if builder.CurrentDescriptorVersion == 0 {
		return chaincli.ServiceDescriptorState{}, fmt.Errorf("builder current descriptor version is zero")
	}
	descriptor, err := r.state.QueryServiceDescriptor(ctx, participantTypeBuilder, desired.Builder, builder.CurrentDescriptorVersion)
	if errors.Is(err, chaincli.ErrNotFound) && builder.CurrentDescriptorVersion == 1 {
		// BroadcastTx is only a synchronous CheckTx: a just-broadcast MsgRegisterBuilder may not be committed
		// yet, but the content of version 1 is fixed by that message, so no follow-up update is needed or wanted.
		return r.descriptorObservation(desired, 1)
	}
	if err != nil {
		return chaincli.ServiceDescriptorState{}, fmt.Errorf("builder registration: query ServiceDescriptor: %w", err)
	}
	if r.descriptorMatches(descriptor, desired) {
		return descriptor, nil
	}
	if builder.CurrentDescriptorVersion == math.MaxUint64 {
		return chaincli.ServiceDescriptorState{}, fmt.Errorf("builder descriptor version overflow")
	}
	// expected_descriptor_version is the current version; the keeper asserts equality and then writes current+1.
	res, err := r.submit.SubmitUpdateServiceDescriptor(ctx, chaincli.UpdateServiceDescriptorTx{
		OperatorAddress: desired.Builder, ParticipantType: participantTypeBuilder,
		ExpectedDescriptorVersion: builder.CurrentDescriptorVersion, Endpoints: desired.Endpoints,
	})
	if err != nil {
		return chaincli.ServiceDescriptorState{}, fmt.Errorf("builder registration: submit UpdateServiceDescriptor: %w", err)
	}
	// Broadcasting only means CheckTx passed; wait for it to be committed (version becomes current+1) before
	// returning, so the chain already holds the new descriptor when the operator runs `nexus start` next.
	target := builder.CurrentDescriptorVersion + 1
	if err := r.waitForDescriptorVersion(ctx, desired.Builder, target); err != nil {
		return chaincli.ServiceDescriptorState{}, fmt.Errorf("builder registration: descriptor update broadcast (tx %x) but %w", res.TxHash, err)
	}
	descriptor, err = r.state.QueryServiceDescriptor(ctx, participantTypeBuilder, desired.Builder, target)
	if err != nil {
		return r.descriptorObservation(desired, target)
	}
	return descriptor, nil
}

// waitForDescriptorVersion polls QueryBuilder until current_descriptor_version >= want.
func (r *Registrar) waitForDescriptorVersion(ctx context.Context, builder string, want uint64) error {
	deadline := time.Now().Add(r.descriptorWaitTimeout)
	for {
		current, err := r.state.QueryBuilder(ctx, builder)
		if err == nil && current.CurrentDescriptorVersion >= want {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("not yet effective after %s (on-chain descriptor version still %d, want %d); wait for it to land and re-run `nexus builder register`",
				r.descriptorWaitTimeout, current.CurrentDescriptorVersion, want)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(r.descriptorPollInterval):
		}
	}
}

// descriptorObservation assembles the local view of what we believe the chain currently holds: the hash is
// recomputed with the §9.6b formula, and the version is the one this batch of endpoints actually landed at
// (it enters the preimage, so it cannot be omitted).
func (r *Registrar) descriptorObservation(desired desiredState, version uint64) (chaincli.ServiceDescriptorState, error) {
	hash, err := nodecontract.ServiceDescriptorHash(
		sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER, desired.Builder, version,
		desired.Endpoints, nodecontract.DefaultServiceEndpointLimits())
	if err != nil {
		return chaincli.ServiceDescriptorState{}, fmt.Errorf("builder descriptor hash: %w", err)
	}
	return chaincli.ServiceDescriptorState{
		ParticipantType: participantTypeBuilder, OperatorAddress: desired.Builder,
		DescriptorVersion: version, Endpoints: desired.Endpoints,
		DescriptorHash: hash, UpdatedHeight: desired.Height,
	}, nil
}

func (r *Registrar) desired(height uint64) (desiredState, error) {
	chainID := strings.TrimSpace(r.authority.Chain.ChainID)
	if chainID == "" {
		return desiredState{}, fmt.Errorf("builder registration authority chain_id is required")
	}
	builder := r.accountSigner.Address()
	if configured := strings.TrimSpace(r.identity.BuilderAddress); configured != "" && configured != builder {
		return desiredState{}, fmt.Errorf("builder registration identity mismatch: configured %s but signer derives %s", configured, builder)
	}
	endpoints, err := ServiceEndpoints(r.identity, r.tlsPubKeyHash)
	if err != nil {
		return desiredState{}, fmt.Errorf("builder registration: %w", err)
	}
	servicePubKeyBytes := r.serviceSigner.PubKeyCompressed()
	registration, err := nodecontract.ServiceRegistrationBytes(
		chainID, sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER, builder,
		servicePubKeyBytes, initialServiceKeyNonce,
	)
	if err != nil {
		return desiredState{}, fmt.Errorf("builder service key proof: %w", err)
	}
	// The Keeper verifies the proof strictly over this digest (VerifyStrictSecp256k1Digest), so it is
	// signed as is: Sign would hash it once more and a fresh registration would be rejected.
	var digest [32]byte
	copy(digest[:], registration)
	proofBytes, err := r.serviceSigner.SignDigest(digest)
	if err != nil {
		return desiredState{}, fmt.Errorf("builder service key proof: %w", err)
	}
	proof := hex.EncodeToString(proofBytes)
	return desiredState{
		ChainID: chainID, Builder: builder,
		ServicePubKey: hex.EncodeToString(servicePubKeyBytes), ServiceKeyProof: proof,
		Endpoints: endpoints, Height: height,
	}, nil
}

// validateBuilderOperational: the wire v0.4.1 BuilderState carries only the service key status. Admission
// (ADMITTED / REVOKED) is not on this path and is fixed by governance; a Builder whose key was REVOKED can
// send nothing carrying a service signature, so the registration flow fails closed here.
func validateBuilderOperational(builder chaincli.BuilderState) error {
	if !strings.EqualFold(builder.ServiceKeyStatus, "ACTIVE") {
		return fmt.Errorf("builder service key status is %q, want ACTIVE", builder.ServiceKeyStatus)
	}
	return nil
}

// descriptorMatches decides whether the current on-chain descriptor already equals what we want. The
// criterion is field-by-field equality of the endpoints: the frozen-contract on-chain descriptor has no
// validity period, so unchanged content is no reason to resubmit anything, and a restart therefore never
// re-sends MsgUpdateServiceDescriptor.
//
// Along the way it recomputes the §9.6b descriptor_hash and reconciles it against the on-chain value: equal
// content with an unequal hash can only mean the local H_FIELDS_V1 convention has diverged from the
// keeper's. That case is not blocking (the hash never goes on the wire and a submission is still handled
// correctly by the keeper), but it must leave a WARN, or such a divergence would go unnoticed.
func (r *Registrar) descriptorMatches(current chaincli.ServiceDescriptorState, desired desiredState) bool {
	if !nodecontract.ServiceEndpointsEqual(current.Endpoints, desired.Endpoints) {
		return false
	}
	expected, err := nodecontract.ServiceDescriptorHash(
		sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER, desired.Builder, current.DescriptorVersion,
		desired.Endpoints, nodecontract.DefaultServiceEndpointLimits())
	if err != nil {
		r.log.Warn("builder descriptor hash could not be recomputed", "err", err)
		return true
	}
	if current.DescriptorHash != "" && current.DescriptorHash != expected {
		r.log.Warn("builder descriptor hash disagrees with the local TRUEOPEN_SERVICE_DESCRIPTOR_V1 recomputation",
			"descriptor_version", current.DescriptorVersion,
			"chain_hash", current.DescriptorHash, "local_hash", expected)
	}
	return true
}

func (r *Registrar) saveObservation(desired desiredState, builder chaincli.BuilderState, descriptor chaincli.ServiceDescriptorState) error {
	data, err := json.Marshal(observation{
		ChainID: desired.ChainID, Builder: desired.Builder, Height: desired.Height,
		ServiceKeyStatus:  builder.ServiceKeyStatus,
		DescriptorVersion: descriptor.DescriptorVersion, DescriptorHash: descriptor.DescriptorHash,
	})
	if err != nil {
		return fmt.Errorf("builder registration observation: %w", err)
	}
	if err := r.store.Set(kv.NSBuilderReg, desired.ChainID+"\x1f"+desired.Builder, data); err != nil {
		return fmt.Errorf("builder registration observation: %w", err)
	}
	return nil
}

func isUnknownBroadcast(err error) bool {
	var submitErr *coordinator.SubmissionError
	return errors.As(err, &submitErr) && submitErr.Phase == coordinator.SubmissionBroadcast && !submitErr.Definitive
}

func isDeferredSubmitError(err error) bool {
	if errors.Is(err, ErrPendingRegistration) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var submitErr *coordinator.SubmissionError
	if errors.As(err, &submitErr) && !submitErr.Definitive {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "deadline exceeded") || strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "connection refused") || strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "no such host") || strings.Contains(msg, "endpoint unavailable")
}
