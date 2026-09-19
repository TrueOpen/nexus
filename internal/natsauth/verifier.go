package natsauth

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/TrueOpen/wire/bus"

	"github.com/TrueOpen/nexus/internal/chaincli"
)

// Request holds the fields extracted from the NATS authorization request that §5.14.3 uses.
type Request struct {
	UserNkey    string // user public key the server assigned to this connection; sub of the issued JWT
	ServerID    string // echoed back as the response aud
	ClientNonce string // nonce from the server INFO
	ConnectNkey string // CONNECT.nkey; empty in operator mode, where Cortex connects with the sentinel JWT
	ConnectSig  string // CONNECT.sig, base64url (nats.go uses RawURLEncoding)
	AuthToken   string // CONNECT.auth_token = binding token
	// ConnectJWT is CONNECT.jwt: the AUTH account's sentinel user JWT (bearer, no permissions, public, non-secret data).
	// In operator mode the server only routes to the auth callout when CONNECT carries a user JWT, so Cortex uses it as the door-knocker (sentinel).
	// It is informational only: the server already verified this JWT; this service neither re-verifies it nor treats it as identity.
	// Its sole use is the sentinel attribute in rejection logs (whether a JWT was present), helping operators tell sentinel access from client misconfiguration.
	ConnectJWT string
}

// Decision is the conclusion after all nine steps pass: which identity to issue for.
type Decision struct {
	OperatorAddress string
	NATSUserPubkey  string
	Fields          bus.BindingFields
}

// VerifierConfig holds the nine-step verifier's dependencies: local chain_id, chain view, allowed clock skew and time source.
type VerifierConfig struct {
	ChainID      string
	Chain        ChainReader
	MaxClockSkew time.Duration
	Now          func() time.Time
}

// Verifier executes the nine steps of §5.14.3 in fixed order; any failing step returns its RejectError immediately without continuing.
type Verifier struct {
	cfg VerifierConfig
}

// NewVerifier constructs a nine-step verifier; Now defaults to time.Now when nil.
func NewVerifier(cfg VerifierConfig) *Verifier {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Verifier{cfg: cfg}
}

// Verify runs the nine checks in the fixed order of §5.14.3; no chain query is issued before step 7.
func (v *Verifier) Verify(ctx context.Context, req Request) (Decision, error) {
	// 1. token prefix / base64 / length / strict decode / schema_version; 3. participant_type and address shape
	//    -- all done by bus in one pass; any failure is BINDING_MALFORMED.
	// Documented deviation (1): row 4 of the spec table files nats_user_pubkey validity under NKEY_MISMATCH,
	// but the shape check is delegated to bus.DecodeBinding, which runs before step 4,
	// so a textually invalid nats_user_pubkey is rejected earlier as BINDING_MALFORMED;
	// NKEY_MISMATCH is reserved for "both valid but not equal".
	// Documented deviation (2): row 4 of the spec table assumes CONNECT always carries an nkey. In operator mode the
	// server requires CONNECT to present a user JWT before routing to the auth callout, and nats.go does not allow
	// nkey and jwt together, so Cortex sends sentinel JWT + sig + auth_token with an empty nkey. Identity is then taken
	// from nats_user_pubkey in the binding (endorsed by the on-chain service key signature), and step 4 degrades to "if given, it must be equal".
	raw, err := bus.DecodeBindingToken(req.AuthToken)
	if err != nil {
		return Decision{}, RejectWithCause(CodeBindingMalformed, err, "binding token is malformed")
	}
	binding, err := bus.DecodeBinding(raw)
	if err != nil {
		return Decision{}, RejectWithCause(CodeBindingMalformed, err, "binding declaration is malformed")
	}
	fields := binding.Fields

	// 2. chain_id
	if fields.ChainID != v.cfg.ChainID {
		return Decision{}, Reject(CodeChainIDMismatch, "binding chain_id %q is not %q", fields.ChainID, v.cfg.ChainID)
	}

	// 4. If CONNECT carries an nkey it must equal the NATS public key in the binding byte for byte (validity already checked by bus);
	//    if absent (sentinel access) skip, and the binding's public key carries the identity.
	if req.ConnectNkey != "" && req.ConnectNkey != fields.NATSUserPubkey {
		return Decision{}, Reject(CodeNkeyMismatch, "connect nkey does not equal the bound nats_user_pubkey")
	}

	// 5. Verify with the binding's NATS public key that CONNECT.sig is a signature over the server nonce.
	//    fields.NATSUserPubkey is used instead of req.ConnectNkey: identical when both are equal, and when nkey is empty
	//    it is the only usable key -- this step is the proof of possession of the private key; without it the binding could be replayed.
	if err := verifyNonceSignature(fields.NATSUserPubkey, req.ClientNonce, req.ConnectSig); err != nil {
		return Decision{}, err
	}

	// 6. issued_at must not come from the future. The comparison must stay in the uint64 domain: converting to int64
	//    would wrap values >= 2^63 to negative and let them "pass" this step.
	limitMS := v.cfg.Now().Add(v.cfg.MaxClockSkew).UnixMilli()
	if limitMS < 0 || fields.IssuedAtUnixMS > uint64(limitMS) {
		return Decision{}, Reject(CodeBindingMalformed, "issued_at_unix_ms %d is in the future", fields.IssuedAtUnixMS)
	}

	// 7. On-chain current service key: exists, ACTIVE, nonce equal
	key, err := v.cfg.Chain.CurrentServiceKey(ctx, fields.OperatorAddress)
	switch {
	case errors.Is(err, chaincli.ErrNotFound):
		return Decision{}, Reject(CodeServiceKeyNotActive, "no current service key for %s", fields.OperatorAddress)
	case err != nil:
		// CachedChain already wraps as CHAIN_UNAVAILABLE; wrap once more as a backstop for other ChainReader
		// implementations so what leaves here is always a closed-set error code.
		return Decision{}, asChainUnavailable(err)
	case !strings.EqualFold(key.Status, "ACTIVE"):
		return Decision{}, Reject(CodeServiceKeyNotActive, "service key status is %s", key.Status)
	case key.AuthorizationNonce != fields.ServiceAuthorizationNonce:
		return Decision{}, Reject(CodeServiceKeyNonceMismatch, "binding nonce %d, chain nonce %d", fields.ServiceAuthorizationNonce, key.AuthorizationNonce)
	}

	// 8. Verify the binding signature with the on-chain current_service_pubkey (projection and rules in wire §7.5)
	pubkey, err := hex.DecodeString(key.ServicePubKey)
	if err != nil || len(pubkey) != 33 {
		return Decision{}, Reject(CodeBindingSignatureInvalid, "chain service pubkey is not 33-byte compressed hex")
	}
	if err := bus.VerifyBindingSignature(fields, binding.Signature, pubkey); err != nil {
		return Decision{}, RejectWithCause(CodeBindingSignatureInvalid, err, "binding signature does not verify under the current service key")
	}

	// 9. Cortex stable identity row exists
	if _, err := v.cfg.Chain.CortexNode(ctx, fields.OperatorAddress); err != nil {
		if errors.Is(err, chaincli.ErrNotFound) {
			return Decision{}, Reject(CodeCortexNotRegistered, "%s has no CortexNode row", fields.OperatorAddress)
		}
		return Decision{}, asChainUnavailable(err)
	}

	return Decision{OperatorAddress: fields.OperatorAddress, NATSUserPubkey: fields.NATSUserPubkey, Fields: fields}, nil
}

// asChainUnavailable guarantees a chain-query error carries a closed-set code: an existing RejectError passes through,
// anything else (non-CachedChain ChainReader implementations may return bare errors) is wrapped as CHAIN_UNAVAILABLE,
// with the raw error attached only as Cause, never in the response text.
func asChainUnavailable(err error) error {
	if errors.As(err, new(*RejectError)) {
		return err
	}
	return RejectWithCause(CodeChainUnavailable, err, "chain query failed")
}

// verifyNonceSignature checks that CONNECT.sig is pubkey's signature over the server nonce;
// any failure is NONCE_SIGNATURE_INVALID, without distinguishing decoding errors from signature failures.
func verifyNonceSignature(pubkey, nonce, sig string) error {
	if nonce == "" || sig == "" {
		return Reject(CodeNonceSignatureInvalid, "connect nonce or signature is missing")
	}
	raw, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		// Also accept padded standard base64 (some client libraries); reject only if both fail.
		if raw, err = base64.StdEncoding.DecodeString(sig); err != nil {
			return Reject(CodeNonceSignatureInvalid, "connect sig is not base64")
		}
	}
	kp, err := nkeys.FromPublicKey(pubkey)
	if err != nil {
		return Reject(CodeNonceSignatureInvalid, "bound nats_user_pubkey is not a public key")
	}
	if err := kp.Verify([]byte(nonce), raw); err != nil {
		return Reject(CodeNonceSignatureInvalid, "nonce signature does not verify")
	}
	return nil
}
