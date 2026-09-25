// Package sdkauth verifies the SDK request envelope SDKRequestEnvelopeV1 (Interface & Topic Catalogue v1.5 §3.0).
// All SDK -> IngressAPI requests share this envelope: anti cross-chain replay (chain_id), anti cross-method replay
// (method/endpoint), anti stale replay (expiry), request body binding (body_digest),
// user chain-account signature (signer_address + signature).
//
// Signing convention (inverse of internal/signer):
//
//	sign_bytes = domain separator + length-prefixed concatenation of each field (SignBytes)
//	signature  = secp256k1_RFC6979( sha256(sign_bytes) ), 64 bytes r||s
//
// Note: the documented field table has no signer_pubkey; secp256k1 without a recovery bit cannot derive the public key
// from the signature, so nexus requires the envelope to carry the compressed public key and checks bech32(pubkey)==signer_address.
// If the finalised SDK wire document adopts another way of carrying the public key (e.g. on-chain account query), align here.
package sdkauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sync"

	"github.com/TrueOpen/nexus/internal/signer"
)

// RequestDomain is the fixed domain separator (v1.5 §3.0).
const RequestDomain = "TRUEOPEN_SDK_REQUEST_V1"

// Errors aligned with the documented error codes (ingress maps them to connect codes + error code strings).
var (
	ErrInvalidSignature = errors.New("SDK_AUTH_INVALID_SIGNATURE")
	ErrExpired          = errors.New("SDK_AUTH_EXPIRED")
	ErrReplay           = errors.New("SDK_AUTH_REPLAY")
	ErrMalformed        = errors.New("NEXUS_INGRESS_MALFORMED")
	// ErrMisconfigured is a caller bug, not a client error: see VerifyOpts.AllowHeightExpiry.
	ErrMisconfigured = errors.New("NEXUS_SDKAUTH_MISCONFIGURED")
)

// ReplayCache records accepted signer nonces. Returns false if the key has been seen before.
type ReplayCache interface {
	StoreOnce(key string, expiresAtMS int64, nowMS int64) bool
}

// MemoryReplayCache is an in-process replay cache; with multiple production replicas the caller may substitute a shared KV.
type MemoryReplayCache struct {
	mu      sync.Mutex
	entries map[string]int64
}

func NewMemoryReplayCache() *MemoryReplayCache {
	return &MemoryReplayCache{entries: make(map[string]int64)}
}

func (c *MemoryReplayCache) StoreOnce(key string, expiresAtMS int64, nowMS int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, exp := range c.entries {
		if exp > 0 && exp <= nowMS {
			delete(c.entries, k)
		}
	}
	if _, ok := c.entries[key]; ok {
		return false
	}
	c.entries[key] = expiresAtMS
	return true
}

// Envelope is SDKRequestEnvelopeV1 (internal representation isomorphic to the proto).
type Envelope struct {
	RequestDomain      string
	ChainID            string
	Method             string
	Endpoint           string
	SessionID          string
	TaskID             string
	RequestNonce       []byte
	ExpiryHeightOrTime int64
	BodyDigest         []byte
	SignerAddress      string
	Signature          []byte
	SignerPubKey       []byte // 33-byte compressed public key (needed for nexus-side verification, see package comment)
}

// VerifyOpts is the verification environment: this node's chain ID, the called method, current time and expected body digest.
type VerifyOpts struct {
	ChainID      string
	Method       string
	NowMS        int64
	WantBody     []byte // expected body_digest (handler computes it via BodyDigest(fields...)); nil = skip body check
	Bech32Prefix string // account address prefix (for checking signer_address)
	ReplayCache  ReplayCache
	// AllowHeightExpiry accepts an expiry below HeightExpiryThreshold (a chain height) without
	// checking it. Only OpenTask sets it: its height expiry and nonce are checked by the taskdata
	// Authorizer against the chain. A caller that allows it must not pass a ReplayCache, since
	// this package cannot bound a height expiry; Verify rejects that combination.
	AllowHeightExpiry bool
}

// SignBytes canonical sign bytes: domain separator first, then each field with a 4-byte big-endian length prefix, eliminating concatenation ambiguity.
// The SDK side must construct them by the same convention.
func SignBytes(e *Envelope) []byte {
	var buf bytes.Buffer
	fields := [][]byte{
		[]byte(RequestDomain),
		[]byte(e.ChainID),
		[]byte(e.Method),
		[]byte(e.Endpoint),
		[]byte(e.SessionID),
		[]byte(e.TaskID),
		e.RequestNonce,
		i64be(e.ExpiryHeightOrTime),
		e.BodyDigest,
	}
	for _, f := range fields {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(f)))
		buf.Write(l[:])
		buf.Write(f)
	}
	return buf.Bytes()
}

// BodyPreimage is the canonical encoding of the request body: length-prefixed field concatenation, not hashed.
//
// What is passed to signer.VerifySig must be this preimage: VerifySig sha256-hashes the message itself
// (byte-for-byte identical to Cosmos PubKey.VerifySignature), while the signer signed
// sha256(preimage). Passing BodyDigest adds an extra hash layer on the verifier side and the signature never verifies.
func BodyPreimage(fields ...[]byte) []byte {
	var buf bytes.Buffer
	var l [4]byte
	for _, f := range fields {
		binary.BigEndian.PutUint32(l[:], uint32(len(f)))
		buf.Write(l[:])
		buf.Write(f)
	}
	return buf.Bytes()
}

// BodyDigest is the canonical digest of the request body: sha256 over BodyPreimage. It is the value of the
// body_digest field in the envelope, not the message used for signature verification.
// Each IngressAPI method defines its own field order in its handler (see ingress/service.go).
func BodyDigest(fields ...[]byte) []byte {
	digest := sha256.Sum256(BodyPreimage(fields...))
	return digest[:]
}

// An expiry below HeightExpiryThreshold is a chain height, at or above it Unix milliseconds.
// 10^12 ms ~ year 2001; chain heights are far smaller. The generic SDK envelope accepts only Unix
// milliseconds; a chain height is accepted only where VerifyOpts.AllowHeightExpiry says another
// check owns it (OpenTask).
const HeightExpiryThreshold = int64(1_000_000_000_000)

// Verify fully validates the envelope. Order: structure -> chain_id -> method -> expiry -> body_digest ->
// signature -> address check. nil means the envelope is trusted and the caller may use e.SignerAddress as the requester identity.
func Verify(e *Envelope, opts VerifyOpts) error {
	if opts.AllowHeightExpiry && opts.ReplayCache != nil {
		return ErrMisconfigured
	}
	if e == nil || e.RequestDomain != RequestDomain ||
		e.SignerAddress == "" || len(e.Signature) == 0 || len(e.SignerPubKey) == 0 || len(e.RequestNonce) == 0 {
		return ErrMalformed
	}
	if e.ChainID != opts.ChainID || e.Method != opts.Method {
		return ErrMalformed
	}
	if e.ExpiryHeightOrTime < HeightExpiryThreshold {
		if !opts.AllowHeightExpiry {
			return ErrMalformed
		}
	} else if e.ExpiryHeightOrTime < opts.NowMS {
		return ErrExpired
	}
	if opts.WantBody != nil && !bytes.Equal(e.BodyDigest, opts.WantBody) {
		return ErrMalformed
	}
	if !signer.VerifySig(e.SignerPubKey, SignBytes(e), e.Signature) {
		return ErrInvalidSignature
	}
	derived, err := signer.AddressFromPubKey(opts.Bech32Prefix, e.SignerPubKey)
	if err != nil || derived != e.SignerAddress {
		return ErrInvalidSignature // public key does not match the claimed address = impersonation
	}
	if opts.ReplayCache != nil {
		if !opts.ReplayCache.StoreOnce(replayKey(e), e.ExpiryHeightOrTime, opts.NowMS) {
			return ErrReplay
		}
	}
	return nil
}

func i64be(v int64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(v))
	return b[:]
}

func replayKey(e *Envelope) string {
	return e.RequestDomain + "\x00" + e.ChainID + "\x00" + e.SignerAddress + "\x00" + hex.EncodeToString(e.RequestNonce)
}
