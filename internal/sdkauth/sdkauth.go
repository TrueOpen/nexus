// Package sdkauth verifies the SDK request envelope SDKRequestEnvelopeV2 and the session grant it
// may carry.
//
// A User request to the Builder Ingress is signed as EIP-712 typed data in the
// "TrueOpen SDK Request" domain (chainId = the chain's EVM chain ID), so a browser wallet can sign
// it:
//
//	SDKRequest(string chainId,string method,string endpoint,bytes32 sessionId,bytes32 taskId,
//	           bytes32 requestNonce,uint64 expiryHeightOrTime,bytes32 bodyDigest,bytes32 sessionGrantHash)
//
// The signature is 65 bytes R||S||V and the verifier recovers the signer from it; no caller-supplied
// public key is used. Without a session grant the request is signed by the user's wallet: it must
// recover to signer_address, whose account must hold that public key on chain. With a grant, the
// wallet has signed a SessionGrant once and a short-lived session key signs the request; the
// request must recover to the grant's session key, and only a closed set of methods accepts it.
//
// Verification runs in a fixed order and stops at the first failure, which fixes the error code:
//
//  1. format                      -> NEXUS_INGRESS_MALFORMED
//  2. session method set          -> SDK_AUTH_SESSION_METHOD_NOT_ALLOWED
//  3. session grant               -> SDK_AUTH_SESSION_GRANT_INVALID / SDK_AUTH_SESSION_GRANT_EXPIRED
//  4. request signature           -> SDK_AUTH_INVALID_SIGNATURE
//  5. request expiry, then replay -> SDK_AUTH_EXPIRED, SDK_AUTH_REPLAY
//
// The body digest signed in step 4 is the one the verifier recomputes from the request, so a body
// changed in transit fails as a signature, not as a format error.
package sdkauth

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"

	"github.com/TrueOpen/nexus/internal/eip712"
	"github.com/TrueOpen/nexus/internal/nodecontract"
)

const (
	// RequestDomain is the envelope's request_domain. It is checked and enters the replay key, but it
	// is not signed.
	RequestDomain = "TRUEOPEN_SDK_REQUEST_V2"
	// DomainName and DomainVersion name the EIP-712 domain of SDK requests and session grants.
	DomainName    = "TrueOpen SDK Request"
	DomainVersion = "1"
	// EndpointPrefix is the procedure prefix every endpoint carries: "/nexus.v1.IngressAPI/<Method>".
	EndpointPrefix = "/nexus.v1.IngressAPI/"

	requestType = "SDKRequest(string chainId,string method,string endpoint,bytes32 sessionId," +
		"bytes32 taskId,bytes32 requestNonce,uint64 expiryHeightOrTime,bytes32 bodyDigest,bytes32 sessionGrantHash)"
	grantType = "SessionGrant(string chainId,string user,address sessionKey,uint64 expiryHeight,bytes32 grantNonce)"
)

// Error codes. Ingress maps each to a connect code; the text is the wire error code.
var (
	ErrMalformed               = errors.New("NEXUS_INGRESS_MALFORMED")
	ErrSessionMethodNotAllowed = errors.New("SDK_AUTH_SESSION_METHOD_NOT_ALLOWED")
	ErrSessionGrantInvalid     = errors.New("SDK_AUTH_SESSION_GRANT_INVALID")
	ErrSessionGrantExpired     = errors.New("SDK_AUTH_SESSION_GRANT_EXPIRED")
	ErrInvalidSignature        = errors.New("SDK_AUTH_INVALID_SIGNATURE")
	ErrExpired                 = errors.New("SDK_AUTH_EXPIRED")
	ErrReplay                  = errors.New("SDK_AUTH_REPLAY")
	// ErrUnavailable is a chain read (current height, account key) that failed; the request may be
	// retried. It never means the request is bad.
	ErrUnavailable = errors.New("NEXUS_SDKAUTH_CHAIN_UNAVAILABLE")
	// ErrMisconfigured is a caller bug, not a client error: see VerifyOpts.AllowHeightExpiry.
	ErrMisconfigured = errors.New("NEXUS_SDKAUTH_MISCONFIGURED")
	// ErrNoAccountKey is what an AccountKeys implementation returns when the account does not exist or
	// holds no public key yet. Any other error is treated as the chain being unavailable.
	ErrNoAccountKey = errors.New("sdkauth: account has no public key on chain")
)

// Chain is the chain state verification reads.
type Chain interface {
	// CurrentHeight is the latest committed height, bounding session grant windows.
	CurrentHeight(ctx context.Context) (uint64, error)
	// AccountPubKey returns the 33-byte compressed public key the account holds on chain, or
	// ErrNoAccountKey when the account does not exist or has no key yet.
	AccountPubKey(ctx context.Context, address string) ([]byte, error)
}

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

// SessionGrant is SessionGrantV1.
type SessionGrant struct {
	ChainID       string
	User          string // canonical bech32 address of the granting user
	SessionKey    []byte // raw 20-byte address of the session key
	ExpiryHeight  uint64
	GrantNonce    []byte // 32 bytes
	UserSignature []byte // 65 bytes R||S||V over the SessionGrant digest
}

// Envelope is SDKRequestEnvelopeV2 (the deprecated signer_pubkey is not carried: it is ignored).
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
	SessionGrant       *SessionGrant
}

// VerifyOpts is the verification environment.
type VerifyOpts struct {
	ChainID    string // the chain's Cosmos chain-id
	EVMChainID uint64 // the chain's EVM chain ID, the domain chainId
	Method     string // the method actually called
	NowMS      int64
	// Body is the body digest the verifier recomputed from the request with the method's
	// TRUEOPEN_SDK_BODY_*_V1 domain. It is what enters the signed digest.
	Body         [32]byte
	Bech32Prefix string
	ReplayCache  ReplayCache
	// AllowHeightExpiry accepts an expiry below HeightExpiryThreshold (a chain height) without
	// checking it. Only OpenTask sets it: its height expiry and nonce are checked by the taskdata
	// Authorizer against the chain. A caller that allows it must not pass a ReplayCache, since this
	// package cannot bound a height expiry; Verify rejects that combination.
	AllowHeightExpiry bool
	// SessionAllowed says the method may be signed by a session key under a grant.
	SessionAllowed bool
	Chain          Chain
	// MaxSessionGrantBlocks bounds a grant's expiry above the current height. Every Task Builder of a
	// network must use the same value.
	MaxSessionGrantBlocks uint64
}

// An expiry below HeightExpiryThreshold is a chain height, at or above it Unix milliseconds.
// 10^12 ms ~ year 2001; chain heights are far smaller. The generic SDK envelope accepts only Unix
// milliseconds; a chain height is accepted only where VerifyOpts.AllowHeightExpiry says another
// check owns it (OpenTask).
const HeightExpiryThreshold = int64(1_000_000_000_000)

// Hash32Hex decodes a session or task ID: exactly 64 lowercase hex characters, no 0x prefix.
func Hash32Hex(field, value string) ([32]byte, error) {
	var out [32]byte
	if len(value) != 64 {
		return out, fmt.Errorf("%w: %s must be 64 lowercase hex characters", ErrMalformed, field)
	}
	for _, c := range value {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return out, fmt.Errorf("%w: %s must be 64 lowercase hex characters", ErrMalformed, field)
		}
	}
	raw, _ := hex.DecodeString(value)
	copy(out[:], raw)
	return out, nil
}

// domainSeparator is the "TrueOpen SDK Request" domain separator.
func domainSeparator(evmChainID uint64) [32]byte {
	return eip712.DomainSeparator(DomainName, DomainVersion, evmChainID)
}

// SessionGrantHash is hashStruct(SessionGrant): the value a request carrying the grant signs as
// sessionGrantHash.
func SessionGrantHash(g *SessionGrant) ([32]byte, error) {
	if g == nil {
		return [32]byte{}, fmt.Errorf("%w: session grant is absent", ErrSessionGrantInvalid)
	}
	if len(g.SessionKey) != 20 || len(g.GrantNonce) != 32 || g.User == "" || g.ChainID == "" {
		return [32]byte{}, fmt.Errorf("%w: session grant fields are malformed", ErrSessionGrantInvalid)
	}
	var key [20]byte
	copy(key[:], g.SessionKey)
	return eip712.HashStruct(grantType,
		eip712.String(g.ChainID), eip712.String(g.User), eip712.Address(key),
		eip712.Uint(g.ExpiryHeight), g.GrantNonce), nil
}

// SessionGrantDigest is the digest the user's wallet signs for a grant.
func SessionGrantDigest(g *SessionGrant, evmChainID uint64) ([32]byte, error) {
	hash, err := SessionGrantHash(g)
	if err != nil {
		return [32]byte{}, err
	}
	return eip712.Digest(domainSeparator(evmChainID), hash), nil
}

// RequestDigest is the digest the request signer signs: the SDKRequest typed data over e, with
// bodyDigest and sessionGrantHash as given (the verifier passes its own recomputed values).
func RequestDigest(e *Envelope, body, grantHash [32]byte, evmChainID uint64) ([32]byte, error) {
	sessionID, err := Hash32Hex("session_id", e.SessionID)
	if err != nil {
		return [32]byte{}, err
	}
	taskID, err := Hash32Hex("task_id", e.TaskID)
	if err != nil {
		return [32]byte{}, err
	}
	if len(e.RequestNonce) != 32 {
		return [32]byte{}, fmt.Errorf("%w: request_nonce must be exactly 32 bytes", ErrMalformed)
	}
	if e.ExpiryHeightOrTime <= 0 {
		return [32]byte{}, fmt.Errorf("%w: expiry_height_or_time must be above zero", ErrMalformed)
	}
	hash := eip712.HashStruct(requestType,
		eip712.String(e.ChainID), eip712.String(e.Method), eip712.String(e.Endpoint),
		sessionID[:], taskID[:], e.RequestNonce, eip712.Uint(uint64(e.ExpiryHeightOrTime)),
		body[:], grantHash[:])
	return eip712.Digest(domainSeparator(evmChainID), hash), nil
}

// GrantCheck is the environment a session grant is verified in.
type GrantCheck struct {
	// ChainID is this chain; RequestChainID the chain_id the request carries. The grant must name both.
	ChainID        string
	RequestChainID string
	EVMChainID     uint64
	// User is the account the grant must be for: signer_address of an SDK request, requester_address
	// of a Task data request.
	User      string
	Chain     Chain
	MaxBlocks uint64
}

// GrantError is a session grant verification failure, carrying the SDK error code (Code: one of
// ErrSessionGrantInvalid, ErrSessionGrantExpired, ErrUnavailable). The Task data path maps the same
// failures to its own DATA_ACCESS_SESSION_* codes.
type GrantError struct {
	Code   error
	Reason string
}

func (e *GrantError) Error() string { return e.Code.Error() + ": " + e.Reason }
func (e *GrantError) Unwrap() error { return e.Code }

func grantErr(code error, format string, args ...any) error {
	return &GrantError{Code: code, Reason: fmt.Sprintf(format, args...)}
}

// VerifyGrant checks a session grant and returns its hashStruct (the sessionGrantHash a request
// signs) and the session key address the request must recover to. The grant must be for c.User on
// this chain, be signed by that user's wallet with the public key the account holds on chain, and
// lie inside current_height <= expiry_height <= current_height + MaxBlocks (checked addition).
func VerifyGrant(ctx context.Context, g *SessionGrant, c GrantCheck) ([32]byte, [20]byte, error) {
	var none [32]byte
	var key [20]byte
	if g == nil {
		return none, key, grantErr(ErrSessionGrantInvalid, "session grant is absent")
	}
	if g.ChainID != c.ChainID || g.ChainID != c.RequestChainID {
		return none, key, grantErr(ErrSessionGrantInvalid, "session grant is for chain %q; the request is for %q on chain %q",
			g.ChainID, c.RequestChainID, c.ChainID)
	}
	if g.User != c.User {
		return none, key, grantErr(ErrSessionGrantInvalid, "session grant is for %q, not the request signer %q", g.User, c.User)
	}
	hash, err := SessionGrantHash(g)
	if err != nil {
		return none, key, grantErr(ErrSessionGrantInvalid, "session grant fields are malformed")
	}
	recovered, err := eip712.Recover(eip712.Digest(domainSeparator(c.EVMChainID), hash), g.UserSignature)
	if err != nil {
		return none, key, grantErr(ErrSessionGrantInvalid, "session grant user_signature: %v", err)
	}
	user, err := nodecontract.CanonicalOperatorAddressBytes("user", g.User)
	if err != nil || len(user) != 20 {
		return none, key, grantErr(ErrSessionGrantInvalid, "session grant user is not a canonical address")
	}
	if !bytes.Equal(recovered.Address[:], user) {
		return none, key, grantErr(ErrSessionGrantInvalid, "session grant user_signature does not recover to %q", g.User)
	}
	if err := matchAccountKey(ctx, c.Chain, g.User, recovered.Compressed); err != nil {
		if errors.Is(err, ErrUnavailable) {
			return none, key, grantErr(ErrUnavailable, "%v", err)
		}
		return none, key, grantErr(ErrSessionGrantInvalid, "session grant user: %v", err)
	}
	if c.Chain == nil {
		return none, key, grantErr(ErrUnavailable, "no chain to read the current height from")
	}
	height, err := c.Chain.CurrentHeight(ctx)
	if err != nil || height == 0 {
		return none, key, grantErr(ErrUnavailable, "current height unavailable")
	}
	if c.MaxBlocks > math.MaxUint64-height {
		return none, key, grantErr(ErrSessionGrantInvalid, "session grant window overflows")
	}
	if g.ExpiryHeight < height || g.ExpiryHeight > height+c.MaxBlocks {
		return none, key, grantErr(ErrSessionGrantExpired,
			"session grant expiry %d is outside [%d, %d]", g.ExpiryHeight, height, height+c.MaxBlocks)
	}
	copy(key[:], g.SessionKey)
	return hash, key, nil
}

// matchAccountKey requires the account to hold exactly this public key on chain. A missing account
// or key is a mismatch; a failed read is ErrUnavailable.
func matchAccountKey(ctx context.Context, chain Chain, address string, compressed []byte) error {
	if chain == nil {
		return fmt.Errorf("%w: no chain to read account keys from", ErrUnavailable)
	}
	stored, err := chain.AccountPubKey(ctx, address)
	if errors.Is(err, ErrNoAccountKey) {
		return fmt.Errorf("account %q holds no public key on chain", address)
	}
	if err != nil {
		return fmt.Errorf("%w: read account %q: %v", ErrUnavailable, address, err)
	}
	if !bytes.Equal(stored, compressed) {
		return fmt.Errorf("the recovered key is not the key account %q holds on chain", address)
	}
	return nil
}

// checkUserAddress requires a canonical 20-byte Bech32 address under prefix (any prefix when prefix
// is empty). An address under another prefix is malformed, not an account the chain can be asked about.
func checkUserAddress(address, prefix string) error {
	raw, err := nodecontract.CanonicalOperatorAddressBytes("signer_address", address)
	if err != nil || len(raw) != 20 {
		return fmt.Errorf("%w: signer_address is not a canonical 20-byte address", ErrMalformed)
	}
	if prefix != "" && address[:strings.LastIndex(address, "1")] != prefix {
		return fmt.Errorf("%w: signer_address is not a %q address", ErrMalformed, prefix)
	}
	return nil
}

// checkFormat is step 1: everything a request must satisfy before any signature is looked at.
func checkFormat(e *Envelope, opts VerifyOpts) error {
	if e == nil {
		return fmt.Errorf("%w: request envelope is absent", ErrMalformed)
	}
	if e.RequestDomain != RequestDomain {
		return fmt.Errorf("%w: request_domain must be %q", ErrMalformed, RequestDomain)
	}
	if e.Method != opts.Method || e.Endpoint != EndpointPrefix+e.Method {
		return fmt.Errorf("%w: method %q and endpoint %q do not name the called method %q",
			ErrMalformed, e.Method, e.Endpoint, opts.Method)
	}
	if err := checkUserAddress(e.SignerAddress, opts.Bech32Prefix); err != nil {
		return err
	}
	if _, err := Hash32Hex("session_id", e.SessionID); err != nil {
		return err
	}
	if _, err := Hash32Hex("task_id", e.TaskID); err != nil {
		return err
	}
	if len(e.RequestNonce) != 32 {
		return fmt.Errorf("%w: request_nonce must be exactly 32 bytes", ErrMalformed)
	}
	if e.ExpiryHeightOrTime <= 0 {
		return fmt.Errorf("%w: expiry_height_or_time must be above zero", ErrMalformed)
	}
	if e.ExpiryHeightOrTime < HeightExpiryThreshold && !opts.AllowHeightExpiry {
		return fmt.Errorf("%w: only OpenTask may carry a chain-height expiry", ErrMalformed)
	}
	if len(e.BodyDigest) != 32 {
		return fmt.Errorf("%w: body_digest must be 32 bytes", ErrMalformed)
	}
	return nil
}

// Verify runs the five steps in order. nil means the request is authentic: e.SignerAddress is the
// user it acts for (the granting user when a session key signed it).
func Verify(ctx context.Context, e *Envelope, opts VerifyOpts) error {
	if opts.AllowHeightExpiry && opts.ReplayCache != nil {
		return ErrMisconfigured
	}
	if err := checkFormat(e, opts); err != nil {
		return err
	}
	if e.SessionGrant != nil && !opts.SessionAllowed {
		return fmt.Errorf("%w: %s must be signed by the wallet, not a session key", ErrSessionMethodNotAllowed, opts.Method)
	}
	var grantHash [32]byte
	var sessionKey [20]byte
	if e.SessionGrant != nil {
		hash, key, err := VerifyGrant(ctx, e.SessionGrant, GrantCheck{
			ChainID: opts.ChainID, RequestChainID: e.ChainID, EVMChainID: opts.EVMChainID, User: e.SignerAddress,
			Chain: opts.Chain, MaxBlocks: opts.MaxSessionGrantBlocks,
		})
		if err != nil {
			return err
		}
		grantHash, sessionKey = hash, key
	}
	// The typed data is rebuilt with this chain's chain-id, so a request signed for another chain
	// fails as a signature. The envelope's own chain_id must still be this chain: it keys the replay
	// record and is not signed.
	signed := *e
	signed.ChainID = opts.ChainID
	digest, err := RequestDigest(&signed, opts.Body, grantHash, opts.EVMChainID)
	if err != nil {
		return err
	}
	if e.ChainID != opts.ChainID {
		return fmt.Errorf("%w: chain_id %q is not this chain", ErrInvalidSignature, e.ChainID)
	}
	// The digest above signs the body the verifier recomputed; the envelope's own copy must agree.
	if !bytes.Equal(e.BodyDigest, opts.Body[:]) {
		return fmt.Errorf("%w: body_digest does not match the request body", ErrInvalidSignature)
	}
	recovered, err := eip712.Recover(digest, e.Signature)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	if e.SessionGrant != nil {
		if recovered.Address != sessionKey {
			return fmt.Errorf("%w: the request does not recover to the grant's session key", ErrInvalidSignature)
		}
	} else {
		signer, _ := nodecontract.CanonicalOperatorAddressBytes("signer_address", e.SignerAddress) // checked in checkFormat
		if !bytes.Equal(recovered.Address[:], signer) {
			return fmt.Errorf("%w: the request does not recover to signer_address", ErrInvalidSignature)
		}
		if err := matchAccountKey(ctx, opts.Chain, e.SignerAddress, recovered.Compressed); err != nil {
			if errors.Is(err, ErrUnavailable) {
				return err
			}
			return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
		}
	}
	if e.ExpiryHeightOrTime >= HeightExpiryThreshold && e.ExpiryHeightOrTime < opts.NowMS {
		return ErrExpired
	}
	if opts.ReplayCache != nil && !opts.ReplayCache.StoreOnce(ReplayKey(e), e.ExpiryHeightOrTime, opts.NowMS) {
		return ErrReplay
	}
	return nil
}

// ReplayKey is request_domain \x00 chain_id \x00 signer_address \x00 hex(request_nonce).
func ReplayKey(e *Envelope) string {
	return e.RequestDomain + "\x00" + e.ChainID + "\x00" + e.SignerAddress + "\x00" + hex.EncodeToString(e.RequestNonce)
}

// Body digests: each User Ingress method's body is an H_FIELDS_V1 digest under its own registered
// domain. Hash32 fields are raw 32 bytes (decoded from lowercase hex), integers u64 big-endian,
// text UTF-8, addresses their raw bytes, optional fields OPTIONAL_V1.
const (
	BodyOpenTaskDomain         = "TRUEOPEN_SDK_BODY_OPEN_TASK_V1"
	BodySubscribeOutputDomain  = "TRUEOPEN_SDK_BODY_SUBSCRIBE_OUTPUT_V1"
	BodyAckOutputDomain        = "TRUEOPEN_SDK_BODY_ACK_OUTPUT_V1"
	BodyGetTaskEventsDomain    = "TRUEOPEN_SDK_BODY_GET_TASK_EVENTS_V1"
	BodyPrepareChallengeDomain = "TRUEOPEN_SDK_BODY_PREPARE_CHALLENGE_V1"
)

func u64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

// optional is OPTIONAL_V1: absent is the single byte 0x00; present is 0x01 || u64be(len) || value.
func optional(value []byte, present bool) []byte {
	if !present {
		return []byte{0x00}
	}
	return append(append([]byte{0x01}, u64(uint64(len(value)))...), value...)
}

// OpenTaskBody is TRUEOPEN_SDK_BODY_OPEN_TASK_V1. taskHash is recomputed from the signed order,
// never taken from the caller; payload_ref and the deprecated outer signature fields do not enter it.
func OpenTaskBody(taskHash [32]byte, sessionID string, orderSequence uint64, userAddress string,
	inputSizeBytes uint64, inputHash string, inputMediaType, idempotencyKey string) ([32]byte, error) {
	session, err := Hash32Hex("session_id", sessionID)
	if err != nil {
		return [32]byte{}, err
	}
	input, err := Hash32Hex("input_hash", inputHash)
	if err != nil {
		return [32]byte{}, err
	}
	user, err := nodecontract.CanonicalOperatorAddressBytes("user_address", userAddress)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return nodecontract.CanonicalHashBytes(BodyOpenTaskDomain,
		taskHash[:], session[:], u64(orderSequence), user, u64(inputSizeBytes), input[:],
		[]byte(inputMediaType), []byte(idempotencyKey)), nil
}

func sessionTask(sessionID, taskID string) ([32]byte, [32]byte, error) {
	session, err := Hash32Hex("session_id", sessionID)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	task, err := Hash32Hex("task_id", taskID)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	return session, task, nil
}

// SubscribeOutputBody is TRUEOPEN_SDK_BODY_SUBSCRIBE_OUTPUT_V1; resumeAfterSeq follows transport
// presence (unset is absent, a set 0 is present 0).
func SubscribeOutputBody(sessionID, taskID string, resumeAfterSeq *uint64) ([32]byte, error) {
	session, task, err := sessionTask(sessionID, taskID)
	if err != nil {
		return [32]byte{}, err
	}
	var resume []byte
	if resumeAfterSeq != nil {
		resume = u64(*resumeAfterSeq)
	}
	return nodecontract.CanonicalHashBytes(BodySubscribeOutputDomain,
		session[:], task[:], optional(resume, resumeAfterSeq != nil)), nil
}

// AckOutputBody is TRUEOPEN_SDK_BODY_ACK_OUTPUT_V1 (the deprecated output_id does not enter it).
func AckOutputBody(sessionID, taskID string, lastSeq uint64) ([32]byte, error) {
	session, task, err := sessionTask(sessionID, taskID)
	if err != nil {
		return [32]byte{}, err
	}
	return nodecontract.CanonicalHashBytes(BodyAckOutputDomain, session[:], task[:], u64(lastSeq)), nil
}

// ParseCursor projects the from_cursor transport text: empty is absent; otherwise decimal without
// sign or leading zeros ("0" is valid) up to 2^64-1.
func ParseCursor(text string) (*uint64, error) {
	if text == "" {
		return nil, nil
	}
	if len(text) > 1 && text[0] == '0' {
		return nil, fmt.Errorf("%w: from_cursor has a leading zero", ErrMalformed)
	}
	var value uint64
	for _, c := range text {
		if c < '0' || c > '9' {
			return nil, fmt.Errorf("%w: from_cursor must be decimal", ErrMalformed)
		}
		digit := uint64(c - '0')
		if value > (math.MaxUint64-digit)/10 {
			return nil, fmt.Errorf("%w: from_cursor overflows uint64", ErrMalformed)
		}
		value = value*10 + digit
	}
	return &value, nil
}

// GetTaskEventsBody is TRUEOPEN_SDK_BODY_GET_TASK_EVENTS_V1.
func GetTaskEventsBody(sessionID, taskID, fromCursor string) ([32]byte, error) {
	session, task, err := sessionTask(sessionID, taskID)
	if err != nil {
		return [32]byte{}, err
	}
	cursor, err := ParseCursor(fromCursor)
	if err != nil {
		return [32]byte{}, err
	}
	var value []byte
	if cursor != nil {
		value = u64(*cursor)
	}
	return nodecontract.CanonicalHashBytes(BodyGetTaskEventsDomain,
		session[:], task[:], optional(value, cursor != nil)), nil
}

// PrepareChallengeBody is TRUEOPEN_SDK_BODY_PREPARE_CHALLENGE_V1. localEvidenceDigest is absent when
// empty and must otherwise be exactly 32 bytes.
func PrepareChallengeBody(sessionID, taskID, challengeKind string, localEvidenceDigest []byte) ([32]byte, error) {
	session, task, err := sessionTask(sessionID, taskID)
	if err != nil {
		return [32]byte{}, err
	}
	if len(localEvidenceDigest) != 0 && len(localEvidenceDigest) != 32 {
		return [32]byte{}, fmt.Errorf("%w: local_evidence_digest must be empty or 32 bytes", ErrMalformed)
	}
	return nodecontract.CanonicalHashBytes(BodyPrepareChallengeDomain,
		session[:], task[:], []byte(challengeKind),
		optional(localEvidenceDigest, len(localEvidenceDigest) != 0)), nil
}
