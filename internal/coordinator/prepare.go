// BuilderPrepare: Builder<->Builder submission-intent announcement that lets Builders avoid duplicate submissions (Detailed Design §8.1 / §4.3).
//
// It is not in the wire-frozen bus kind set -- the contract's subject table is closed, and prepare only
// flows between Builders, Cortex neither receives nor sends it, so it does not use BusEnvelopeV1 but the
// nexus-internal signed format defined in this file: JSON transport encoding, signature over the H_FIELDS
// digest of the typed field projection (domain NEXUS_BUILDER_PREPARE_V1), signed by the sender's current service key.
//
// No replay store: prepare is purely an advisory de-duplication signal (§4.1: must not be a blocking requirement for abandoning a
// proposal); replaying a prepare within its freshness window has the same effect as the original, expired ones are rejected, no dedup needed.
package coordinator

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/cosmos/btcutil/bech32"

	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/signer"
)

// prepareSignDomain is the signing domain of prepare announcements. nexus-internal; not in the protocol domain registry.
const prepareSignDomain = "NEXUS_BUILDER_PREPARE_V1"

// prepareStageSettle is currently the only prepare stage.
const prepareStageSettle = "SETTLE"

// prepareTTL is the freshness window of a prepare announcement (expires_at - issued_at).
const prepareTTL = 30 * time.Second

// builderPrepare is the wire form of one prepare announcement. All fields except signature
// enter the signing projection (field order in prepareSignPreimage).
type builderPrepare struct {
	ChainID         string `json:"chain_id"`
	SessionID       string `json:"session_id"`
	TaskID          string `json:"task_id"`
	Stage           string `json:"stage"`
	Submitter       string `json:"submitter"`
	IssuedAtUnixMS  uint64 `json:"issued_at_unix_ms"`
	ExpiresAtUnixMS uint64 `json:"expires_at_unix_ms"`
	Signature       string `json:"signature"` // 64-byte compact r||s, bare lowercase hex
}

// prepareSignPreimage assembles the signing preimage: CanonicalFramePreimage(domain, per-field frame).
// submitter enters the frame as bech32-decoded codec bytes (same address convention as wire bus),
// not as address text.
func prepareSignPreimage(p builderPrepare) ([]byte, error) {
	if p.ChainID == "" || p.SessionID == "" || p.TaskID == "" || p.Stage == "" ||
		p.Submitter == "" || p.IssuedAtUnixMS == 0 || p.ExpiresAtUnixMS <= p.IssuedAtUnixMS {
		return nil, fmt.Errorf("builder prepare: incomplete fields")
	}
	_, codec, err := bech32.DecodeToBase256(p.Submitter)
	if err != nil {
		return nil, fmt.Errorf("builder prepare: submitter is not canonical bech32: %w", err)
	}
	return nodecontract.CanonicalFramePreimage(prepareSignDomain,
		[]byte(p.ChainID),
		[]byte(p.SessionID),
		[]byte(p.TaskID),
		[]byte(p.Stage),
		codec,
		nodecontract.Uint64BE(p.IssuedAtUnixMS),
		nodecontract.Uint64BE(p.ExpiresAtUnixMS),
	), nil
}

// prepareCodec holds the local facts needed to assemble/verify prepare announcements (one per coordinator, shared by all FSMs).
type prepareCodec struct {
	log           *slog.Logger
	chainID       string
	addressPrefix string
	self          string
	signer        signer.Signer       // current service key (for signing)
	authority     servicekey.Resolver // looks up the sender's Builder binding for inbound verification
}

// ready reports whether this node can sign a prepare. When it cannot, the only correct behavior is not to send.
func (c *prepareCodec) ready() bool {
	return c != nil && c.signer != nil && c.self != ""
}

// encode assembles and signs one prepare announcement.
func (c *prepareCodec) encode(sessionID, taskID string, nowUnixMS uint64) ([]byte, error) {
	if !c.ready() {
		return nil, fmt.Errorf("builder prepare: current service key is not configured")
	}
	p := builderPrepare{
		ChainID:         c.chainID,
		SessionID:       sessionID,
		TaskID:          taskID,
		Stage:           prepareStageSettle,
		Submitter:       c.self,
		IssuedAtUnixMS:  nowUnixMS,
		ExpiresAtUnixMS: nowUnixMS + uint64(prepareTTL.Milliseconds()),
	}
	preimage, err := prepareSignPreimage(p)
	if err != nil {
		return nil, err
	}
	signature, err := c.signer.Sign(preimage)
	if err != nil {
		return nil, fmt.Errorf("builder prepare: sign: %w", err)
	}
	p.Signature = hex.EncodeToString(signature)
	return json.Marshal(p)
}

// decode parses and verifies one inbound prepare. Any failure only drops it (advisory de-duplication signal, no Nak semantics).
func (c *prepareCodec) decode(ctx context.Context, data []byte, nowUnixMS uint64) (builderPrepare, error) {
	var p builderPrepare
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&p); err != nil {
		return builderPrepare{}, fmt.Errorf("builder prepare: decode: %w", err)
	}
	if decoder.More() {
		return builderPrepare{}, fmt.Errorf("builder prepare: trailing data")
	}
	if p.Stage != prepareStageSettle {
		return builderPrepare{}, fmt.Errorf("builder prepare: unknown stage %q", p.Stage)
	}
	if p.ChainID != c.chainID {
		return builderPrepare{}, fmt.Errorf("builder prepare: chain_id mismatch")
	}
	if nowUnixMS > p.ExpiresAtUnixMS {
		return builderPrepare{}, fmt.Errorf("builder prepare: expired")
	}
	preimage, err := prepareSignPreimage(p)
	if err != nil {
		return builderPrepare{}, err
	}
	signature, err := hex.DecodeString(p.Signature)
	if err != nil || len(signature) != 64 {
		return builderPrepare{}, fmt.Errorf("builder prepare: signature must be 64-byte lowercase hex")
	}
	// The sender must be a Builder registered on-chain: verify against the current service key, no historical key fallback.
	publicKey, _, err := servicekey.Current(
		ctx, c.authority, c.addressPrefix, servicekey.ParticipantBuilder, p.Submitter)
	if err != nil {
		return builderPrepare{}, fmt.Errorf("builder prepare: submitter binding: %w", err)
	}
	if !signer.VerifySig(publicKey, preimage, signature) {
		return builderPrepare{}, fmt.Errorf("builder prepare: signature does not verify")
	}
	return p, nil
}
