package builderreg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/coordinator"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
)

// ErrVRFKeyRotationPending means the chain already has another Builder VRF key pending activation:
// it keeps one pending rotation at a time, so a new key can only be registered after that one has
// become active.
var ErrVRFKeyRotationPending = errors.New("another builder VRF key is already pending activation")

// VRFKeyStatus is where the chain holds a Builder VRF key.
type VRFKeyStatus string

const (
	VRFKeyActive  VRFKeyStatus = "active"
	VRFKeyPending VRFKeyStatus = "pending"
)

const (
	defaultVRFKeyWaitInterval = time.Second
	defaultVRFKeyWaitTimeout  = 60 * time.Second
)

// VRFKeyChain is the Hub surface a Builder VRF key registration reads.
type VRFKeyChain interface {
	QueryVrfKey(ctx context.Context, participantType, operator string) (chaincli.VrfKey, error)
	chaincli.TxQuerier
}

// VRFKeyRegistration registers Key as the Builder's VRF key on the Hub (ChainID), signed by the
// Builder operator account behind Submit.
type VRFKeyRegistration struct {
	ChainID string
	Builder string
	Key     ed25519.PrivateKey
	Chain   VRFKeyChain
	Submit  coordinator.VRFKeySubmitter
	Log     *slog.Logger
	// WaitInterval and WaitTimeout pace and bound the wait for the transaction's block result
	// (1s / 60s by default).
	WaitInterval time.Duration
	WaitTimeout  time.Duration
}

// VRFKeyOutcome is the chain's VRF key state for the Builder once the key is registered.
type VRFKeyOutcome struct {
	// Submitted is false when the chain already held the key and nothing was sent.
	Submitted bool
	TxHash    []byte
	Status    VRFKeyStatus
	State     chaincli.VrfKey
}

// RegisterVRFKey makes the chain hold r.Key as the Builder VRF key, active or pending. A key the
// chain already holds is not sent again. Otherwise it sends MsgRegisterVrfKey with the next
// authorization nonce and a possession proof over that nonce, waits for the transaction's block
// result and reads the state back. A registered key becomes active at the next epoch.
func RegisterVRFKey(ctx context.Context, r VRFKeyRegistration) (VRFKeyOutcome, error) {
	if len(r.Key) != ed25519.PrivateKeySize || r.Chain == nil || r.Submit == nil {
		return VRFKeyOutcome{}, fmt.Errorf("builder VRF key registration needs a key, the Hub reader and a submitter")
	}
	pub := r.Key.Public().(ed25519.PublicKey)
	state, found, err := readVRFKey(ctx, r.Chain, r.Builder)
	if err != nil {
		return VRFKeyOutcome{}, err
	}
	if status := vrfKeyStatus(state, pub); status != "" {
		return VRFKeyOutcome{Status: status, State: state}, nil
	}
	if state.PendingPubKey != nil {
		return VRFKeyOutcome{}, fmt.Errorf("%w: pending key %x activates at epoch %d; register again after that epoch has begun",
			ErrVRFKeyRotationPending, state.PendingPubKey, state.PendingFromEpoch)
	}
	nonce := uint64(1)
	if found {
		if state.AuthorizationNonce == math.MaxUint64 {
			return VRFKeyOutcome{}, fmt.Errorf("builder VRF key authorization nonce is exhausted")
		}
		nonce = state.AuthorizationNonce + 1
	}
	proof, err := dispatchdraw.ProveVRFKeyPossession(r.Key, r.ChainID, r.Builder, nonce)
	if err != nil {
		return VRFKeyOutcome{}, err
	}
	res, err := r.Submit.SubmitRegisterVrfKey(ctx, &hubv1.MsgRegisterVrfKey{
		VrfPubkey:             append([]byte(nil), pub...),
		VrfKeyPop:             proof,
		VrfAuthorizationNonce: nonce,
		OperatorAddress:       r.Builder,
		ParticipantType:       sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER,
	})
	if err != nil {
		return VRFKeyOutcome{}, fmt.Errorf("register builder VRF key: %w", err)
	}
	result, err := chaincli.WaitTx(ctx, r.Log, r.Chain, res.TxHash, chaincli.TxWait{
		Kind:     "MsgRegisterVrfKey",
		Interval: durationOr(r.WaitInterval, defaultVRFKeyWaitInterval),
		Timeout:  durationOr(r.WaitTimeout, defaultVRFKeyWaitTimeout),
	})
	if err != nil {
		return VRFKeyOutcome{}, fmt.Errorf("register builder VRF key: tx %x was broadcast but %w; re-run `nexus builder register-vrf-key` to check its outcome",
			res.TxHash, err)
	}
	if result.Code != 0 {
		return VRFKeyOutcome{}, fmt.Errorf("register builder VRF key: tx %x rejected by the chain (%s code %d): %s",
			res.TxHash, result.Codespace, result.Code, chaincli.TruncateRawLog(result.RawLog))
	}
	state, _, err = readVRFKey(ctx, r.Chain, r.Builder)
	if err != nil {
		return VRFKeyOutcome{}, fmt.Errorf("register builder VRF key: tx %x is in block %d, but reading the key back failed: %w", res.TxHash, result.Height, err)
	}
	status := vrfKeyStatus(state, pub)
	if status == "" {
		return VRFKeyOutcome{}, fmt.Errorf("register builder VRF key: tx %x is in block %d, but the chain does not hold the key", res.TxHash, result.Height)
	}
	return VRFKeyOutcome{Submitted: true, TxHash: res.TxHash, Status: status, State: state}, nil
}

func readVRFKey(ctx context.Context, chain VRFKeyChain, builder string) (chaincli.VrfKey, bool, error) {
	state, err := chain.QueryVrfKey(ctx, participantTypeBuilder, builder)
	switch {
	case errors.Is(err, chaincli.ErrNotFound):
		return chaincli.VrfKey{}, false, nil
	case err != nil:
		return chaincli.VrfKey{}, false, fmt.Errorf("builder VRF key: %w", err)
	}
	return state, true, nil
}

func vrfKeyStatus(state chaincli.VrfKey, pub []byte) VRFKeyStatus {
	switch {
	case len(state.ActivePubKey) != 0 && bytes.Equal(state.ActivePubKey, pub):
		return VRFKeyActive
	case state.PendingPubKey != nil && bytes.Equal(state.PendingPubKey, pub):
		return VRFKeyPending
	}
	return ""
}

func durationOr(d, fallback time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return fallback
}
