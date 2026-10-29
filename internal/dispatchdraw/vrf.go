package dispatchdraw

import (
	"context"
	"fmt"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
)

const vrfInputName = "task.v1.DispatchVrfInputV1"

// VRFProof is the dispatch randomness of one order: the ticket's vrf_epoch, vrf_output and
// vrf_proof (scheme BUILDER_VRF).
type VRFProof struct {
	Epoch uint64
	// Alpha is the proven input: the DispatchVrfInputV1 signing digest.
	Alpha [32]byte
	// Proof is the 80-byte ECVRF proof.
	Proof []byte
	// Output is r, the reduced VRF output that seeds the draw.
	Output [32]byte
}

// VRFAlpha is the VRF input of an order: the DispatchVrfInputV1 signing digest over chain, epoch,
// epoch seed, session and order sequence. Request content is not an input, so a re-signed order
// with the same sequence in the same epoch keeps its randomness.
func VRFAlpha(chainID string, epoch uint64, seed, sessionID [32]byte, sequence uint64) ([32]byte, error) {
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(vrfInput(chainID, epoch, seed, sessionID, sequence))
	if err != nil {
		return [32]byte{}, err
	}
	return dispatch.SigningDigest(vrfInputName, raw)
}

func vrfInput(chainID string, epoch uint64, seed, sessionID [32]byte, sequence uint64) *taskv1.DispatchVrfInputV1 {
	return &taskv1.DispatchVrfInputV1{
		ChainId:       chainID,
		Epoch:         epoch,
		EpochSeed:     append([]byte(nil), seed[:]...),
		SessionId:     append([]byte(nil), sessionID[:]...),
		OrderSequence: sequence,
	}
}

// Prove computes the dispatch randomness of (session, sequence) in ep with the key the chain
// registered for ep.
func (k *VRFKeys) Prove(ctx context.Context, chainID string, ep Epoch, sessionID [32]byte, sequence uint64) (VRFProof, error) {
	key, err := k.KeyFor(ctx, ep.Number)
	if err != nil {
		return VRFProof{}, err
	}
	alpha, err := VRFAlpha(chainID, ep.Number, ep.Seed, sessionID, sequence)
	if err != nil {
		return VRFProof{}, fmt.Errorf("dispatch VRF input: %w", err)
	}
	proof, output, err := dispatch.ProveDispatchVRF(key, alpha[:])
	if err != nil {
		return VRFProof{}, fmt.Errorf("prove dispatch VRF: %w", err)
	}
	return VRFProof{Epoch: ep.Number, Alpha: alpha, Proof: proof, Output: output}, nil
}
