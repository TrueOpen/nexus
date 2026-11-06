package dispatchdraw

import (
	"crypto/ed25519"
	"fmt"

	"github.com/TrueOpen/wire/dispatch"
)

// vrfKeyPoPDomain separates the VRF key possession digest.
const vrfKeyPoPDomain = "TRUEOPEN_VRF_KEY_POP_V1"

// VRFKeyPoPDigest is the digest a VRF key proves possession over when it is registered with
// MsgRegisterVrfKey: H_FIELDS_V1 over chain_id, the operator's raw 20-byte address, the raw 32-byte
// VRF public key and uint64_be(vrf_authorization_nonce). The participant type is not a field, and
// neither is the activation epoch (the chain derives it as the next epoch).
func VRFKeyPoPDigest(chainID, operator string, vrfPubKey []byte, nonce uint64) ([32]byte, error) {
	if chainID == "" {
		return [32]byte{}, fmt.Errorf("VRF key possession: chain_id is empty")
	}
	operatorRaw, err := dispatch.AddressBytes(operator)
	if err != nil {
		return [32]byte{}, fmt.Errorf("VRF key possession: operator address %q: %w", operator, err)
	}
	if len(vrfPubKey) != ed25519.PublicKeySize {
		return [32]byte{}, fmt.Errorf("VRF key possession: vrf_pubkey is %d bytes, want %d", len(vrfPubKey), ed25519.PublicKeySize)
	}
	if nonce == 0 {
		return [32]byte{}, fmt.Errorf("VRF key possession: vrf_authorization_nonce must be greater than zero")
	}
	return vrfKeyPoPDigest(chainID, operatorRaw, vrfPubKey, nonce), nil
}

func vrfKeyPoPDigest(chainID string, operatorRaw, vrfPubKey []byte, nonce uint64) [32]byte {
	return dispatch.HashFields(vrfKeyPoPDomain, []byte(chainID), operatorRaw, vrfPubKey, dispatch.Uint64(nonce))
}

// ProveVRFKeyPossession is the vrf_key_pop of MsgRegisterVrfKey: one ECVRF prove with key over its
// VRFKeyPoPDigest, in the suite dispatch proofs use. The chain verifies the proof under the
// submitted public key and ignores its output.
func ProveVRFKeyPossession(key ed25519.PrivateKey, chainID, operator string, nonce uint64) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("VRF key possession: key is %d bytes, want %d", len(key), ed25519.PrivateKeySize)
	}
	digest, err := VRFKeyPoPDigest(chainID, operator, key.Public().(ed25519.PublicKey), nonce)
	if err != nil {
		return nil, err
	}
	proof, _, err := dispatch.ProveDispatchVRF(key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("VRF key possession: prove: %w", err)
	}
	return proof, nil
}
