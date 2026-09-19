// EIP-712 v4 signature verification for USER-side Task data plane requests (Interface &
// Topic Catalogue §4.2.1).
//
// USER and CORTEX_SERVICE are two mutually exclusive paths, chosen solely by
// requester_kind: never sniff by signature length, and never try the other path after one
// fails. USER is exactly 65 bytes R||S||V, CORTEX_SERVICE exactly 64 bytes R||S
// (CortexTaskDataRequestDigest in objectref.go).
package taskdata

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/TrueOpen/nexus/internal/nodecontract"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

// EIP-712 domain and struct types. encodeType is single-line ASCII with no spaces between
// fields: one extra space changes the typeHash and nothing a wallet signs would ever verify.
const (
	eip712DomainType = "EIP712Domain(string name,string version,uint256 chainId)"
	eip712DomainName = "TrueOpen Task Data Request"
	eip712Version    = "1"

	eip712RequestType = "TaskDataRequest(uint32 schemaVersion,string chainId," +
		"string builderOperatorAddress,string rpcMethod,bytes32 bodyDigest,uint32 requesterKind," +
		"string requesterAddress,uint64 serviceAuthorizationNonce,bytes32 requestNonce,uint64 expiryHeight)"
)

func keccak256(parts ...[]byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// eip712Word left-pads an integer into a 32-byte big-endian word, the EIP-712 encoding of uintN.
func eip712Word(value uint64) []byte {
	word := make([]byte, 32)
	binary.BigEndian.PutUint64(word[24:], value)
	return word
}

// EIP712DomainSeparator is keccak(typeHash || keccak(name) || keccak(version) || chainId).
// numericChainID comes from the Genesis/account contract mapping; it and the auth.ChainID
// string must both match the current chain. Checking only one lets the same signature from
// another chain be replayed here.
func EIP712DomainSeparator(numericChainID uint64) [32]byte {
	typeHash := keccak256([]byte(eip712DomainType))
	name := keccak256([]byte(eip712DomainName))
	version := keccak256([]byte(eip712Version))
	return keccak256(typeHash[:], name[:], version[:], eip712Word(numericChainID))
}

// eip712HashStruct projects auth fields 1..10 one by one: the two addresses as canonical
// bech32 text (wallets display them to humans), body/nonce as raw bytes32, integers padded
// to 32-byte words per their uint width.
func eip712HashStruct(auth RequestAuthV1) ([32]byte, error) {
	bodyDigest, err := canonicalHash32("body_digest", auth.BodyDigest)
	if err != nil {
		return [32]byte{}, err
	}
	if len(auth.RequestNonce) != 32 {
		return [32]byte{}, fmt.Errorf("%w: request_nonce must be 32 bytes", ErrMalformed)
	}
	typeHash := keccak256([]byte(eip712RequestType))
	chainID := keccak256([]byte(auth.ChainID))
	builder := keccak256([]byte(auth.BuilderOperatorAddress))
	method := keccak256([]byte(auth.RPCMethod))
	requester := keccak256([]byte(auth.RequesterAddress))
	return keccak256(
		typeHash[:],
		eip712Word(uint64(auth.SchemaVersion)),
		chainID[:],
		builder[:],
		method[:],
		bodyDigest,
		eip712Word(uint64(auth.RequesterKind)),
		requester[:],
		eip712Word(auth.ServiceAuthorizationNonce),
		auth.RequestNonce,
		eip712Word(auth.ExpiryHeight),
	), nil
}

// UserTaskDataRequestDigest is the 32 bytes signed on the USER path:
// keccak(0x19 0x01 || domainSeparator || hashStruct).
func UserTaskDataRequestDigest(auth RequestAuthV1, numericChainID uint64) ([32]byte, error) {
	hashStruct, err := eip712HashStruct(auth)
	if err != nil {
		return [32]byte{}, err
	}
	separator := EIP712DomainSeparator(numericChainID)
	return keccak256([]byte{0x19, 0x01}, separator[:], hashStruct[:]), nil
}

// secp256k1HalfOrder is the low-S criterion: an S above it is high-S and must be rejected,
// otherwise the same authorization has two valid signatures and the replay key cannot stop
// the second one.
var secp256k1HalfOrder = new(big.Int).Rsh(secp256k1.S256().N, 1)

// RecoverUserTaskDataRequester recovers the signer's 20-byte address from 65-byte R||S||V.
//
// Only V in {27, 28} is accepted: personal_sign and eth_sign wrap the digest in an extra
// prefix, so their signatures cannot pass here, which §4.2.1 explicitly requires rejecting.
func RecoverUserTaskDataRequester(digest [32]byte, signature []byte) ([20]byte, error) {
	if len(signature) != 65 {
		return [20]byte{}, fmt.Errorf("%w: USER signature must be exactly 65 bytes", ErrMalformed)
	}
	v := signature[64]
	if v != 27 && v != 28 {
		return [20]byte{}, fmt.Errorf("%w: USER signature V must be 27 or 28", ErrMalformed)
	}
	s := new(big.Int).SetBytes(signature[32:64])
	if s.Sign() == 0 || s.Cmp(secp256k1HalfOrder) > 0 {
		return [20]byte{}, fmt.Errorf("%w: USER signature must be low-S", ErrMalformed)
	}
	r := new(big.Int).SetBytes(signature[:32])
	if r.Sign() == 0 {
		return [20]byte{}, fmt.Errorf("%w: USER signature R must be non-zero", ErrMalformed)
	}
	// dcrec's compact layout is [V R S], with V based at 27 and +4 for the compressed bit.
	// We recover the uncompressed public key, so that bit is not added.
	compact := make([]byte, 65)
	compact[0] = v
	copy(compact[1:], signature[:64])
	pub, _, err := ecdsa.RecoverCompact(compact, digest[:])
	if err != nil {
		return [20]byte{}, fmt.Errorf("%w: USER signature does not recover", ErrUnauthorized)
	}
	// Ethereum address = last 20 bytes of keccak(uncompressed pubkey without the 0x04 prefix).
	uncompressed := pub.SerializeUncompressed()
	sum := keccak256(uncompressed[1:])
	var address [20]byte
	copy(address[:], sum[12:])
	return address, nil
}

// UserAddressBytes returns the 20-byte address codec value of requester_address, for
// byte-for-byte comparison with the recovered address.
func UserAddressBytes(bech32Address string) ([20]byte, error) {
	raw, err := nodecontract.CanonicalOperatorAddressBytes("requester_address", bech32Address)
	if err != nil {
		return [20]byte{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if len(raw) != 20 {
		return [20]byte{}, fmt.Errorf("%w: requester_address must decode to 20 bytes", ErrMalformed)
	}
	var out [20]byte
	copy(out[:], raw)
	return out, nil
}

// VerifyUserTaskDataRequest is the full USER-path check: compute the digest, recover the
// address, compare with requester_address. It only answers "was this signature made by this
// address"; authorization still depends solely on on-chain roles, and the role the requester
// claims for itself does not count.
func VerifyUserTaskDataRequest(auth RequestAuthV1, numericChainID uint64) error {
	if auth.RequesterKind != RequesterKindUser {
		return fmt.Errorf("%w: requester_kind", ErrMalformed)
	}
	// USER has no service key, so the nonce field must be 0; non-zero means the caller mixed up the two paths.
	if auth.ServiceAuthorizationNonce != 0 {
		return fmt.Errorf("%w: USER service_authorization_nonce must be 0", ErrMalformed)
	}
	digest, err := UserTaskDataRequestDigest(auth, numericChainID)
	if err != nil {
		return err
	}
	recovered, err := RecoverUserTaskDataRequester(digest, auth.Signature)
	if err != nil {
		return err
	}
	declared, err := UserAddressBytes(auth.RequesterAddress)
	if err != nil {
		return err
	}
	if recovered != declared {
		return fmt.Errorf("%w: USER signature recovers %s, not %s",
			ErrUnauthorized, hex.EncodeToString(recovered[:]), hex.EncodeToString(declared[:]))
	}
	return nil
}
