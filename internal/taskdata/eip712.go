// EIP-712 v4 signature verification for USER-side Task data plane requests.
//
// USER and CORTEX_SERVICE are two mutually exclusive paths, chosen solely by
// requester_kind: never sniff by signature length, and never try the other path after one
// fails. USER is exactly 65 bytes R||S||V, CORTEX_SERVICE exactly 64 bytes R||S
// (CortexTaskDataRequestDigest in objectref.go).
package taskdata

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/TrueOpen/nexus/internal/eip712"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/sdkauth"
)

// EIP-712 domain and struct type of the USER path, domain version 2. encodeType is single-line
// ASCII with no spaces between fields: one extra space changes the typeHash and nothing a wallet
// signs would ever verify. Version 1 (without sessionGrantHash) is not accepted.
const (
	eip712DomainName = "TrueOpen Task Data Request"
	eip712Version    = "2"

	eip712RequestType = "TaskDataRequest(uint32 schemaVersion,string chainId," +
		"string builderOperatorAddress,string rpcMethod,bytes32 bodyDigest,uint32 requesterKind," +
		"string requesterAddress,uint64 serviceAuthorizationNonce,bytes32 requestNonce,uint64 expiryHeight," +
		"bytes32 sessionGrantHash)"
)

// EIP712DomainSeparator is the "TrueOpen Task Data Request" version 2 domain separator.
// numericChainID comes from the chain's Hub parameters; it and the auth.ChainID string must both
// match the current chain. Checking only one lets the same signature from another chain be
// replayed here.
func EIP712DomainSeparator(numericChainID uint64) [32]byte {
	return eip712.DomainSeparator(eip712DomainName, eip712Version, numericChainID)
}

// eip712HashStruct projects auth fields 1..10 one by one (the two addresses as canonical bech32
// text, which wallets display, body/nonce as raw bytes32, integers as uint words), then
// sessionGrantHash: 32 zero bytes without a grant, hashStruct(SessionGrant) with one.
func eip712HashStruct(auth RequestAuthV1, grantHash [32]byte) ([32]byte, error) {
	bodyDigest, err := canonicalHash32("body_digest", auth.BodyDigest)
	if err != nil {
		return [32]byte{}, err
	}
	if len(auth.RequestNonce) != 32 {
		return [32]byte{}, fmt.Errorf("%w: request_nonce must be 32 bytes", ErrMalformed)
	}
	return eip712.HashStruct(eip712RequestType,
		eip712.Uint(uint64(auth.SchemaVersion)),
		eip712.String(auth.ChainID),
		eip712.String(auth.BuilderOperatorAddress),
		eip712.String(auth.RPCMethod),
		bodyDigest,
		eip712.Uint(uint64(auth.RequesterKind)),
		eip712.String(auth.RequesterAddress),
		eip712.Uint(auth.ServiceAuthorizationNonce),
		auth.RequestNonce,
		eip712.Uint(auth.ExpiryHeight),
		grantHash[:],
	), nil
}

// UserTaskDataRequestDigest is the 32 bytes signed on the USER path with the given sessionGrantHash.
func UserTaskDataRequestDigest(auth RequestAuthV1, numericChainID uint64, grantHash [32]byte) ([32]byte, error) {
	hashStruct, err := eip712HashStruct(auth, grantHash)
	if err != nil {
		return [32]byte{}, err
	}
	return eip712.Digest(EIP712DomainSeparator(numericChainID), hashStruct), nil
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

// SessionGrantEnv is what a USER request carrying a session grant is verified against.
type SessionGrantEnv struct {
	Chain     sdkauth.Chain
	MaxBlocks uint64
	// AddressPrefix, when set, is the Bech32 prefix requester_address must carry.
	AddressPrefix string
}

// sessionAllowed reports whether a session key may sign this request: only metadata and fetch of an
// OUTPUT object.
func sessionAllowed(auth RequestAuthV1) bool {
	return (auth.RPCMethod == rpcMethodPath(MethodGetMetadata) || auth.RPCMethod == rpcMethodPath(MethodFetch)) &&
		auth.Key.Kind == ObjectKindOutput
}

// VerifyUserTaskDataRequest is the full USER-path check. It answers only "is this request signed for
// requester_address": without a grant the signature must recover to requester_address; with one, the
// grant must be the requester's, valid now, and the request must recover to its session key.
// Authorization still depends solely on on-chain roles.
func VerifyUserTaskDataRequest(ctx context.Context, auth RequestAuthV1, numericChainID uint64, env SessionGrantEnv) error {
	if auth.RequesterKind != RequesterKindUser {
		return fmt.Errorf("%w: requester_kind", ErrMalformed)
	}
	// USER has no service key, so the nonce field must be 0; non-zero means the caller mixed up the two paths.
	if auth.ServiceAuthorizationNonce != 0 {
		return fmt.Errorf("%w: USER service_authorization_nonce must be 0", ErrMalformed)
	}
	declared, err := UserAddressBytes(auth.RequesterAddress)
	if err != nil {
		return err
	}
	if p := env.AddressPrefix; p != "" && auth.RequesterAddress[:strings.LastIndex(auth.RequesterAddress, "1")] != p {
		return fmt.Errorf("%w: requester_address is not a %q address", ErrMalformed, p)
	}
	var grantHash [32]byte
	var sessionKey [20]byte
	if auth.SessionGrant != nil {
		if !sessionAllowed(auth) {
			return fmt.Errorf("%w: only metadata and fetch of an OUTPUT object may be signed by a session key", ErrSessionMethodNotAllowed)
		}
		grantHash, sessionKey, err = sdkauth.VerifyGrant(ctx, auth.SessionGrant, sdkauth.GrantCheck{
			ChainID: auth.ChainID, RequestChainID: auth.ChainID, EVMChainID: numericChainID, User: auth.RequesterAddress,
			Chain: env.Chain, MaxBlocks: env.MaxBlocks,
		})
		// Report the grant failure under this path's own code, without the SDK code in front.
		reason := ""
		var grantErr *sdkauth.GrantError
		if errors.As(err, &grantErr) {
			reason = grantErr.Reason
		} else if err != nil {
			reason = err.Error()
		}
		switch {
		case errors.Is(err, sdkauth.ErrSessionGrantExpired):
			return fmt.Errorf("%w: %s", ErrSessionGrantExpired, reason)
		case errors.Is(err, sdkauth.ErrUnavailable):
			return fmt.Errorf("%w: %s", ErrAuthorityUnavailable, reason)
		case err != nil:
			return fmt.Errorf("%w: %s", ErrSessionGrantInvalid, reason)
		}
	}
	digest, err := UserTaskDataRequestDigest(auth, numericChainID, grantHash)
	if err != nil {
		return err
	}
	recovered, err := eip712.Recover(digest, auth.Signature)
	if err != nil {
		return fmt.Errorf("%w: USER signature: %v", ErrInvalidSignature, err)
	}
	want := declared
	if auth.SessionGrant != nil {
		want = sessionKey
	}
	if recovered.Address != want {
		return fmt.Errorf("%w: USER signature recovers %s, not %s",
			ErrInvalidSignature, hex.EncodeToString(recovered.Address[:]), hex.EncodeToString(want[:]))
	}
	return nil
}
