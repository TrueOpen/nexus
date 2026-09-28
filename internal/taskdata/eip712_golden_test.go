package taskdata

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"github.com/TrueOpen/nexus/internal/eip712"
	"github.com/TrueOpen/nexus/internal/sdkauth"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

// Byte for byte against the USER task data request vectors of wire
// testdata/v1/shared/account_signing_v1.json, domain version 2: "task_data_request" (wallet signed,
// a ranged FetchTaskData) and "task_data_request_session" (session-key signed GetTaskDataMetadata of
// an OUTPUT object under "session_grant"). Every link in the chain has a published value, so a wrong
// step is located directly instead of being reverse-engineered from the final digest.
const goldenEIP712NumericChainID = 424242

type goldenTypedData struct {
	HashStruct string `json:"hash_struct"`
	Digest     string `json:"signing_digest"`
	Signature  string `json:"signature_65"`
	Recovered  string `json:"recovered_address"`
	Domain     struct {
		Separator string `json:"domain_separator"`
	} `json:"domain"`
	Message map[string]string `json:"message"`
}

type goldenAccountSigning struct {
	Account struct {
		Bech32        string `json:"account_bech32"`
		PubCompressed string `json:"pub_compressed"`
	} `json:"account"`
	Request      goldenTypedData `json:"task_data_request"`
	Session      goldenTypedData `json:"task_data_request_session"`
	SessionGrant struct {
		Signature string `json:"signature_65"`
		Transport struct {
			ChainID      string `json:"chain_id"`
			ExpiryHeight string `json:"expiry_height"`
			GrantNonce   string `json:"grant_nonce_hex"`
			SessionKey   string `json:"session_key_hex"`
			User         string `json:"user"`
		} `json:"transport"`
	} `json:"session_grant"`
}

func loadGoldenAccountSigning(t *testing.T) goldenAccountSigning {
	t.Helper()
	var file goldenAccountSigning
	if err := json.Unmarshal(wirefixture.ReadFile(t, "testdata/v1/shared/account_signing_v1.json"), &file); err != nil {
		t.Fatal(err)
	}
	return file
}

func mustHexT(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// goldenUserFetchAuth is the wallet-signed USER Fetch request of the vector: nonce 00..1f, service
// nonce 0, expiry 2000, chain trueopen-golden-1, same Builder as the Cortex vector.
func goldenUserFetchAuth(t *testing.T) RequestAuthV1 {
	t.Helper()
	file := loadGoldenAccountSigning(t)
	body, err := TaskDataFetchBodyDigest(goldenOutputRef(), &ByteRange{Offset: 64, Length: 128})
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(body[:]) != file.Request.Message["bodyDigest"] {
		t.Fatalf("fetch body %x is not the vector's %s", body, file.Request.Message["bodyDigest"])
	}
	return RequestAuthV1{
		SchemaVersion: 1, ChainID: "trueopen-golden-1",
		BuilderOperatorAddress:    goldenBuilder,
		RPCMethod:                 "/nexus.v1.IngressAPI/FetchTaskData",
		BodyDigest:                hex.EncodeToString(body[:]),
		RequesterKind:             RequesterKindUser,
		RequesterAddress:          file.Account.Bech32,
		ServiceAuthorizationNonce: 0,
		RequestNonce:              mustHexT(t, file.Request.Message["requestNonce"]),
		ExpiryHeight:              2000,
		Signature:                 mustHexT(t, file.Request.Signature),
		Key:                       goldenOutputRef(),
	}
}

// goldenGrantChain is the chain the session vector verifies against: height 1200, the account's key.
type goldenGrantChain struct {
	height uint64
	keys   map[string][]byte
}

func (c goldenGrantChain) CurrentHeight(context.Context) (uint64, error) { return c.height, nil }
func (c goldenGrantChain) AccountPubKey(_ context.Context, address string) ([]byte, error) {
	if key, ok := c.keys[address]; ok {
		return key, nil
	}
	return nil, sdkauth.ErrNoAccountKey
}

// goldenUserSessionAuth is the session-key-signed USER GetTaskDataMetadata request of the vector,
// with its grant, and the environment it verifies in.
func goldenUserSessionAuth(t *testing.T) (RequestAuthV1, SessionGrantEnv) {
	t.Helper()
	file := loadGoldenAccountSigning(t)
	body, err := TaskDataMetadataBodyDigest(goldenOutputRef())
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(body[:]) != file.Session.Message["bodyDigest"] {
		t.Fatalf("metadata body %x is not the vector's %s", body, file.Session.Message["bodyDigest"])
	}
	g := file.SessionGrant
	expiry, err := strconv.ParseUint(g.Transport.ExpiryHeight, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	auth := RequestAuthV1{
		SchemaVersion: 1, ChainID: "trueopen-golden-1",
		BuilderOperatorAddress:    goldenBuilder,
		RPCMethod:                 "/nexus.v1.IngressAPI/GetTaskDataMetadata",
		BodyDigest:                hex.EncodeToString(body[:]),
		RequesterKind:             RequesterKindUser,
		RequesterAddress:          file.Account.Bech32,
		ServiceAuthorizationNonce: 0,
		RequestNonce:              mustHexT(t, file.Session.Message["requestNonce"]),
		ExpiryHeight:              2000,
		Signature:                 mustHexT(t, file.Session.Signature),
		SessionGrant: &sdkauth.SessionGrant{
			ChainID: g.Transport.ChainID, User: g.Transport.User, SessionKey: mustHexT(t, g.Transport.SessionKey),
			ExpiryHeight: expiry, GrantNonce: mustHexT(t, g.Transport.GrantNonce), UserSignature: mustHexT(t, g.Signature),
		},
		Key: goldenOutputRef(),
	}
	env := SessionGrantEnv{
		Chain:     goldenGrantChain{height: 1200, keys: map[string][]byte{file.Account.Bech32: mustHexT(t, file.Account.PubCompressed)}},
		MaxBlocks: 400,
	}
	return auth, env
}

func TestEIP712DomainSeparatorVersion2(t *testing.T) {
	file := loadGoldenAccountSigning(t)
	separator := EIP712DomainSeparator(goldenEIP712NumericChainID)
	if got := hex.EncodeToString(separator[:]); got != file.Request.Domain.Separator {
		t.Fatalf("domain separator = %s, want %s", got, file.Request.Domain.Separator)
	}
}

func TestEIP712UserFetchVector(t *testing.T) {
	file := loadGoldenAccountSigning(t)
	auth := goldenUserFetchAuth(t)
	hashStruct, err := eip712HashStruct(auth, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(hashStruct[:]); got != file.Request.HashStruct {
		t.Fatalf("hash_struct = %s", got)
	}
	digest, err := UserTaskDataRequestDigest(auth, goldenEIP712NumericChainID, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(digest[:]); got != file.Request.Digest {
		t.Fatalf("signing_digest = %s", got)
	}
	recovered, err := eip712.Recover(digest, auth.Signature)
	if err != nil || hex.EncodeToString(recovered.Address[:]) != file.Request.Recovered {
		t.Fatalf("recovered_address = %x (%v)", recovered.Address, err)
	}
	if err := VerifyUserTaskDataRequest(context.Background(), auth, goldenEIP712NumericChainID, goldenAccountEnv(t)); err != nil {
		t.Fatalf("full verification failed: %v", err)
	}
	// The same request from an account the chain holds no key for fails as a signature.
	if err := VerifyUserTaskDataRequest(context.Background(), auth, goldenEIP712NumericChainID,
		SessionGrantEnv{Chain: goldenGrantChain{height: 1200}}); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("account without a stored key: %v, want DATA_ACCESS_INVALID_SIGNATURE", err)
	}
}

func TestEIP712UserSessionVector(t *testing.T) {
	file := loadGoldenAccountSigning(t)
	auth, env := goldenUserSessionAuth(t)
	grantHash, err := sdkauth.SessionGrantHash(auth.SessionGrant)
	if err != nil {
		t.Fatal(err)
	}
	hashStruct, err := eip712HashStruct(auth, grantHash)
	if err != nil || hex.EncodeToString(hashStruct[:]) != file.Session.HashStruct {
		t.Fatalf("hash_struct = %x (%v)", hashStruct, err)
	}
	digest, err := UserTaskDataRequestDigest(auth, goldenEIP712NumericChainID, grantHash)
	if err != nil || hex.EncodeToString(digest[:]) != file.Session.Digest {
		t.Fatalf("signing_digest = %x (%v)", digest, err)
	}
	if err := VerifyUserTaskDataRequest(context.Background(), auth, goldenEIP712NumericChainID, env); err != nil {
		t.Fatalf("full verification failed: %v", err)
	}
}

// A session key may sign only metadata and fetch of an OUTPUT object; the grant window is enforced.
func TestEIP712UserSessionRejects(t *testing.T) {
	ctx := context.Background()
	t.Run("upload with a grant", func(t *testing.T) {
		auth, env := goldenUserSessionAuth(t)
		auth.RPCMethod = "/nexus.v1.IngressAPI/UploadTaskResultObject"
		if err := VerifyUserTaskDataRequest(ctx, auth, goldenEIP712NumericChainID, env); !errors.Is(err, ErrSessionMethodNotAllowed) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("input object with a grant", func(t *testing.T) {
		auth, env := goldenUserSessionAuth(t)
		auth.Key.Kind = ObjectKindInput
		if err := VerifyUserTaskDataRequest(ctx, auth, goldenEIP712NumericChainID, env); !errors.Is(err, ErrSessionMethodNotAllowed) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("grant expired", func(t *testing.T) {
		auth, env := goldenUserSessionAuth(t)
		env.Chain = goldenGrantChain{height: 1501, keys: env.Chain.(goldenGrantChain).keys}
		if err := VerifyUserTaskDataRequest(ctx, auth, goldenEIP712NumericChainID, env); !errors.Is(err, ErrSessionGrantExpired) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("grant user without a key", func(t *testing.T) {
		auth, env := goldenUserSessionAuth(t)
		env.Chain = goldenGrantChain{height: 1200}
		if err := VerifyUserTaskDataRequest(ctx, auth, goldenEIP712NumericChainID, env); !errors.Is(err, ErrSessionGrantInvalid) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("request signed without the grant hash", func(t *testing.T) {
		auth, env := goldenUserSessionAuth(t)
		auth.SessionGrant = nil // the session-key signature no longer recovers to the requester
		if err := VerifyUserTaskDataRequest(ctx, auth, goldenEIP712NumericChainID, env); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("version 1 signature", func(t *testing.T) {
		auth := goldenUserFetchAuth(t)
		// wire's obsolete version 1 signature over the same request.
		auth.Signature = mustHexT(t, loadGoldenV1Signature(t))
		if err := VerifyUserTaskDataRequest(ctx, auth, goldenEIP712NumericChainID, SessionGrantEnv{}); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("err = %v", err)
		}
	})
}

// Inputs that must be rejected. Each is a concrete form of "a signature from
// another chain / another body / another path impersonating this request".
func TestEIP712UserRejects(t *testing.T) {
	t.Run("wrong numeric chain id", func(t *testing.T) {
		auth := goldenUserFetchAuth(t)
		if err := VerifyUserTaskDataRequest(context.Background(), auth, goldenEIP712NumericChainID+1, SessionGrantEnv{}); err == nil {
			t.Fatal("domain numeric chain ID must take part in verification")
		}
	})

	t.Run("wrong string chain id", func(t *testing.T) {
		auth := goldenUserFetchAuth(t)
		auth.ChainID = "trueopen-golden-2"
		if err := VerifyUserTaskDataRequest(context.Background(), auth, goldenEIP712NumericChainID, SessionGrantEnv{}); err == nil {
			t.Fatal("chain_id string must take part in verification")
		}
	})

	t.Run("nonzero service nonce", func(t *testing.T) {
		auth := goldenUserFetchAuth(t)
		auth.ServiceAuthorizationNonce = 7
		if err := VerifyUserTaskDataRequest(context.Background(), auth, goldenEIP712NumericChainID, SessionGrantEnv{}); err == nil {
			t.Fatal("USER service_authorization_nonce must be 0")
		}
	})

	t.Run("raw64 signature", func(t *testing.T) {
		auth := goldenUserFetchAuth(t)
		auth.Signature = auth.Signature[:64]
		if err := VerifyUserTaskDataRequest(context.Background(), auth, goldenEIP712NumericChainID, SessionGrantEnv{}); err == nil {
			t.Fatal("USER must be exactly 65 bytes; raw64 must not be accepted")
		}
	})

	t.Run("bad recovery id", func(t *testing.T) {
		auth := goldenUserFetchAuth(t)
		bad := append([]byte(nil), auth.Signature...)
		bad[64] = 0 // the 0/1 form common with personal_sign
		auth.Signature = bad
		if err := VerifyUserTaskDataRequest(context.Background(), auth, goldenEIP712NumericChainID, SessionGrantEnv{}); err == nil {
			t.Fatal("V must be 27 or 28")
		}
	})

	t.Run("another requester", func(t *testing.T) {
		auth := goldenUserFetchAuth(t)
		auth.RequesterAddress = goldenProducer
		if err := VerifyUserTaskDataRequest(context.Background(), auth, goldenEIP712NumericChainID, SessionGrantEnv{}); err == nil {
			t.Fatal("recovered address must equal requester_address")
		}
	})

	t.Run("another body", func(t *testing.T) {
		auth := goldenUserFetchAuth(t)
		other, err := TaskDataFetchBodyDigest(goldenOutputRef(), nil)
		if err != nil {
			t.Fatal(err)
		}
		auth.BodyDigest = hex.EncodeToString(other[:])
		if err := VerifyUserTaskDataRequest(context.Background(), auth, goldenEIP712NumericChainID, SessionGrantEnv{}); err == nil {
			t.Fatal("a different body must fail: whole and ranged reads cannot share one signature")
		}
	})

	t.Run("another method", func(t *testing.T) {
		auth := goldenUserFetchAuth(t)
		auth.RPCMethod = "/nexus.v1.IngressAPI/GetTaskDataMetadata"
		if err := VerifyUserTaskDataRequest(context.Background(), auth, goldenEIP712NumericChainID, SessionGrantEnv{}); err == nil {
			t.Fatal("rpc_method must take part in verification")
		}
	})

	t.Run("cortex kind on a user signature", func(t *testing.T) {
		auth := goldenUserFetchAuth(t)
		auth.RequesterKind = RequesterKindCortexService
		if err := VerifyUserTaskDataRequest(context.Background(), auth, goldenEIP712NumericChainID, SessionGrantEnv{}); err == nil {
			t.Fatal("requester_kind selects the path; paths must not be mixed")
		}
	})
}

// The Task data rows of wire request_auth_negative_cases, byte for byte: the digest the verifier
// rebuilds, the address the signature recovers to over it, and the error code.
func TestEIP712UserWireNegativeCases(t *testing.T) {
	var file struct {
		Cases []struct {
			Name      string `json:"name"`
			Error     string `json:"error"`
			Signature string `json:"signature_65"`
			Digest    string `json:"signing_digest"`
			Recovered string `json:"recovered_address"`
			Signed    *struct {
				Message map[string]string `json:"message"`
			} `json:"signed"`
			Verified *struct {
				Domain map[string]string `json:"domain"`
			} `json:"verified"`
		} `json:"request_auth_negative_cases"`
	}
	if err := json.Unmarshal(wirefixture.ReadFile(t, "testdata/v1/shared/account_signing_v1.json"), &file); err != nil {
		t.Fatal(err)
	}
	codes := map[string]error{
		ErrInvalidSignature.Error():        ErrInvalidSignature,
		ErrSessionMethodNotAllowed.Error(): ErrSessionMethodNotAllowed,
	}
	ctx := context.Background()
	seen := 0
	for _, row := range file.Cases {
		t.Run(row.Name, func(t *testing.T) {
			var auth RequestAuthV1
			env := SessionGrantEnv{}
			separator := EIP712DomainSeparator(goldenEIP712NumericChainID)
			verifierChainID := uint64(goldenEIP712NumericChainID)
			var grantHash [32]byte
			switch row.Name {
			case "task_data_request_other_evm_chain_id":
				auth = goldenUserFetchAuth(t)
				verifierChainID = mustUintT(t, row.Verified.Domain["chain_id"])
				separator = EIP712DomainSeparator(verifierChainID)
			case "task_data_request_domain_version_1":
				auth = goldenUserFetchAuth(t)
				separator = eip712.DomainSeparator(eip712DomainName, row.Verified.Domain["version"], goldenEIP712NumericChainID)
			case "task_data_upload_with_session_grant":
				auth, env = goldenUserSessionAuth(t)
				auth.RPCMethod = row.Signed.Message["rpcMethod"]
				auth.BodyDigest = row.Signed.Message["bodyDigest"]
				auth.Signature = mustHexT(t, row.Signature)
				h, err := sdkauth.SessionGrantHash(auth.SessionGrant)
				if err != nil {
					t.Fatal(err)
				}
				grantHash = h
			default:
				t.Skip("not a Task data row with published bytes")
			}
			seen++
			hashStruct, err := eip712HashStruct(auth, grantHash)
			if err != nil {
				t.Fatal(err)
			}
			digest := eip712.Digest(separator, hashStruct)
			if got := hex.EncodeToString(digest[:]); got != row.Digest {
				t.Fatalf("signing_digest = %s, want %s", got, row.Digest)
			}
			recovered, err := eip712.Recover(digest, auth.Signature)
			if err != nil || hex.EncodeToString(recovered.Address[:]) != row.Recovered {
				t.Fatalf("recovered_address = %x (%v), want %s", recovered.Address, err, row.Recovered)
			}
			if row.Name == "task_data_request_domain_version_1" {
				// Nexus has no version 1 route; the published version 1 signature must not verify.
				auth.Signature = mustHexT(t, loadGoldenV1Signature(t))
			}
			want := codes[row.Error]
			if want == nil {
				t.Fatalf("unknown error %q", row.Error)
			}
			if err := VerifyUserTaskDataRequest(ctx, auth, verifierChainID, env); !errors.Is(err, want) {
				t.Fatalf("err = %v, want %s", err, row.Error)
			}
		})
	}
	if seen != 3 {
		t.Fatalf("checked %d Task data rows, want 3", seen)
	}
}

func mustUintT(t *testing.T, s string) uint64 {
	t.Helper()
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// loadGoldenV1Signature is the signature of wire's task_data_request_v1_obsolete section.
func loadGoldenV1Signature(t *testing.T) string {
	t.Helper()
	var file struct {
		V1 struct {
			Signature string `json:"signature_65"`
		} `json:"task_data_request_v1_obsolete"`
	}
	if err := json.Unmarshal(wirefixture.ReadFile(t, "testdata/v1/shared/account_signing_v1.json"), &file); err != nil {
		t.Fatal(err)
	}
	if file.V1.Signature == "" {
		t.Fatal("no task_data_request_v1_obsolete signature")
	}
	return file.V1.Signature
}

// goldenAccountEnv is a verifier whose chain holds the vector account's key.
func goldenAccountEnv(t *testing.T) SessionGrantEnv {
	t.Helper()
	file := loadGoldenAccountSigning(t)
	return SessionGrantEnv{Chain: goldenGrantChain{height: 1200,
		keys: map[string][]byte{file.Account.Bech32: mustHexT(t, file.Account.PubCompressed)}}, MaxBlocks: 400}
}
