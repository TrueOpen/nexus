package taskdata

import (
	"encoding/hex"
	"testing"
)

// Byte for byte against monorepo Interface & Topic Catalogue §4.2.1
// "USER Fetch auth (EIP-712 v4)". Every link in the chain has a published value, so a wrong
// step is located directly instead of being reverse-engineered from the final digest.
const (
	goldenEIP712NumericChainID = 424242
	goldenEIP712DomainTypeHash = "c2f8787176b8ac6bf7215b4adcc1e069bf4ab82d9ab1df05a57a91d425935b6e"
	goldenEIP712RequestTypeHas = "b46d57a151e675bb90df1ffa518e88e93ae97b3e0400ab9064c2d3f84cb3735a"
	goldenEIP712Separator      = "43a9e01264c13d99f777f935bb9125ec78f6d19732efca7d1e4328de85dd0d4f"
	goldenEIP712HashStruct     = "9701c62f684c238216b1f8f6da7edecd161a0c1dfb3b13821b6ef6f5353285a3"
	goldenEIP712SigningDigest  = "a4697bc65277f4214c034f720c0872579b6e2d4a718ca0117c4c8bf2041bf512"
	goldenEIP712Signature      = "b07b5449de0058012712d5ea8fe5e12ed807ef2aea0ddd194468bc0730006b30" +
		"5e93462045acab80fff3aeabaae44ec31cd86f0240e8710fd36739c6d20873531c"
	goldenEIP712Recovered = "1a642f0e3c3af545e7acbd38b07251b3990914f1"
	// Canonical bech32 of the same 20 bytes as recovered_address.
	goldenEIP712User = "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz"
)

// goldenUserFetchAuth is the USER Fetch request from the vector: nonce 00..1f, service
// nonce 0, expiry 2000, chain trueopen-golden-1, same Builder as the Cortex vector.
func goldenUserFetchAuth(t *testing.T) RequestAuthV1 {
	t.Helper()
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	body, err := TaskDataFetchBodyDigest(goldenOutputRef(), &ByteRange{Offset: 64, Length: 128})
	if err != nil {
		t.Fatal(err)
	}
	signature, err := hex.DecodeString(goldenEIP712Signature)
	if err != nil {
		t.Fatal(err)
	}
	return RequestAuthV1{
		SchemaVersion: 1, ChainID: "trueopen-golden-1",
		BuilderOperatorAddress:    goldenBuilder,
		RPCMethod:                 "/nexus.v1.IngressAPI/FetchTaskData",
		BodyDigest:                hex.EncodeToString(body[:]),
		RequesterKind:             RequesterKindUser,
		RequesterAddress:          goldenEIP712User,
		ServiceAuthorizationNonce: 0,
		RequestNonce:              nonce,
		ExpiryHeight:              2000,
		Signature:                 signature,
	}
}

func TestEIP712TypeHashes(t *testing.T) {
	domain := keccak256([]byte(eip712DomainType))
	if got := hex.EncodeToString(domain[:]); got != goldenEIP712DomainTypeHash {
		t.Fatalf("domain type hash = %s", got)
	}
	request := keccak256([]byte(eip712RequestType))
	if got := hex.EncodeToString(request[:]); got != goldenEIP712RequestTypeHas {
		t.Fatalf("request type hash = %s\nencodeType = %s", got, eip712RequestType)
	}
	separator := EIP712DomainSeparator(goldenEIP712NumericChainID)
	if got := hex.EncodeToString(separator[:]); got != goldenEIP712Separator {
		t.Fatalf("domain separator = %s", got)
	}
}

func TestEIP712UserFetchVector(t *testing.T) {
	auth := goldenUserFetchAuth(t)

	hashStruct, err := eip712HashStruct(auth)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(hashStruct[:]); got != goldenEIP712HashStruct {
		t.Fatalf("hash_struct = %s", got)
	}

	digest, err := UserTaskDataRequestDigest(auth, goldenEIP712NumericChainID)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(digest[:]); got != goldenEIP712SigningDigest {
		t.Fatalf("signing_digest = %s", got)
	}

	recovered, err := RecoverUserTaskDataRequester(digest, auth.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(recovered[:]); got != goldenEIP712Recovered {
		t.Fatalf("recovered_address = %s", got)
	}

	if err := VerifyUserTaskDataRequest(auth, goldenEIP712NumericChainID); err != nil {
		t.Fatalf("full verification failed: %v", err)
	}
}

// Inputs §4.2.1 explicitly requires rejecting. Each is a concrete form of "a signature from
// another chain / another body / another path impersonating this request".
func TestEIP712UserRejects(t *testing.T) {
	t.Run("wrong numeric chain id", func(t *testing.T) {
		auth := goldenUserFetchAuth(t)
		if err := VerifyUserTaskDataRequest(auth, goldenEIP712NumericChainID+1); err == nil {
			t.Fatal("domain numeric chain ID must take part in verification")
		}
	})

	t.Run("wrong string chain id", func(t *testing.T) {
		auth := goldenUserFetchAuth(t)
		auth.ChainID = "trueopen-golden-2"
		if err := VerifyUserTaskDataRequest(auth, goldenEIP712NumericChainID); err == nil {
			t.Fatal("chain_id string must take part in verification")
		}
	})

	t.Run("nonzero service nonce", func(t *testing.T) {
		auth := goldenUserFetchAuth(t)
		auth.ServiceAuthorizationNonce = 7
		if err := VerifyUserTaskDataRequest(auth, goldenEIP712NumericChainID); err == nil {
			t.Fatal("USER service_authorization_nonce must be 0")
		}
	})

	t.Run("raw64 signature", func(t *testing.T) {
		auth := goldenUserFetchAuth(t)
		auth.Signature = auth.Signature[:64]
		if err := VerifyUserTaskDataRequest(auth, goldenEIP712NumericChainID); err == nil {
			t.Fatal("USER must be exactly 65 bytes; raw64 must not be accepted")
		}
	})

	t.Run("bad recovery id", func(t *testing.T) {
		auth := goldenUserFetchAuth(t)
		bad := append([]byte(nil), auth.Signature...)
		bad[64] = 0 // the 0/1 form common with personal_sign
		auth.Signature = bad
		if err := VerifyUserTaskDataRequest(auth, goldenEIP712NumericChainID); err == nil {
			t.Fatal("V must be 27 or 28")
		}
	})

	t.Run("another requester", func(t *testing.T) {
		auth := goldenUserFetchAuth(t)
		auth.RequesterAddress = goldenProducer
		if err := VerifyUserTaskDataRequest(auth, goldenEIP712NumericChainID); err == nil {
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
		if err := VerifyUserTaskDataRequest(auth, goldenEIP712NumericChainID); err == nil {
			t.Fatal("a different body must fail: whole and ranged reads cannot share one signature")
		}
	})

	t.Run("another method", func(t *testing.T) {
		auth := goldenUserFetchAuth(t)
		auth.RPCMethod = "/nexus.v1.IngressAPI/GetTaskDataMetadata"
		if err := VerifyUserTaskDataRequest(auth, goldenEIP712NumericChainID); err == nil {
			t.Fatal("rpc_method must take part in verification")
		}
	})

	t.Run("cortex kind on a user signature", func(t *testing.T) {
		auth := goldenUserFetchAuth(t)
		auth.RequesterKind = RequesterKindCortexService
		if err := VerifyUserTaskDataRequest(auth, goldenEIP712NumericChainID); err == nil {
			t.Fatal("requester_kind selects the path; paths must not be mixed")
		}
	})
}
