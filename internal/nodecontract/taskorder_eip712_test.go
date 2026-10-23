package nodecontract

import (
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/TrueOpen/nexus/internal/eip712"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

// TestTaskOrderDigestMatchesWireVectors: every task_order_eip712_v1 case must reproduce the signing
// digest over the task_order_v3 vector it names.
func TestTaskOrderDigestMatchesWireVectors(t *testing.T) {
	var file struct {
		Domain struct {
			ChainID string `json:"chain_id"`
		} `json:"domain"`
		FeeDenom string `json:"fee_denom"`
		Vectors  []struct {
			Name            string `json:"name"`
			TaskOrderVector string `json:"task_order_vector"`
			SigningDigest   string `json:"signing_digest"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(wirefixture.ReadFile(t, "testdata/v1/task/task_order_eip712_v1.json"), &file); err != nil {
		t.Fatalf("decode task_order_eip712_v1.json: %v", err)
	}
	chainID, err := strconv.ParseUint(file.Domain.ChainID, 10, 64)
	if err != nil {
		t.Fatalf("domain chain_id: %v", err)
	}
	orders := wirefixture.Load(t, "task/task_order_v3.json")
	if len(file.Vectors) == 0 {
		t.Fatal("no task order EIP-712 vectors")
	}
	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			ref, name, ok := strings.Cut(v.TaskOrderVector, "#")
			if !ok || ref != "task/task_order_v3.json" {
				t.Fatalf("unexpected task_order_vector %q", v.TaskOrderVector)
			}
			order := wireTaskOrder(t, orders.Vector(t, name, 0))
			digest, err := TaskOrderDigestV3(order, file.FeeDenom, chainID)
			if err != nil {
				t.Fatalf("TaskOrderDigestV3: %v", err)
			}
			if got := hex.EncodeToString(digest[:]); got != v.SigningDigest {
				t.Fatalf("signing digest = %s, want %s", got, v.SigningDigest)
			}
		})
	}
}

// TestTaskOrderDigestWalletAndSessionKey: the wallet and the registered session key sign the same
// order digest; recovery tells them apart (wire session_key_authorization_v1.json).
func TestTaskOrderDigestWalletAndSessionKey(t *testing.T) {
	type signedOrder struct {
		Message struct {
			FeeDenom string `json:"feeDenom"`
		} `json:"message"`
		RecoveredAddress string `json:"recovered_address"`
		Signature        string `json:"signature_65"`
		SignatureChainID uint64 `json:"signature_chain_id,string"`
		SigningDigest    string `json:"signing_digest"`
	}
	var file struct {
		OrderPayload   wirefixture.Vector `json:"order_payload"`
		WalletOrder    signedOrder        `json:"wallet_order"`
		DelegatedOrder signedOrder        `json:"delegated_order"`
		Account        struct {
			AddressBytes string `json:"address_bytes"`
		} `json:"account"`
		SessionKey struct {
			AddressBytes string `json:"address_bytes"`
		} `json:"session_key"`
	}
	if err := json.Unmarshal(wirefixture.ReadFile(t, "testdata/v1/task/session_key_authorization_v1.json"), &file); err != nil {
		t.Fatalf("decode session_key_authorization_v1.json: %v", err)
	}
	order := wireTaskOrder(t, file.OrderPayload)
	for name, c := range map[string]struct {
		signed signedOrder
		want   string
	}{
		"wallet":      {file.WalletOrder, file.Account.AddressBytes},
		"session_key": {file.DelegatedOrder, file.SessionKey.AddressBytes},
	} {
		t.Run(name, func(t *testing.T) {
			digest, err := TaskOrderDigestV3(order, c.signed.Message.FeeDenom, c.signed.SignatureChainID)
			if err != nil {
				t.Fatalf("TaskOrderDigestV3: %v", err)
			}
			if got := hex.EncodeToString(digest[:]); got != c.signed.SigningDigest {
				t.Fatalf("signing digest = %s, want %s", got, c.signed.SigningDigest)
			}
			signature, err := hex.DecodeString(c.signed.Signature)
			if err != nil {
				t.Fatalf("signature: %v", err)
			}
			recovered, err := eip712.Recover(digest, signature)
			if err != nil {
				t.Fatalf("recover: %v", err)
			}
			if got := hex.EncodeToString(recovered.Address[:]); got != c.want || got != c.signed.RecoveredAddress {
				t.Fatalf("recovered %s, want %s", got, c.want)
			}
		})
	}
}

func TestTaskOrderDigestRefusesBadInput(t *testing.T) {
	order := contractTaskOrderFixture(t)
	if _, err := TaskOrderDigestV3(order, "", 1); err == nil {
		t.Fatal("an empty fee denom must be refused")
	}
	if _, err := TaskOrderDigestV3(order, "uusdc", 0); err == nil {
		t.Fatal("signature_chain_id 0 must be refused")
	}
	if _, err := TaskOrderDigestV3(nil, "uusdc", 1); err == nil {
		t.Fatal("a nil order must be refused")
	}
}
