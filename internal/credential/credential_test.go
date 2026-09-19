package credential

import (
	"testing"

	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/types"
)

const testKeyHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60" // test only

func TestIssueVerifyRoundTrip(t *testing.T) {
	sg, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	cred, err := Issue(sg, types.Credential{
		SessionID: "sess-1", TaskID: "task-1", Recipient: "trueopen1user",
		Usage: "VERIFIER_FETCH", AccessLevel: types.AccessSealedKey, ValidUntil: 2_000_000_000_000,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if cred.ID == "" || len(cred.IssuerSig) != 64 || cred.Issuer != sg.Address() {
		t.Fatalf("credential incomplete: %+v", cred)
	}
	if err := Verify(cred, sg.PubKeyCompressed(), 1_000_000_000_000); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Expired.
	if err := Verify(cred, sg.PubKeyCompressed(), 3_000_000_000_000); err != ErrExpired {
		t.Fatalf("want ErrExpired, got %v", err)
	}
	// Tampered recipient -> the ID no longer matches.
	forged := cred
	forged.Recipient = "trueopen1attacker"
	if err := Verify(forged, sg.PubKeyCompressed(), 1_000_000_000_000); err != ErrInvalidSignature {
		t.Fatalf("want ErrInvalidSignature, got %v", err)
	}
	// Tampered validity with the ID recomputed (no private key) -> the signature fails to verify.
	forged2 := cred
	forged2.ValidUntil = 9_000_000_000_000
	forged2, _ = Issue(nil, forged2) // recompute the ID without re-signing (Issue(nil) does not overwrite Issuer/Sig)
	forged2.IssuerSig = cred.IssuerSig
	if err := Verify(forged2, sg.PubKeyCompressed(), 1_000_000_000_000); err != ErrInvalidSignature {
		t.Fatalf("want ErrInvalidSignature, got %v", err)
	}
}

func TestDevModeUnsigned(t *testing.T) {
	cred, err := Issue(nil, types.Credential{
		SessionID: "s", TaskID: "t", Recipient: "r", Usage: "SDK_DELIVERY",
		AccessLevel: types.AccessPackage, ValidUntil: 2_000_000_000_000,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if len(cred.IssuerSig) != 0 {
		t.Fatal("dev credential must be unsigned")
	}
	if err := Verify(cred, nil, 1_000_000_000_000); err != nil {
		t.Fatalf("dev verify: %v", err)
	}
}
