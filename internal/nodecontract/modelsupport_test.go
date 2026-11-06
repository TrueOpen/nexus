package nodecontract

import (
	"encoding/hex"
	"testing"

	"github.com/TrueOpen/nexus/internal/wirefixture"
)

func wireSupportModels(t *testing.T, v wirefixture.Vector) [][]byte {
	t.Helper()
	frame := v.Field(t, "models").Fields
	models := make([][]byte, 0, len(frame)-1)
	for _, f := range frame[1:] {
		models = append(models, f.Bytes(t))
	}
	return models
}

// The confirmation digest is pinned to the daily_support_confirmation_v1 vector of wire
// testdata/v1/hub/hub_domains_v1.json, preimage byte for byte.
func TestDailySupportConfirmationDigestMatchesWireVector(t *testing.T) {
	v := wirefixture.Load(t, "hub/hub_domains_v1.json").Vector(t, "daily_support_confirmation_v1", 0)
	v.CheckPreimage(t)
	operator := v.Field(t, "operator_address").Bytes(t)
	models := wireSupportModels(t, v)
	chainID := v.Field(t, "chain_id").UTF8
	epoch := v.Field(t, "epoch_index").Uint64(t)
	nonce := v.Field(t, "service_authorization_nonce").Uint64(t)
	expiry := v.Field(t, "expiry_height").Uint64(t)

	preimage, err := DailySupportConfirmationPreimage(chainID, operator, epoch, nonce, expiry, models)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(preimage); got != v.PreimageHex {
		t.Fatalf("preimage mismatch\n got %s\nwant %s", got, v.PreimageHex)
	}
	digest, err := DailySupportConfirmationSigningDigest(chainID, operator, epoch, nonce, expiry, models)
	if err != nil {
		t.Fatal(err)
	}
	if digest != v.Digest(t) {
		t.Fatalf("digest = %x, want wire %s", digest, v.DigestHex)
	}
}

func TestSupportedModelsHashMatchesWireVector(t *testing.T) {
	v := wirefixture.Load(t, "hub/hub_domains_v1.json").Vector(t, "support_models_v1", 0)
	v.CheckPreimage(t)
	got, err := SupportedModelsHash(wireSupportModels(t, v))
	if err != nil {
		t.Fatal(err)
	}
	if got != v.Digest(t) {
		t.Fatalf("supported models hash = %x, want wire %s", got, v.DigestHex)
	}
}

// The model list must already be canonical: raw Hash32 ids, strictly ascending and unique. A
// list the chain would refuse has no digest rather than a reordered one.
func TestModelSupportDigestsRefuseNonCanonicalModels(t *testing.T) {
	one, two := make([]byte, 32), make([]byte, 32)
	one[31], two[31] = 1, 2
	operator := make([]byte, 20)
	for name, models := range map[string][][]byte{
		"empty":      nil,
		"short id":   {one[:31]},
		"descending": {two, one},
		"duplicate":  {one, one},
	} {
		if _, err := DailySupportConfirmationSigningDigest("c", operator, 1, 1, 1, models); err == nil {
			t.Errorf("%s: confirmation digest accepted", name)
		}
		if _, err := SupportedModelsHash(models); err == nil {
			t.Errorf("%s: supported models hash accepted", name)
		}
	}
	if _, err := DailySupportConfirmationSigningDigest("c", operator[:19], 1, 1, 1, [][]byte{one}); err == nil {
		t.Error("19-byte operator accepted")
	}
}
