package registeredkey

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/cosmos/cosmos-sdk/types/bech32"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

type wireState struct {
	Cap       string `json:"cap"`
	Expiry    uint64 `json:"expiry"`
	Key       string `json:"key"`
	Owner     string `json:"owner"`
	SetHeight uint64 `json:"set_height"`
	Spent     string `json:"spent"`
	Status    string `json:"status"`
}

type admissionCase struct {
	Name          string    `json:"name"`
	Expected      string    `json:"expected"`
	Order         string    `json:"order"`
	CurrentHeight uint64    `json:"current_height"`
	AnchorHeight  uint64    `json:"anchor_height"`
	State         wireState `json:"state"`
}

type signedOrderVector struct {
	Message struct {
		MaxFee   string `json:"maxFee"`
		FeeDenom string `json:"feeDenom"`
	} `json:"message"`
	Signature        string `json:"signature_65"`
	SignatureChainID uint64 `json:"signature_chain_id,string"`
	SigningDigest    string `json:"signing_digest"`
}

type authorizationFile struct {
	OrderPayload wirefixture.Vector `json:"order_payload"`
	WalletOrder  signedOrderVector  `json:"wallet_order"`
	WrongKey     struct {
		PrivateKey   string `json:"private_key"`
		AddressBytes string `json:"address_bytes"`
	} `json:"wrong_key"`
	Account struct {
		AccountBech32 string `json:"account_bech32"`
		AddressBytes  string `json:"address_bytes"`
	} `json:"account"`
	SessionKey struct {
		AddressBytes string `json:"address_bytes"`
	} `json:"session_key"`
	DelegatedOrder signedOrderVector `json:"delegated_order"`
	AdmissionCases []admissionCase   `json:"admission_cases"`
}

func loadAuthorization(t *testing.T) authorizationFile {
	t.Helper()
	var file authorizationFile
	if err := json.Unmarshal(wirefixture.ReadFile(t, "testdata/v1/task/session_key_authorization_v1.json"), &file); err != nil {
		t.Fatalf("decode session_key_authorization_v1.json: %v", err)
	}
	return file
}

func address20(t *testing.T, value string) [20]byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 20 {
		t.Fatalf("address %q", value)
	}
	var out [20]byte
	copy(out[:], raw)
	return out
}

// stateFrom converts a vector state; the owner is given as raw bytes and becomes the bech32 form
// the chain query returns.
func stateFrom(t *testing.T, file authorizationFile, s wireState) State {
	t.Helper()
	owner := s.Owner
	if owner == file.Account.AddressBytes {
		owner = file.Account.AccountBech32
	} else {
		raw, err := hex.DecodeString(owner)
		if err != nil {
			t.Fatalf("owner %q", owner)
		}
		owner, err = bech32.ConvertAndEncode("trueopen", raw)
		if err != nil {
			t.Fatalf("owner %q: %v", s.Owner, err)
		}
	}
	state := State{
		Found: true, Owner: owner, Closed: s.Status == "CLOSED",
		ExpiryHeight: s.Expiry, SetHeight: s.SetHeight, SpendCap: s.Cap, Spent: s.Spent,
	}
	if s.Key != "" {
		key := address20(t, s.Key)
		state.Key = &key
	}
	return state
}

// TestCheckOrderMatchesWireAdmissionCases runs the authorization rows of the wire admission cases
// through the precheck.
func TestCheckOrderMatchesWireAdmissionCases(t *testing.T) {
	file := loadAuthorization(t)
	want := map[string]error{
		"ACCEPT_SESSION_KEY":                 nil,
		"ERR_SESSION_KEY_EXPIRED":            ErrKeyExpired,
		"ERR_SESSION_KEY_INVALID":            ErrKeyInvalid,
		"ERR_SESSION_KEY_SPEND_CAP_EXCEEDED": ErrSpendCapExceeded,
		// Outcome labels the Keeper reports under existing codes. The precheck maps a cleared key
		// and a CLOSED session to an invalid key (SDK_AUTH_INVALID_SIGNATURE), and a counter
		// overflow under an unlimited cap to over the cap (SDK_AUTH_SESSION_KEY_SPEND_CAP_EXCEEDED).
		"SIGNATURE_MISMATCH": ErrKeyInvalid,
		"SESSION_CLOSED":     ErrKeyInvalid,
		"OWNER_MISMATCH":     ErrKeyInvalid,
		"AMOUNT_OVERFLOW":    ErrSpendCapExceeded,
	}
	// Keeper-only rows: sequence use, rollback and admitted tasks are not session key checks.
	keeperOnly := map[string]bool{
		"SEQUENCE_MISMATCH": true, "LATER_ADMISSION_REJECTED": true, "ALREADY_ADMITTED": true,
	}
	recovered := address20(t, file.SessionKey.AddressBytes)
	checked := 0
	for _, c := range file.AdmissionCases {
		if keeperOnly[c.Expected] {
			continue
		}
		if c.Expected == "ACCEPT_WALLET" {
			// A wallet order is told apart by OrderSigner and never reaches CheckOrder, whatever
			// the registered key's state.
			checked++
			if c.Order != "wallet_order" {
				t.Fatalf("case %s: ACCEPT_WALLET for %s", c.Name, c.Order)
			}
			if _, wallet, err := OrderSigner(signedOrder(t, file, file.WalletOrder), file.WalletOrder.Message.FeeDenom); err != nil || !wallet {
				t.Fatalf("case %s: wallet=%v err=%v", c.Name, wallet, err)
			}
			continue
		}
		expected, ok := want[c.Expected]
		if !ok {
			t.Fatalf("case %s: unknown expectation %s", c.Name, c.Expected)
		}
		checked++
		t.Run(c.Name, func(t *testing.T) {
			state := stateFrom(t, file, c.State)
			err := CheckOrder(state, file.Account.AccountBech32, recovered, c.AnchorHeight,
				file.DelegatedOrder.Message.MaxFee, c.CurrentHeight)
			if expected == nil && err != nil || expected != nil && !errors.Is(err, expected) {
				t.Fatalf("CheckOrder = %v, want %v", err, expected)
			}
		})
	}
	if checked < 15 {
		t.Fatalf("only %d admission cases checked", checked)
	}
}

func TestCheckRequest(t *testing.T) {
	file := loadAuthorization(t)
	key := address20(t, file.SessionKey.AddressBytes)
	owner := file.Account.AccountBech32
	base := State{Found: true, Owner: owner, Key: &key, ExpiryHeight: 1100, SetHeight: 980, SpendCap: "1", Spent: "5"}
	other := address20(t, file.Account.AddressBytes)
	cases := []struct {
		name      string
		edit      func(*State)
		signer    string
		recovered [20]byte
		height    uint64
		want      error
	}{
		{name: "accepted at the inclusive expiry", height: 1100},
		// Requests never consume the cap, so a cap below spent does not matter.
		{name: "cap below spent is irrelevant", height: 1000},
		{name: "expired", height: 1101, want: ErrKeyExpired},
		{name: "no session", edit: func(s *State) { *s = State{} }, height: 1000, want: ErrKeyInvalid},
		{name: "closed", edit: func(s *State) { s.Closed = true }, height: 1000, want: ErrKeyInvalid},
		{name: "no key", edit: func(s *State) { s.Key = nil }, height: 1000, want: ErrKeyInvalid},
		{name: "other owner", signer: "trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man", height: 1000, want: ErrKeyInvalid},
		{name: "other key", recovered: other, height: 1000, want: ErrKeyInvalid},
		// A closed session reports an invalid key even past expiry: state comes before expiry.
		{name: "closed and expired", edit: func(s *State) { s.Closed = true }, height: 2000, want: ErrKeyInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state := base
			if c.edit != nil {
				c.edit(&state)
			}
			signer, recovered := owner, key
			if c.signer != "" {
				signer = c.signer
			}
			if c.recovered != ([20]byte{}) {
				recovered = c.recovered
			}
			err := CheckRequest(state, signer, recovered, c.height)
			if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("CheckRequest = %v, want %v", err, c.want)
			}
		})
	}
}

func TestCheckOrderRefusesMalformedAmounts(t *testing.T) {
	key := [20]byte{1}
	state := State{Found: true, Owner: "u", Key: &key, ExpiryHeight: 10, SpendCap: "100", Spent: "x"}
	if err := CheckOrder(state, "u", key, 0, "1", 5); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("malformed spent = %v, want unavailable", err)
	}
	state.Spent = "1"
	if err := CheckOrder(state, "u", key, 0, "-1", 5); !errors.Is(err, ErrKeyInvalid) {
		t.Fatalf("negative max_fee = %v, want invalid", err)
	}
	state.SpendCap = ""
	if err := CheckOrder(state, "u", key, 0, "1000000", 5); err != nil {
		t.Fatalf("an empty cap is unlimited: %v", err)
	}
}

func signedOrder(t *testing.T, file authorizationFile, v signedOrderVector) *taskv1.SignedOrderV2 {
	t.Helper()
	signature, err := hex.DecodeString(v.Signature)
	if err != nil {
		t.Fatalf("signature: %v", err)
	}
	return &taskv1.SignedOrderV2{
		Order: wirefixture.TaskOrderV3(t, file.OrderPayload), SignatureScheme: "eip712",
		UserSignature: signature, SignatureChainId: v.SignatureChainID,
	}
}

// OrderSigner tells the wallet from any other signer of the same order digest; a key that is not
// the session's (wire wrong_key) then fails CheckOrder as an invalid key.
func TestOrderSigner(t *testing.T) {
	file := loadAuthorization(t)
	denom := file.WalletOrder.Message.FeeDenom
	if _, wallet, err := OrderSigner(signedOrder(t, file, file.WalletOrder), denom); err != nil || !wallet {
		t.Fatalf("wallet order: wallet=%v err=%v", wallet, err)
	}
	recovered, wallet, err := OrderSigner(signedOrder(t, file, file.DelegatedOrder), denom)
	if err != nil || wallet || recovered != address20(t, file.SessionKey.AddressBytes) {
		t.Fatalf("delegated order: wallet=%v recovered=%x err=%v", wallet, recovered, err)
	}
	// The same order under another fee denom is another digest: it recovers to some other address.
	if recovered, wallet, err := OrderSigner(signedOrder(t, file, file.WalletOrder), "uother"); err != nil || wallet ||
		recovered == address20(t, file.Account.AddressBytes) {
		t.Fatalf("wrong denom: wallet=%v recovered=%x err=%v", wallet, recovered, err)
	}

	digest, err := hex.DecodeString(file.DelegatedOrder.SigningDigest)
	if err != nil || len(digest) != 32 {
		t.Fatalf("signing digest: %v", err)
	}
	keyBytes, err := hex.DecodeString(file.WrongKey.PrivateKey)
	if err != nil {
		t.Fatalf("wrong key: %v", err)
	}
	compact := ecdsa.SignCompact(secp256k1.PrivKeyFromBytes(keyBytes), digest, false) // [V R S]
	wrong := file.DelegatedOrder
	wrong.Signature = hex.EncodeToString(append(compact[1:], compact[0]))
	recovered, wallet, err = OrderSigner(signedOrder(t, file, wrong), denom)
	if err != nil || wallet || recovered != address20(t, file.WrongKey.AddressBytes) {
		t.Fatalf("wrong key order: wallet=%v recovered=%x err=%v", wallet, recovered, err)
	}
	state := stateFrom(t, file, file.AdmissionCases[0].State)
	if err := CheckOrder(state, file.Account.AccountBech32, recovered, 990, "150000", 1100); !errors.Is(err, ErrKeyInvalid) {
		t.Fatalf("wrong key CheckOrder = %v, want invalid", err)
	}

	broken := signedOrder(t, file, file.DelegatedOrder)
	broken.UserSignature = broken.UserSignature[:64]
	if _, _, err := OrderSigner(broken, denom); !errors.Is(err, ErrKeyInvalid) {
		t.Fatalf("short signature = %v, want invalid", err)
	}
}
