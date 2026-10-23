package sdkauth

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/registeredkey"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

type orderVectors struct {
	OrderPayload wirefixture.Vector `json:"order_payload"`
	Wallet       orderSignature     `json:"wallet_order"`
	Delegated    orderSignature     `json:"delegated_order"`
	Account      struct {
		Bech32 string `json:"account_bech32"`
	} `json:"account"`
	SessionKey struct {
		AddressBytes string `json:"address_bytes"`
	} `json:"session_key"`
}

type orderSignature struct {
	Message struct {
		FeeDenom string `json:"feeDenom"`
	} `json:"message"`
	Signature        string `json:"signature_65"`
	SignatureChainID uint64 `json:"signature_chain_id,string"`
}

func loadOrderVectors(t *testing.T) (orderVectors, *taskv1.TaskOrderV3) {
	t.Helper()
	var out orderVectors
	raw := wirefixture.ReadFile(t, filepath.Join("testdata", "v1", "task", "session_key_authorization_v1.json"))
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out, wirefixture.TaskOrderV3(t, out.OrderPayload)
}

func signedWith(t *testing.T, order *taskv1.TaskOrderV3, s orderSignature) *taskv1.SignedOrderV2 {
	t.Helper()
	return &taskv1.SignedOrderV2{
		Order: order, SignatureScheme: "eip712", UserSignature: mustHex(t, s.Signature), SignatureChainId: s.SignatureChainID,
	}
}

func TestOrderPrecheckWalletOrderReadsNothing(t *testing.T) {
	f, order := loadOrderVectors(t)
	chain := &fakeChain{heightE: errors.New("CurrentHeight must not be called")}
	p, err := BeginOrderPrecheck(context.Background(), signedWith(t, order, f.Wallet), f.Wallet.Message.FeeDenom, chain)
	if err != nil || !p.Wallet || p.Height != 0 {
		t.Fatalf("wallet precheck = %+v, %v", p, err)
	}
	keys := &fakeSessionKeys{err: errors.New("must not be called")}
	if err := p.Check(context.Background(), keys, "77", order); err != nil || keys.calls != 0 {
		t.Fatalf("wallet Check = %v after %d lookups", err, keys.calls)
	}
}

// The delegated order of the wire vectors at height 1100, anchor 990: accepted against a key
// registered at 980 until 1100 with spent 1000000 and cap 1150000 (max_fee 150000), and each
// state change fails with its SDK code.
func TestOrderPrecheckRegisteredKeyOrder(t *testing.T) {
	f, order := loadOrderVectors(t)
	if order.GetSessionAnchorHeight() != 990 || order.GetMaxFee().GetAtomicUnits() != "150000" {
		t.Fatalf("vector order anchor %d max_fee %s", order.GetSessionAnchorHeight(), order.GetMaxFee().GetAtomicUnits())
	}
	var key, other [20]byte
	copy(key[:], mustHex(t, f.SessionKey.AddressBytes))
	other[0] = 9
	base := registeredkey.State{
		Found: true, Owner: f.Account.Bech32, Key: &key, ExpiryHeight: 1100, SetHeight: 980,
		SpendCap: "1150000", Spent: "1000000",
	}
	sessionID := hex.EncodeToString(order.GetSessionId())
	cases := []struct {
		name string
		edit func(*registeredkey.State)
		err  error
		want error
	}{
		{name: "accepted at the exact cap and inclusive expiry"},
		{name: "another key", edit: func(s *registeredkey.State) { s.Key = &other }, want: ErrInvalidSignature},
		{name: "cleared", edit: func(s *registeredkey.State) { s.Key = nil }, want: ErrInvalidSignature},
		{name: "closed", edit: func(s *registeredkey.State) { s.Closed = true }, want: ErrInvalidSignature},
		{name: "registered after the anchor", edit: func(s *registeredkey.State) { s.SetHeight = 991 }, want: ErrInvalidSignature},
		{name: "expired", edit: func(s *registeredkey.State) { s.ExpiryHeight = 1099 }, want: ErrSessionGrantExpired},
		{name: "one unit short", edit: func(s *registeredkey.State) { s.SpendCap = "1149999" }, want: ErrSessionKeySpendCapExceeded},
		{name: "unlimited", edit: func(s *registeredkey.State) { s.SpendCap = "0"; s.Spent = "999999999999" }},
		{name: "unlimited overflow", edit: func(s *registeredkey.State) { s.SpendCap = "0"; s.Spent = "18446744073709551615" }, want: ErrSessionKeySpendCapExceeded},
		{name: "state unreadable", err: registeredkey.ErrChainUnreadable, want: ErrInvalidSignature},
		{name: "lookups over budget", err: registeredkey.ErrUnavailable, want: ErrUnavailable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := BeginOrderPrecheck(context.Background(), signedWith(t, order, f.Delegated), f.Delegated.Message.FeeDenom,
				&fakeChain{height: 1100})
			if err != nil || p.Wallet || p.Recovered != key || p.Height != 1100 {
				t.Fatalf("precheck = %+v, %v", p, err)
			}
			state := base
			if c.edit != nil {
				c.edit(&state)
			}
			keys := &fakeSessionKeys{state: state, err: c.err}
			err = p.Check(context.Background(), keys, sessionID, order)
			if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("Check = %v, want %v", err, c.want)
			}
			if keys.heights[0] != 1100 {
				t.Fatalf("looked up at %d, want 1100", keys.heights[0])
			}
		})
	}
}

func TestOrderPrecheckFailures(t *testing.T) {
	f, order := loadOrderVectors(t)
	broken := signedWith(t, order, f.Delegated)
	broken.UserSignature = broken.UserSignature[:64]
	if _, err := BeginOrderPrecheck(context.Background(), broken, f.Delegated.Message.FeeDenom, &fakeChain{height: 1}); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("short signature = %v, want invalid", err)
	}
	if _, err := BeginOrderPrecheck(context.Background(), signedWith(t, order, f.Delegated), f.Delegated.Message.FeeDenom,
		&fakeChain{heightE: errors.New("down")}); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("height read failure = %v, want invalid", err)
	}
	p, err := BeginOrderPrecheck(context.Background(), signedWith(t, order, f.Delegated), f.Delegated.Message.FeeDenom, &fakeChain{height: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Check(context.Background(), nil, "77", order); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("no registered keys = %v, want invalid", err)
	}
}
