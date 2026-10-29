package registeredkey

import (
	"errors"
	"testing"
)

// The base case: key registered at 50, expiring at 200, cap 1000 with 600 spent; an order with
// max_fee 100 at height 100 whose record deadline is 150.
func dispatchBase() (State, DispatchOrder) {
	key := [20]byte{7}
	state := State{Found: true, Owner: "u", Key: &key, ExpiryHeight: 200, SetHeight: 50, SpendCap: "1000", Spent: "600"}
	order := DispatchOrder{User: "u", Recovered: key, AnchorHeight: 60, MaxFee: "100", Height: 100, Deadline: 150}
	return state, order
}

func TestCheckDispatchOrder(t *testing.T) {
	other := [20]byte{8}
	cases := []struct {
		name  string
		state func(*State)
		order func(*DispatchOrder)
		want  error
	}{
		{name: "accepted"},
		{name: "request checks still apply", state: func(s *State) { s.Closed = true }, want: ErrKeyInvalid},
		{name: "anchor before registration", order: func(o *DispatchOrder) { o.AnchorHeight = 49 }, want: ErrKeyInvalid},
		// The key must outlive the record deadline, not only the current height.
		{name: "expiry at the deadline", state: func(s *State) { s.ExpiryHeight = 150 }},
		{name: "expiry before the deadline", state: func(s *State) { s.ExpiryHeight = 149 }, want: ErrKeyExpired},
		// Two in-flight orders: each fits the cap alone, the second must count the first.
		{name: "in flight fills the cap exactly", order: func(o *DispatchOrder) { o.InFlight = "300" }},
		{name: "in flight leaves no room", order: func(o *DispatchOrder) { o.InFlight = "301" }, want: ErrSpendCapExceeded},
		{name: "unlimited cap ignores in flight", state: func(s *State) { s.SpendCap = "0" }, order: func(o *DispatchOrder) { o.InFlight = "99999" }},
		{name: "malformed in flight", order: func(o *DispatchOrder) { o.InFlight = "x" }, want: ErrChainUnreadable},
		// A registered clear or lower cap is treated as already effective.
		{name: "pending clear", state: func(s *State) { s.Pending = &PendingChange{Clear: true, EffectiveHeight: 999} }, want: ErrKeyInvalid},
		{name: "pending lower cap", state: func(s *State) {
			s.Pending = &PendingChange{Key: s.Key, ExpiryHeight: 200, SpendCap: "699", EffectiveHeight: 999}
		}, want: ErrSpendCapExceeded},
		{name: "pending cap from unlimited to limited", state: func(s *State) {
			s.SpendCap = "0"
			s.Pending = &PendingChange{Key: s.Key, ExpiryHeight: 200, SpendCap: "650", EffectiveHeight: 999}
		}, want: ErrSpendCapExceeded},
		{name: "pending higher cap waits for its height", state: func(s *State) {
			s.SpendCap = "650"
			s.Pending = &PendingChange{Key: s.Key, ExpiryHeight: 200, SpendCap: "5000", EffectiveHeight: 120}
		}, want: ErrSpendCapExceeded},
		{name: "pending shorter expiry", state: func(s *State) {
			s.Pending = &PendingChange{Key: s.Key, ExpiryHeight: 149, SpendCap: "1000", EffectiveHeight: 999}
		}, want: ErrKeyExpired},
		// A pending switch to another key ends the old one at its effective height: the old key may
		// still sign only orders recorded before it.
		{name: "pending other key after the deadline", state: func(s *State) {
			s.Pending = &PendingChange{Key: &other, ExpiryHeight: 900, EffectiveHeight: 151}
		}},
		{name: "pending other key by the deadline", state: func(s *State) {
			s.Pending = &PendingChange{Key: &other, ExpiryHeight: 900, EffectiveHeight: 150}
		}, want: ErrKeyInvalid},
		{name: "pending key not effective yet signs nothing", order: func(o *DispatchOrder) { o.Recovered = other }, state: func(s *State) {
			s.Pending = &PendingChange{Key: &other, ExpiryHeight: 900, EffectiveHeight: 101}
		}, want: ErrKeyInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state, order := dispatchBase()
			if c.state != nil {
				c.state(&state)
			}
			if c.order != nil {
				c.order(&order)
			}
			err := CheckDispatchOrder(state, order)
			if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("CheckDispatchOrder = %v, want %v", err, c.want)
			}
		})
	}
}
