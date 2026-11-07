package config

import "testing"

// With gas_price set, a transaction's fee is gas_limit × gas_price rounded up; without it the
// fixed fee_amount applies whatever the gas.
func TestTxFeeFollowsTheGasWithAGasPrice(t *testing.T) {
	c := ChainConfig{FeeDenom: "utrueopen", FeeAmount: "5000", GasPrice: "0.025"}
	for _, tc := range []struct {
		gas  uint64
		want string
	}{{200_000, "5000"}, {400_000, "10000"}, {1, "1"}, {41, "2"}, {0, "0"}} {
		if got := c.TxFee(tc.gas); got != tc.want {
			t.Fatalf("fee for gas %d = %s, want %s", tc.gas, got, tc.want)
		}
	}
	for _, price := range []string{"", "0", "0.0"} {
		c.GasPrice = price
		if got := c.TxFee(400_000); got != "5000" {
			t.Fatalf("gas price %q: fee %s, want the fixed 5000", price, got)
		}
	}
}

func TestValidateFee(t *testing.T) {
	for _, tc := range []struct {
		c  ChainConfig
		ok bool
	}{
		{ChainConfig{}, true},
		{ChainConfig{GasPrice: "0"}, true},
		{ChainConfig{FeeDenom: "utrueopen", GasPrice: "0.025"}, true},
		{ChainConfig{FeeDenom: "utrueopen", GasPrice: "12"}, true},
		{ChainConfig{GasPrice: "0.025"}, false}, // no denom to pay it in
		{ChainConfig{FeeDenom: "utrueopen", GasPrice: "-1"}, false},
		{ChainConfig{FeeDenom: "utrueopen", GasPrice: "1e-3"}, false},
		{ChainConfig{FeeDenom: "utrueopen", GasPrice: "1/3"}, false},
		{ChainConfig{FeeDenom: "utrueopen", GasPrice: "0.025utrueopen"}, false},
	} {
		if err := tc.c.ValidateFee(); (err == nil) != tc.ok {
			t.Fatalf("%+v: err = %v, want ok %v", tc.c, err, tc.ok)
		}
	}
}

// record_gas_max defaults to a cap above a full batch at the formula's gas and must hold at least
// one entry.
func TestRecordGasMax(t *testing.T) {
	d := defaultDispatch()
	if d.RecordGasMax == 0 {
		t.Fatal("no default record_gas_max")
	}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	d.RecordGasMax = d.RecordGasBase + d.RecordGasPerEntry - 1
	if err := d.Validate(); err == nil {
		t.Fatal("record_gas_max below one entry accepted")
	}
	d.RecordGasMax = maxRecordGas + 1
	if err := d.Validate(); err == nil {
		t.Fatal("record_gas_max above the bound accepted")
	}
}
