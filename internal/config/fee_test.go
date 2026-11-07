package config

import (
	"os"
	"path/filepath"
	"testing"
)

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

// record_gas_max defaults to DefaultRecordGasMax, also when it is 0 (a config built without it,
// or a yaml that sets 0); a value set must hold at least one entry.
func TestRecordGasMax(t *testing.T) {
	d := defaultDispatch()
	if d.RecordGasMax != DefaultRecordGasMax || d.RecordGasCap() != DefaultRecordGasMax {
		t.Fatalf("default record_gas_max %d, cap %d", d.RecordGasMax, d.RecordGasCap())
	}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	d.RecordGasMax = 0
	if err := d.Validate(); err != nil || d.RecordGasCap() != DefaultRecordGasMax {
		t.Fatalf("record_gas_max 0: err %v, cap %d; want the default", err, d.RecordGasCap())
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

// A deployed yaml without record_gas_max (or gas_price) still loads and gets the default.
func TestYAMLWithoutRecordGasMaxGetsTheDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nexus.yaml")
	yaml := "dispatch:\n  record_gas_base: 200000\n  record_gas_per_entry: 150000\n  record_gas_per_byte: 150\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Dispatch.RecordGasMax != DefaultRecordGasMax || cfg.Chain.GasPrice != "" {
		t.Fatalf("record_gas_max %d, gas_price %q; want the defaults", cfg.Dispatch.RecordGasMax, cfg.Chain.GasPrice)
	}
	if err := cfg.Dispatch.Validate(); err != nil {
		t.Fatal(err)
	}
}
