package coordinator

import (
	"bytes"
	"context"
	"encoding/hex"
	"log/slog"
	"strings"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/signer"
)

// hashingChain returns an assertable tx_hash on successful broadcast.
//
// captureChain returns TxResult{Code: 0} with an empty TxHash -- it cares about "what bytes were
// broadcast", not "what hash the chain returned", so this is a separate fake rather than a change to it.
type hashingChain struct {
	*captureChain
	txHash []byte
}

func (c *hashingChain) BroadcastTx(ctx context.Context, tx []byte) (chaincli.TxResult, error) {
	if _, err := c.captureChain.BroadcastTx(ctx, tx); err != nil {
		return chaincli.TxResult{}, err
	}
	return chaincli.TxResult{Code: 0, TxHash: c.txHash, Height: 0}, nil
}

// TestBroadcastSuccessLogsTxHash pins "a transaction that was sent must leave its tx_hash".
//
// CheckTx code=0 only means it entered the mempool; DeliverTx success or failure is only known by
// QueryTx with this hash -- which is exactly what the coordinator's periodic reconciliation does.
// Previously the success path logged nothing; on site one only saw the failure line
// "AssignTx rejected by DeliverTx"; successful transactions left no trace, and there was no hash
// to look one up on-chain.
//
// The assertion sits at the single exit of submitMsg, so all nine Msg kinds are covered: any Submit*
// reaching CheckTx code=0 leaves a trace, without logging in each method or missing a newly added one.
func TestBroadcastSuccessLogsTxHash(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	sg, err := signer.NewFromHex(testKeyHex, "trueopen")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	wantHash := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}
	chain := &hashingChain{
		captureChain: &captureChain{acc: chaincli.AccountInfo{AccountNumber: 7, Sequence: 42}},
		txHash:       wantHash,
	}
	sub := NewSignedSubmitter(log, chain, chain, sg, sg, config.ChainConfig{
		ChainID: "trueopen-localnet", GasLimit: 200000, FeeDenom: "utrueopen", FeeAmount: "5000",
	})

	res, err := sub.SubmitSettle(context.Background(), chaincli.SettleTx{
		Submitter: sg.Address(), SessionID: "sess-txhash", TaskID: strings.Repeat("ab", 32),
	})
	if err != nil {
		t.Fatalf("SubmitSettle: %v", err)
	}
	if res.Code != 0 {
		t.Fatalf("code = %d, want 0", res.Code)
	}

	body := buf.String()
	if !strings.Contains(body, "tx broadcast accepted by CheckTx") {
		t.Fatalf("successful broadcast left no trace at Info level:\n%s", body)
	}
	if !strings.Contains(body, hex.EncodeToString(wantHash)) {
		t.Fatalf("log has no tx_hash=%s:\n%s", hex.EncodeToString(wantHash), body)
	}
	// sequence must report the one actually used (42), not the post-increment 43 -- it has to match the chain when debugging.
	if !strings.Contains(body, "sequence=42") {
		t.Fatalf("logged sequence is not the 42 actually used:\n%s", body)
	}
	if !strings.Contains(body, chaincli.TypeURLMsgSettleTask) {
		t.Fatalf("log has no type_url:\n%s", body)
	}
}
