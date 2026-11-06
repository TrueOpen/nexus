package nodecontract

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"
)

// TrueOpen/wire testdata/v1/task/output_mmr_v1.json "fin_signing", compared byte-for-byte:
// the TRUEOPEN_OUTPUT_FIN_V1 digest for each accepted finish reason, the mutation digests, the full
// EOS_TOKEN preimage and the RFC6979 signature under the chunk_signing test key.
func TestGoldenOutputFinSigningDigest(t *testing.T) {
	v := loadWireOutputMMR(t)
	fin := v.Fin
	taskHash, ticket, root := mustHex(t, fin.TaskHashHex), mustHex(t, fin.TicketHex), mustHex(t, fin.RootHex)
	if len(fin.Accepted) != MaxFinishReasonV1 {
		t.Fatalf("wire lists %d accepted finish reasons, want %d", len(fin.Accepted), MaxFinishReasonV1)
	}
	for _, c := range fin.Accepted {
		digest, err := OutputFinSigningDigest(fin.ChainID, taskHash, ticket, fin.FinalSeq, root, c.Value)
		if err != nil {
			t.Fatalf("finish_reason %d: %v", c.Value, err)
		}
		if got := hex.EncodeToString(digest[:]); got != c.DigestHex {
			t.Fatalf("finish_reason %d digest = %s, want %s", c.Value, got, c.DigestHex)
		}
	}
	for _, c := range fin.Rejected {
		if c.Value < 0 {
			continue // a negative enum number cannot reach the uint32 API
		}
		if _, err := OutputFinSigningDigest(fin.ChainID, taskHash, ticket, fin.FinalSeq, root, uint32(c.Value)); err == nil {
			t.Fatalf("finish_reason %d must be rejected", c.Value)
		}
	}
	if len(fin.Mutations) == 0 {
		t.Fatal("wire fin_signing has no mutation digests")
	}
	for _, m := range fin.Mutations {
		chainID, task, tk, seq, r, reason := fin.ChainID, taskHash, ticket, fin.FinalSeq, root, uint32(1)
		var text string
		if len(m.Value) > 0 {
			if unquoted, err := strconv.Unquote(string(m.Value)); err == nil {
				text = unquoted
			} else {
				text = string(m.Value)
			}
		}
		switch m.Field {
		case "chain_id":
			chainID = text
		case "task_hash":
			task = mustHex(t, m.ValueHex)
		case "dispatch_ticket_hash":
			tk = mustHex(t, m.ValueHex)
		case "final_seq":
			n, err := strconv.ParseUint(text, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			seq = n
		case "output_mmr_root":
			r = mustHex(t, m.ValueHex)
		case "finish_reason":
			n, err := strconv.ParseUint(text, 10, 32)
			if err != nil {
				t.Fatal(err)
			}
			reason = uint32(n)
		default:
			t.Fatalf("unknown mutation field %q", m.Field)
		}
		digest, err := OutputFinSigningDigest(chainID, task, tk, seq, r, reason)
		if err != nil {
			t.Fatalf("%s mutation: %v", m.Field, err)
		}
		if got := hex.EncodeToString(digest[:]); got != m.DigestHex {
			t.Fatalf("%s mutation digest = %s, want %s", m.Field, got, m.DigestHex)
		}
	}

	eos, err := OutputFinSigningDigest(fin.ChainID, taskHash, ticket, fin.FinalSeq, root, 1)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(mustHex(t, fin.PreimageHex)) != eos {
		t.Fatal("the published EOS_TOKEN preimage does not hash to the computed digest")
	}
	if got := signRFC6979(t, v.Chunk.PrivateKeyHex, eos); got != fin.SignatureHex {
		t.Fatalf("signature = %s, want %s", got, fin.SignatureHex)
	}
}
