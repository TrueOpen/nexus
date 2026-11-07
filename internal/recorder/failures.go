package recorder

import (
	"fmt"

	"github.com/TrueOpen/nexus/internal/chaincli"
)

const (
	// sameRefusalLimit is how many record transactions in a row may be refused with the same
	// unexplained code before the batch is halved, or records stop once a batch holds one entry.
	sameRefusalLimit = 3
	// fatalRetryBlocks is how long records stay stopped after a refusal sending again cannot fix,
	// unless an event of this Builder's service key comes first.
	fatalRetryBlocks = 10
	// maxGasFactor bounds how far out-of-gas refusals raise the gas of record transactions.
	maxGasFactor = 8
	// gasStepDownSuccesses is how many transactions sent at the raised gas factor must succeed in
	// a row before it is halved. Halving after one success would, for a batch that needs a gas in
	// between two factors, run every other transaction out of gas.
	gasStepDownSuccesses = 8
)

// refusalClass is what a refused record transaction asks of the next one.
type refusalClass int

const (
	// refusalOther: unexplained; the entries go out again unchanged until it repeats.
	refusalOther refusalClass = iota
	// refusalOutOfGas: the batch needs more gas than it had; the same batch with more gas, and
	// smaller batches only once the gas is at its highest.
	refusalOutOfGas
	// refusalFatal: the submitter itself is refused (unauthorized, unfunded, invalid key);
	// sending again changes nothing until the account or key does.
	refusalFatal
)

// classify reads a refusal's cosmos-sdk code. Module codes are not told apart: their numbers are
// the node's, so they repeat into a halving or a stop instead.
func classify(res chaincli.TxResult) refusalClass {
	if chaincli.IsOutOfGas(res) {
		return refusalOutOfGas
	}
	if res.Codespace != "sdk" {
		return refusalOther
	}
	switch res.Code {
	case 4, 5, 8, codeInsufficientFee: // unauthorized, insufficient funds, invalid pubkey, insufficient fee
		return refusalFatal
	}
	return refusalOther
}

// codeInsufficientFee is the cosmos-sdk code of a fee below the chain's minimum gas price.
const codeInsufficientFee = 13

// atGasCeiling reports whether a record transaction sent with gas factor factor and gas limit gas
// had the most gas a record gets: the highest factor, or the GasMax cap.
func (r *Recorder) atGasCeiling(factor, gas uint64) bool {
	return factor >= maxGasFactor || r.cfg.GasMax != 0 && gas >= r.cfg.GasMax
}

// sizing is the local limit deterministic refusals put on record transactions, and the stop a
// fatal one puts on them. Guarded by Recorder.mu.
type sizing struct {
	// maxEntries is the lowered entry cap, 0 when params.MaxEntries applies.
	maxEntries uint32
	// gasFactor multiplies the gas of every record transaction; 0 counts as 1. gasWins counts the
	// transactions sent at gasFactor that succeeded since it last changed.
	gasFactor uint64
	gasWins   int
	// streak counts consecutive refusals with streakCode.
	streak     int
	streakCode string
	// stoppedUntil is the height records resume at after a fatal refusal; 0 when not stopped.
	stoppedUntil uint64
	stopReason   string
}

// refused takes the refusal of a record transaction of the entries objects, sent with gas factor
// factor and gas limit gas, at height.
func (r *Recorder) refused(res chaincli.TxResult, objects []string, factor, gas, height uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := &r.sizing
	entries := len(objects)
	code := fmt.Sprintf("%s/%d", res.Codespace, res.Code)
	switch classify(res) {
	case refusalOutOfGas:
		factor = max(factor, 1)
		if entries == 1 && r.atGasCeiling(factor, gas) {
			// No more gas to give it and nothing to split: sending it again every block would
			// only pay for the same refusal.
			r.giveUpOutOfGasLocked(objects[0], gas)
			return
		}
		if factor < max(s.gasFactor, 1) {
			// Sent before the factor was raised: the raise already covers it.
			r.log.Warn("record transaction out of gas at a gas factor already raised; it goes again with the current one",
				"entries", entries, "tx_gas_factor", factor, "gas_factor", max(s.gasFactor, 1))
			return
		}
		// The gas follows the entries and bytes of a batch, so a smaller batch alone does not get
		// more gas per byte: halving helps only once the gas cannot grow.
		if r.atGasCeiling(factor, gas) && entries > 1 {
			r.shrinkLocked(entries)
		}
		s.gasFactor, s.gasWins = min(factor*2, maxGasFactor), 0
		r.log.Error("record transaction out of gas; it goes again with more gas (raise dispatch.record_gas_per_byte)",
			"entries", entries, "max_entries", s.maxEntries, "gas_factor", s.gasFactor)
	case refusalFatal:
		why := code + ": " + res.RawLog
		if res.Code == codeInsufficientFee {
			why += " (with a chain minimum gas price, set chain.gas_price so the fee follows the gas)"
		}
		r.stopLocked(height, why)
	default:
		r.repeatedLocked(code, res.RawLog, entries, height)
	}
}

// giveUpOutOfGasLocked stops sending the entry objectID, out of gas alone at the highest gas, and
// logs it once. Caller holds r.mu.
func (r *Recorder) giveUpOutOfGasLocked(objectID string, gas uint64) {
	e := r.entries[objectID]
	if e == nil || r.outOfGas[objectID] {
		return
	}
	r.outOfGas[objectID] = true
	r.log.Error("dispatch entry out of gas at the highest record gas; it is not sent again and is rejected as late at its deadline (raise dispatch.record_gas_per_byte or record_gas_max and restart)",
		"session_id", e.SessionID, "order_sequence", e.Sequence, "object_id", objectID, "gas", gas, "deadline", r.deadlineLocked(e))
}

// unattributable takes an executed record transaction of entries entries whose results could not
// be attributed (batch_digest or object_id): a refusal of its own kind, so results that keep
// failing halve the batch and then stop the records instead of sending every entry again each
// block.
func (r *Recorder) unattributable(entries int, height uint64, why string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.repeatedLocked("results/unattributable", why, entries, height)
}

// repeatedLocked counts one unexplained refusal with code: sameRefusalLimit in a row halve the
// batch, or stop the records once a batch holds one entry. Caller holds r.mu.
func (r *Recorder) repeatedLocked(code, detail string, entries int, height uint64) {
	s := &r.sizing
	if s.streakCode != code {
		s.streak, s.streakCode = 0, code
	}
	s.streak++
	if s.streak < sameRefusalLimit {
		return
	}
	s.streak = 0
	if entries > 1 {
		r.shrinkLocked(entries)
		r.log.Error("record transactions refused the same way repeatedly; smaller batches follow", "code", code, "max_entries", s.maxEntries)
		return
	}
	r.stopLocked(height, code+" on single entries: "+detail)
}

func (r *Recorder) shrinkLocked(entries int) {
	r.sizing.maxEntries = uint32(max(entries/2, 1))
}

func (r *Recorder) stopLocked(height uint64, why string) {
	r.sizing.stoppedUntil, r.sizing.stopReason = height+fatalRetryBlocks, why
	r.log.Error("dispatch records stopped: the chain refuses this Builder's record transactions", "reason", why,
		"retry_height", r.sizing.stoppedUntil)
}

// succeeded takes the executed record transaction hash: the streak ends and a lowered entry cap
// comes back by halves; the gas factor is halved once gasStepDownSuccesses transactions sent with
// it succeeded in a row (one sent with another factor says nothing about the current one). A
// transaction counts once, whether its result or a dispatch_recorded event of an entry it carries
// comes first.
func (r *Recorder) succeeded(hash string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.succeededLocked(hash)
}

// succeededLocked is succeeded with r.mu held.
func (r *Recorder) succeededLocked(hash string) {
	tx := r.txs[hash]
	if tx != nil {
		if tx.succeeded {
			return
		}
		tx.succeeded = true
	}
	s := &r.sizing
	s.streak, s.streakCode = 0, ""
	if s.maxEntries != 0 {
		if s.maxEntries *= 2; s.maxEntries >= r.params.Load().MaxEntries {
			s.maxEntries = 0
		}
	}
	if s.gasFactor > 1 && tx != nil && max(tx.GasFactor, 1) == s.gasFactor {
		if s.gasWins++; s.gasWins >= gasStepDownSuccesses {
			s.gasFactor, s.gasWins = s.gasFactor/2, 0
		}
	}
}

// limits returns the entry cap and gas factor records go out with now.
func (r *Recorder) limits(maxEntries uint32) (uint32, uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sizing.maxEntries != 0 && r.sizing.maxEntries < maxEntries {
		maxEntries = r.sizing.maxEntries
	}
	return maxEntries, max(r.sizing.gasFactor, 1)
}

// stopped reports the height records resume at while a fatal refusal stops them.
func (r *Recorder) stopped(height uint64) (uint64, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if height >= r.sizing.stoppedUntil {
		r.sizing.stoppedUntil = 0
		return 0, ""
	}
	return r.sizing.stoppedUntil, r.sizing.stopReason
}

// resumeOnKeyEvent ends a stop when this Builder's service key changes, is revoked or gets a
// replacement registered: the refusal may have been about it.
func (r *Recorder) resumeOnKeyEvent(ev chaincli.ChainEvent) {
	var operator string
	switch t := ev.Typed.(type) {
	case chaincli.ServiceKeyRotated:
		operator = t.Operator
	case chaincli.ServiceKeyRevoked:
		operator = t.Operator
	case chaincli.ServiceKeyRotationRegistered:
		operator = t.Operator
	default:
		return
	}
	if operator != r.cfg.Builder {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sizing.stoppedUntil != 0 {
		r.sizing.stoppedUntil = 0
		r.log.Info("dispatch records resume after a service key event of this Builder")
	}
}
