package handraise

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/kv"
)

// Keys of kv.NSHandraise.
const (
	currentPrefix    = "current/"
	watermarkPrefix  = "watermark/"
	rttPrefix        = "rtt/"
	suspensionPrefix = "suspension/"
	thresholdPrefix  = "rtt_threshold/"
	latestRootKey    = "latest_root"
)

func currentKey(operator string) string    { return currentPrefix + operator }
func watermarkKey(operator string) string  { return watermarkPrefix + operator }
func rttKey(operator string) string        { return rttPrefix + operator }
func suspensionKey(operator string) string { return suspensionPrefix + operator }

func encodeOrder(o order) []byte { return []byte(fmt.Sprintf("%d/%d", o.issued, o.nonce)) }

func decodeOrder(value []byte) (order, error) {
	issued, nonce, ok := strings.Cut(string(value), "/")
	if !ok {
		return order{}, fmt.Errorf("malformed handraise watermark %q", value)
	}
	var o order
	var err error
	if o.issued, err = strconv.ParseUint(issued, 10, 64); err != nil {
		return order{}, err
	}
	if o.nonce, err = strconv.ParseUint(nonce, 10, 64); err != nil {
		return order{}, err
	}
	return o, nil
}

func nsCurrentKey(operator string) (kv.Namespace, string) {
	return kv.NSHandraise, currentKey(operator)
}

// rootKey orders kv.NSHandraiseRoot by (root_height, root_version).
func rootKey(height, version uint64) string { return fmt.Sprintf("%020d/%020d", height, version) }

func rootKeyHeight(key string) (uint64, error) {
	height, _, ok := strings.Cut(key, "/")
	if !ok {
		return 0, fmt.Errorf("malformed handraise root key %q", key)
	}
	return strconv.ParseUint(height, 10, 64)
}

// currentRecord is a held handraise: its bytes as hashed and when it was received.
type currentRecord struct {
	Handraise      []byte `json:"handraise"`
	ReceivedUnixMs int64  `json:"received_unix_ms"`
}

// rootRecord is an issued root: the signed root and every leaf exactly as sent.
type rootRecord struct {
	Digest string   `json:"digest"`
	Root   []byte   `json:"root"`
	Leaves [][]byte `json:"leaves"`
}

type thresholdRecord struct {
	ThresholdMs uint64 `json:"threshold_ms"`
	SinceUnixMs int64  `json:"since_unix_ms"`
}

func (r *Registry) persistCurrent(operator string, h *held) error {
	raw, err := json.Marshal(currentRecord{Handraise: h.raw, ReceivedUnixMs: h.receivedAt.UnixMilli()})
	if err != nil {
		return fmt.Errorf("%w: encode handraise record: %w", ErrStorage, err)
	}
	// The watermark has its own key: expiry deletes the current handraise, never the watermark.
	if err := r.opts.Store.WriteBatch(
		kv.WriteOp{NS: kv.NSHandraise, Key: currentKey(operator), Val: raw},
		kv.WriteOp{NS: kv.NSHandraise, Key: watermarkKey(operator), Val: encodeOrder(orderOf(h.msg))},
	); err != nil {
		return fmt.Errorf("%w: %w", ErrStorage, err)
	}
	return nil
}

func (r *Registry) persistRTT(operator string, rttMs uint64) error {
	return r.opts.Store.Set(kv.NSHandraise, rttKey(operator), []byte(strconv.FormatUint(rttMs, 10)))
}

func (r *Registry) persistSuspension(operator string, until uint64) error {
	if err := r.opts.Store.Set(kv.NSHandraise, suspensionKey(operator), []byte(strconv.FormatUint(until, 10))); err != nil {
		return fmt.Errorf("store reject-rate suspension: %w", err)
	}
	return nil
}

// deleteKeys removes kv.NSHandraise entries that expired; a failure is only logged, the entry
// expires again on the next recovery.
func (r *Registry) deleteKeys(keys []string) {
	if len(keys) == 0 {
		return
	}
	ops := make([]kv.WriteOp, len(keys))
	for i, key := range keys {
		ops[i] = kv.WriteOp{NS: kv.NSHandraise, Key: key, Delete: true}
	}
	if err := r.opts.Store.WriteBatch(ops...); err != nil {
		r.log.Warn("delete expired handraise state", "error", err)
	}
}

// persistRoot stores an issued root, its digest index and the latest pointer in one batch. The
// stored bytes are the ones sent; a root is never signed twice.
func (r *Registry) persistRoot(issued *IssuedRoot, raw []byte) error {
	record := rootRecord{Digest: hex.EncodeToString(issued.Digest[:]), Root: raw, Leaves: make([][]byte, len(issued.Leaves))}
	for i, leaf := range issued.Leaves {
		b, err := proto.MarshalOptions{Deterministic: true}.Marshal(leaf)
		if err != nil {
			return fmt.Errorf("encode handraise root leaf: %w", err)
		}
		record.Leaves[i] = b
	}
	value, err := json.Marshal(record)
	if err != nil {
		return err
	}
	key := rootKey(issued.Root.GetRootHeight(), issued.Root.GetRootVersion())
	if err := r.opts.Store.WriteBatch(
		kv.WriteOp{NS: kv.NSHandraiseRoot, Key: key, Val: value},
		kv.WriteOp{NS: kv.NSHandraiseRootDigest, Key: record.Digest, Val: []byte(key)},
		kv.WriteOp{NS: kv.NSHandraise, Key: latestRootKey, Val: []byte(key)},
	); err != nil {
		return fmt.Errorf("store handraise root: %w", err)
	}
	return nil
}

func (r *Registry) loadRootByDigest(digest [32]byte) (*IssuedRoot, bool, error) {
	key, found, err := r.opts.Store.GetWithError(kv.NSHandraiseRootDigest, hex.EncodeToString(digest[:]))
	if err != nil || !found {
		return nil, false, err
	}
	issued, err := r.loadRoot(string(key))
	if err != nil {
		return nil, false, err
	}
	return issued, true, nil
}

// loadRoot reads a stored root and checks that its leaves reproduce its root, leaf count and digest.
func (r *Registry) loadRoot(key string) (*IssuedRoot, error) {
	value, found, err := r.opts.Store.GetWithError(kv.NSHandraiseRoot, key)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("handraise root %s is missing", key)
	}
	var record rootRecord
	if err := json.Unmarshal(value, &record); err != nil {
		return nil, fmt.Errorf("decode handraise root %s: %w", key, err)
	}
	issued := &IssuedRoot{Root: &taskv1.SignedHandraiseRootV1{}}
	if err := proto.Unmarshal(record.Root, issued.Root); err != nil {
		return nil, fmt.Errorf("decode handraise root %s: %w", key, err)
	}
	for _, b := range record.Leaves {
		leaf := &taskv1.HandraiseRootLeafV1{}
		if err := proto.Unmarshal(b, leaf); err != nil {
			return nil, fmt.Errorf("decode handraise root %s leaf: %w", key, err)
		}
		digest, err := LeafDigest(leaf)
		if err != nil {
			return nil, fmt.Errorf("handraise root %s leaf: %w", key, err)
		}
		issued.Leaves = append(issued.Leaves, leaf)
		issued.leafDigests = append(issued.leafDigests, digest)
	}
	digest, err := dispatch.SigningDigest(rootName, record.Root)
	if err != nil {
		return nil, fmt.Errorf("handraise root %s: %w", key, err)
	}
	issued.Digest = digest
	want := dispatch.HandraiseRoot(issued.leafDigests)
	if hex.EncodeToString(digest[:]) != record.Digest || int(issued.Root.GetLeafCount()) != len(issued.Leaves) ||
		!bytes.Equal(issued.Root.GetRoot(), want[:]) || rootKey(issued.Root.GetRootHeight(), issued.Root.GetRootVersion()) != key {
		return nil, fmt.Errorf("handraise root %s does not match its stored leaves", key)
	}
	return issued, nil
}

// PruneRootsBelow deletes issued roots with root_height below height, except the latest root and
// every root keep holds, and returns how many it deleted. keep holds the roots bound by retained
// dispatch evidence (dispatchevidence.Store.ReferencesRoot): a challenge or GetDispatchRoster
// still needs them. height must stay below every root an order still dispatching may bind.
func (r *Registry) PruneRootsBelow(height uint64, keep func(digest [32]byte) bool) (int, error) {
	r.issueMu.Lock()
	defer r.issueMu.Unlock()
	var latestKey string
	if latest, ok := r.LatestRoot(); ok {
		latestKey = rootKey(latest.Root.GetRootHeight(), latest.Root.GetRootVersion())
	}
	var ops []kv.WriteOp
	var scanErr error
	err := r.opts.Store.Scan(kv.NSHandraiseRoot, func(key string, value []byte) bool {
		h, err := rootKeyHeight(key)
		if err != nil {
			scanErr = err
			return false
		}
		if h >= height {
			return false
		}
		if key == latestKey {
			return true
		}
		var record rootRecord
		if err := json.Unmarshal(value, &record); err != nil {
			scanErr = fmt.Errorf("decode handraise root %s: %w", key, err)
			return false
		}
		digest, err := hex.DecodeString(record.Digest)
		if err != nil || len(digest) != 32 {
			scanErr = fmt.Errorf("handraise root %s has a malformed digest", key)
			return false
		}
		if keep([32]byte(digest)) {
			return true
		}
		ops = append(ops,
			kv.WriteOp{NS: kv.NSHandraiseRoot, Key: key, Delete: true},
			kv.WriteOp{NS: kv.NSHandraiseRootDigest, Key: record.Digest, Delete: true})
		return true
	})
	if err == nil {
		err = scanErr
	}
	if err != nil {
		return 0, fmt.Errorf("scan handraise roots: %w", err)
	}
	if len(ops) == 0 {
		return 0, nil
	}
	if err := r.opts.Store.WriteBatch(ops...); err != nil {
		return 0, fmt.Errorf("prune handraise roots: %w", err)
	}
	return len(ops) / 2, nil
}

// RTTThresholdHistory returns every RTT admission threshold this Builder has used, oldest first.
// It is kept in memory from the start on; the error is always nil.
func (r *Registry) RTTThresholdHistory() ([]RTTThresholdChange, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]RTTThresholdChange(nil), r.history...), nil
}

// recover loads current handraises, watermarks, measured RTTs, suspensions, the threshold history
// and the latest root, and
// records the configured RTT threshold when it differs from the last one used.
func (r *Registry) recover() error {
	var thresholds []RTTThresholdChange
	var latestKey string
	var loadErr error
	err := r.opts.Store.Scan(kv.NSHandraise, func(key string, value []byte) bool {
		switch {
		case strings.HasPrefix(key, currentPrefix):
			loadErr = r.recoverCurrent(strings.TrimPrefix(key, currentPrefix), value)
		case strings.HasPrefix(key, watermarkPrefix):
			var mark order
			mark, loadErr = decodeOrder(value)
			r.watermark[strings.TrimPrefix(key, watermarkPrefix)] = mark
		case strings.HasPrefix(key, rttPrefix):
			var rtt uint64
			rtt, loadErr = strconv.ParseUint(string(value), 10, 64)
			r.rtt[strings.TrimPrefix(key, rttPrefix)] = rtt
		case strings.HasPrefix(key, suspensionPrefix):
			var until uint64
			until, loadErr = strconv.ParseUint(string(value), 10, 64)
			r.suspended[strings.TrimPrefix(key, suspensionPrefix)] = until
		case strings.HasPrefix(key, thresholdPrefix):
			var record thresholdRecord
			loadErr = json.Unmarshal(value, &record)
			thresholds = append(thresholds, RTTThresholdChange{ThresholdMs: record.ThresholdMs, Since: time.UnixMilli(record.SinceUnixMs)})
		case key == latestRootKey:
			latestKey = string(value)
		}
		if loadErr != nil {
			loadErr = fmt.Errorf("%s: %w", key, loadErr)
		}
		return loadErr == nil
	})
	if err == nil {
		err = loadErr
	}
	if err != nil {
		return err
	}
	// A current handraise stored before watermarks had their own key still sets the watermark.
	for operator, h := range r.current {
		if mark, ok := r.watermark[operator]; !ok || orderOf(h.msg).after(mark) {
			r.watermark[operator] = orderOf(h.msg)
		}
	}
	if latestKey != "" {
		if r.latest, err = r.loadRoot(latestKey); err != nil {
			return err
		}
	}
	configured := r.opts.Config.BuilderRTTAdmitMs
	if n := len(thresholds); n > 0 && thresholds[n-1].ThresholdMs == configured {
		r.threshold, r.history = thresholds[n-1], thresholds
		return nil
	}
	r.threshold = RTTThresholdChange{ThresholdMs: configured, Since: time.UnixMilli(r.now().UnixMilli())}
	value, err := json.Marshal(thresholdRecord{ThresholdMs: configured, SinceUnixMs: r.threshold.Since.UnixMilli()})
	if err != nil {
		return err
	}
	if err := r.opts.Store.Set(kv.NSHandraise, fmt.Sprintf("%s%020d", thresholdPrefix, r.threshold.Since.UnixMilli()), value); err != nil {
		return err
	}
	r.history = append(thresholds, r.threshold)
	return nil
}

func (r *Registry) recoverCurrent(operator string, value []byte) error {
	var record currentRecord
	if err := json.Unmarshal(value, &record); err != nil {
		return err
	}
	msg := &taskv1.StandingHandraiseV1{}
	if err := proto.Unmarshal(record.Handraise, msg); err != nil {
		return err
	}
	digest, err := dispatch.SigningDigest(standingName, record.Handraise)
	if err != nil {
		return err
	}
	if msg.GetMember().GetOperatorAddress() != operator {
		return fmt.Errorf("stored handraise belongs to another operator")
	}
	r.current[operator] = &held{msg: msg, raw: record.Handraise, digest: digest, receivedAt: time.UnixMilli(record.ReceivedUnixMs)}
	return nil
}
