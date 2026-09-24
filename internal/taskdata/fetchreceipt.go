package taskdata

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/kv"
)

// fetchReceiptLimit caps the receipts kept per (task, requester). Cortex fetches INPUT in 1 MiB
// signed ranges with a 64 MiB default ceiling, so a normal download needs at most 64; the rest
// is room for retries. Past the cap downloads are still served and only counted.
const fetchReceiptLimit = 256

// FetchReceipt is what the Builder keeps of one FetchTaskData request by a selected Worker or
// Verifier, so that it can later show what that node downloaded: a Worker that took the INPUT
// and then left, or a Verifier that downloaded the data and still reported it unavailable
// (MsgReportDataUnavailable). No protocol message consumes it yet; it is read only through
// Service.FetchReceipts.
//
// Request and Range are what the requester signed, byte for byte: with them anyone can rebuild
// body_digest (TRUEOPEN_TASK_DATA_FETCH_BODY_V1 over the object ref and range) and the
// request digest, and check Signature against RequesterServicePubKey. The key is stored because
// service keys rotate and V1 offers no historical service key query.
type FetchReceipt struct {
	Request RequestAuth `json:"request"`
	// Range is the signed byte range; nil is a signed whole-object read.
	Range *ByteRange `json:"range,omitempty"`
	// RequesterServicePubKey is the Cortex service key the signature verified against, the one
	// bound to Request.ServiceAuthorizationNonce at the time of the request.
	RequesterServicePubKey []byte `json:"requester_service_pubkey"`
	// Observed is builder-observed, not signed by the requester.
	Observed FetchObserved `json:"builder_observed"`
}

// FetchObserved is the Builder's own account of serving a request. The requester did not sign
// any of it, so it supports the signed request and does not replace it.
type FetchObserved struct {
	AuthorizedHeight uint64    `json:"authorized_height"`
	Served           ByteRange `json:"served_range"`
	// BytesServed counts the bytes read from storage for this response; delivery to the
	// requester is not confirmed by anything.
	BytesServed uint64 `json:"bytes_served"`
	// Completed is true when the whole served range was read out for the response.
	Completed            bool  `json:"completed"`
	RecordedAtUnixMillis int64 `json:"recorded_at_unix_millis"`
}

// FetchReceiptSet is every receipt kept for one requester of one task.
type FetchReceiptSet struct {
	Requester string
	Receipts  []FetchReceipt
	// Dropped counts requests served after the cap was reached and not kept.
	Dropped uint64
}

// fetchReceiptIndex lists the receipt keys of one (session, task, requester) in arrival order.
type fetchReceiptIndex struct {
	Keys    []string `json:"keys"`
	Dropped uint64   `json:"dropped,omitempty"`
}

// recordsFetch is the recording scope: the selected Worker's INPUT downloads and every download
// by a selected Verifier of any round, read from the same VerifierRounds the authorizer uses.
// User downloads of OUTPUT are not kept.
func recordsFetch(task chaincli.OnChainTask, request RequestAuth) bool {
	if request.RequesterKind != RequesterKindCortexService {
		return false
	}
	if request.Key.Kind == ObjectKindInput && task.Assignment.SelectedWorkerOperatorAddress == request.RequesterAddress {
		return true
	}
	for _, round := range task.VerifierRounds {
		if slices.Contains(round.Verifiers, request.RequesterAddress) {
			return true
		}
	}
	return false
}

func fetchReceiptTaskPrefix(sessionID, taskID string) string {
	return sessionID + "|" + taskID + "|"
}

func fetchReceiptIndexKey(sessionID, taskID, requester string) string {
	return fetchReceiptTaskPrefix(sessionID, taskID) + requester
}

// recordFetchReceipt keeps one receipt before any byte is served. It returns the receipt key,
// or "" when the cap was reached and the request was only counted. A write failure is returned:
// a Builder that cannot keep the receipt does not serve the data.
func (s *Store) recordFetchReceipt(receipt FetchReceipt) (string, error) {
	digest, err := CortexTaskDataRequestDigest(receipt.Request)
	if err != nil {
		return "", err
	}
	request := receipt.Request
	indexKey := fetchReceiptIndexKey(request.Key.SessionID, request.Key.TaskID, request.RequesterAddress)
	key := indexKey + "|" + hex.EncodeToString(digest[:])

	s.maintenance.RLock()
	defer s.maintenance.RUnlock()
	s.fetchReceiptMu.Lock()
	defer s.fetchReceiptMu.Unlock()
	index, err := s.fetchReceiptIndex(indexKey)
	if err != nil {
		return "", err
	}
	if slices.Contains(index.Keys, key) {
		return key, nil
	}
	if len(index.Keys) >= fetchReceiptLimit {
		index.Dropped++
		raw, err := json.Marshal(index)
		if err == nil {
			err = s.backend.Set(kv.NSTaskDataFetchReceiptIndex, indexKey, raw)
		}
		if err != nil {
			return "", fmt.Errorf("%w: persist fetch receipt index: %v", ErrStorage, err)
		}
		return "", nil
	}
	index.Keys = append(index.Keys, key)
	indexRaw, err := json.Marshal(index)
	if err != nil {
		return "", fmt.Errorf("%w: encode fetch receipt index: %v", ErrStorage, err)
	}
	receiptRaw, err := json.Marshal(receipt)
	if err != nil {
		return "", fmt.Errorf("%w: encode fetch receipt: %v", ErrStorage, err)
	}
	if err := s.backend.WriteBatch(
		kv.WriteOp{NS: kv.NSTaskDataFetchReceipt, Key: key, Val: receiptRaw},
		kv.WriteOp{NS: kv.NSTaskDataFetchReceiptIndex, Key: indexKey, Val: indexRaw},
	); err != nil {
		return "", fmt.Errorf("%w: persist fetch receipt: %v", ErrStorage, err)
	}
	return key, nil
}

// completeFetchReceipt writes the served byte count once the response ends. A receipt already
// removed by cleanup is left alone.
func (s *Store) completeFetchReceipt(key string, bytesServed uint64, completed bool) error {
	s.maintenance.RLock()
	defer s.maintenance.RUnlock()
	s.fetchReceiptMu.Lock()
	defer s.fetchReceiptMu.Unlock()
	raw, found, err := s.backend.GetWithError(kv.NSTaskDataFetchReceipt, key)
	if err != nil {
		return fmt.Errorf("%w: read fetch receipt: %v", ErrStorage, err)
	}
	if !found {
		return nil
	}
	var receipt FetchReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return fmt.Errorf("%w: decode fetch receipt: %v", ErrStorage, err)
	}
	receipt.Observed.BytesServed, receipt.Observed.Completed = bytesServed, completed
	if raw, err = json.Marshal(receipt); err == nil {
		err = s.backend.Set(kv.NSTaskDataFetchReceipt, key, raw)
	}
	if err != nil {
		return fmt.Errorf("%w: persist fetch receipt: %v", ErrStorage, err)
	}
	return nil
}

// FetchReceipts returns the receipts kept for one task, grouped by requester.
func (s *Store) FetchReceipts(_ context.Context, sessionID, taskID string) ([]FetchReceiptSet, error) {
	s.maintenance.RLock()
	defer s.maintenance.RUnlock()
	s.fetchReceiptMu.Lock()
	defer s.fetchReceiptMu.Unlock()
	prefix := fetchReceiptTaskPrefix(sessionID, taskID)
	var sets []FetchReceiptSet
	var scanErr error
	if err := s.backend.Scan(kv.NSTaskDataFetchReceiptIndex, func(indexKey string, raw []byte) bool {
		if !strings.HasPrefix(indexKey, prefix) {
			return true
		}
		var index fetchReceiptIndex
		if err := json.Unmarshal(raw, &index); err != nil {
			scanErr = fmt.Errorf("%w: decode fetch receipt index: %v", ErrStorage, err)
			return false
		}
		set := FetchReceiptSet{Requester: strings.TrimPrefix(indexKey, prefix), Dropped: index.Dropped}
		for _, key := range index.Keys {
			receiptRaw, found, err := s.backend.GetWithError(kv.NSTaskDataFetchReceipt, key)
			if err != nil {
				scanErr = fmt.Errorf("%w: read fetch receipt: %v", ErrStorage, err)
				return false
			}
			if !found {
				continue
			}
			var receipt FetchReceipt
			if err := json.Unmarshal(receiptRaw, &receipt); err != nil {
				scanErr = fmt.Errorf("%w: decode fetch receipt: %v", ErrStorage, err)
				return false
			}
			set.Receipts = append(set.Receipts, receipt)
		}
		sets = append(sets, set)
		return true
	}); err != nil {
		return nil, fmt.Errorf("%w: scan fetch receipt index: %v", ErrStorage, err)
	}
	if scanErr != nil {
		return nil, scanErr
	}
	return sets, nil
}

// pruneFetchReceiptsLocked runs at the end of a retention sweep, under the maintenance lock. The
// receipts of a task live exactly as long as its INPUT: once no INPUT of that task is left in
// the store, whether it was deleted in this sweep or an earlier one, every receipt of the task
// is removed.
func (s *Store) pruneFetchReceiptsLocked(records map[string]metadataRecord) error {
	withInput := make(map[string]struct{})
	for _, record := range records {
		if record.Metadata.Key.Kind == ObjectKindInput {
			withInput[fetchReceiptTaskPrefix(record.Metadata.Key.SessionID, record.Metadata.Key.TaskID)] = struct{}{}
		}
	}
	type staleIndex struct {
		key  string
		keys []string
	}
	var stale []staleIndex
	var scanErr error
	if err := s.backend.Scan(kv.NSTaskDataFetchReceiptIndex, func(indexKey string, raw []byte) bool {
		parts := strings.SplitN(indexKey, "|", 3)
		if len(parts) != 3 {
			scanErr = fmt.Errorf("%w: fetch receipt index key", ErrStorage)
			return false
		}
		if _, ok := withInput[fetchReceiptTaskPrefix(parts[0], parts[1])]; ok {
			return true
		}
		var index fetchReceiptIndex
		if err := json.Unmarshal(raw, &index); err != nil {
			scanErr = fmt.Errorf("%w: decode fetch receipt index: %v", ErrStorage, err)
			return false
		}
		stale = append(stale, staleIndex{key: indexKey, keys: index.Keys})
		return true
	}); err != nil {
		return fmt.Errorf("%w: scan fetch receipt index: %v", ErrStorage, err)
	}
	if scanErr != nil {
		return scanErr
	}
	for _, index := range stale {
		ops := make([]kv.WriteOp, 0, len(index.keys)+1)
		for _, key := range index.keys {
			ops = append(ops, kv.WriteOp{NS: kv.NSTaskDataFetchReceipt, Key: key, Delete: true})
		}
		ops = append(ops, kv.WriteOp{NS: kv.NSTaskDataFetchReceiptIndex, Key: index.key, Delete: true})
		if err := s.backend.WriteBatch(ops...); err != nil {
			return fmt.Errorf("%w: delete fetch receipts: %v", ErrStorage, err)
		}
	}
	return nil
}

func (s *Store) fetchReceiptIndex(indexKey string) (fetchReceiptIndex, error) {
	raw, found, err := s.backend.GetWithError(kv.NSTaskDataFetchReceiptIndex, indexKey)
	if err != nil {
		return fetchReceiptIndex{}, fmt.Errorf("%w: read fetch receipt index: %v", ErrStorage, err)
	}
	var index fetchReceiptIndex
	if found {
		if err := json.Unmarshal(raw, &index); err != nil {
			return fetchReceiptIndex{}, fmt.Errorf("%w: decode fetch receipt index: %v", ErrStorage, err)
		}
	}
	return index, nil
}

// receiptReader counts what is read out for a recorded fetch and writes the count into the
// receipt when the response closes. That update is best effort: the signed request was kept
// before the first byte, and losing the byte count only loses builder-observed detail.
type receiptReader struct {
	io.ReadCloser
	store  *Store
	key    string
	length uint64
	served uint64
	once   sync.Once
}

func (r *receiptReader) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	r.served += uint64(n)
	return n, err
}

func (r *receiptReader) Close() error {
	err := r.ReadCloser.Close()
	r.once.Do(func() {
		if updateErr := r.store.completeFetchReceipt(r.key, r.served, r.served == r.length); updateErr != nil && r.store.log != nil {
			r.store.log.Warn("fetch receipt byte count not recorded", "receipt", r.key, "err", updateErr)
		}
	})
	return err
}

func newFetchReceipt(grant FetchGrant, request RequestAuth, byteRange *ByteRange, served ByteRange) FetchReceipt {
	receipt := FetchReceipt{
		Request:                cloneRequestAuth(request),
		RequesterServicePubKey: bytes.Clone(grant.RequesterKey),
		Observed: FetchObserved{
			AuthorizedHeight: grant.Height, Served: served, RecordedAtUnixMillis: time.Now().UnixMilli(),
		},
	}
	if byteRange != nil {
		signed := *byteRange
		receipt.Range = &signed
	}
	return receipt
}

func cloneRequestAuth(request RequestAuth) RequestAuth {
	request.RequestNonce = bytes.Clone(request.RequestNonce)
	request.Signature = bytes.Clone(request.Signature)
	return request
}
