package taskdata

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/signer"
)

type fetchReceiptFixture struct {
	*authorizerFixture
	store   *Store
	service *Service
	input   Metadata
	output  Metadata
	body    []byte
}

func newFetchReceiptFixture(t *testing.T, backend kv.Store) *fetchReceiptFixture {
	t.Helper()
	fx := newAuthorizerFixture(t)
	var store *Store
	if backend == nil {
		store, _, _ = newTestStore(t, testStoreConfig())
	} else {
		created, err := NewStore(slog.New(slog.NewTextHandler(io.Discard, nil)), filepath.Join(t.TempDir(), "objects"), backend, testStoreConfig())
		if err != nil {
			t.Fatal(err)
		}
		store = created
	}
	service, err := NewService(store, fx.authorizer)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("abcdefgh")
	ready := func(header UploadHeader) Metadata {
		t.Helper()
		metadata := prepareObject(t, store, header, body)
		metadata, err := store.MarkReady(context.Background(), metadata.Key)
		if err != nil {
			t.Fatal(err)
		}
		return metadata
	}
	input := ready(testHeader(body))
	outputHeader := testHeader(body)
	outputHeader.Key.Kind = ObjectKindOutput
	outputHeader.Uploader = fx.worker.Address()
	output := ready(outputHeader)
	return &fetchReceiptFixture{authorizerFixture: fx, store: store, service: service, input: input, output: output, body: body}
}

func (f *fetchReceiptFixture) fetch(t *testing.T, caller signer.Signer, key ObjectKey, byteRange *ByteRange, nonce byte, readAll bool) error {
	t.Helper()
	request := f.fixtureFetch(t, caller, key, byteRange, nonce, 110)
	reader, _, _, err := f.service.OpenFetch(context.Background(), request, byteRange)
	if err != nil {
		return err
	}
	if readAll {
		if _, err := io.ReadAll(reader); err != nil {
			t.Fatal(err)
		}
	} else if _, err := reader.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	return reader.Close()
}

func (f *fetchReceiptFixture) receipts(t *testing.T) map[string]FetchReceiptSet {
	t.Helper()
	sets, err := f.service.FetchReceipts(context.Background(), testSessionID, testTaskID)
	if err != nil {
		t.Fatal(err)
	}
	byRequester := map[string]FetchReceiptSet{}
	for _, set := range sets {
		byRequester[set.Requester] = set
	}
	return byRequester
}

// The kept receipt is enough for a third party: it rebuilds body_digest from the signed ref and
// range, rebuilds the request digest, and verifies the signature against the stored key.
func TestFetchReceiptKeepsTheSignedWorkerInputRequest(t *testing.T) {
	f := newFetchReceiptFixture(t, nil)
	byteRange := &ByteRange{Offset: 2, Length: 4}
	if err := f.fetch(t, f.worker, f.input.Key, byteRange, 1, true); err != nil {
		t.Fatal(err)
	}
	set, ok := f.receipts(t)[f.worker.Address()]
	if !ok || len(set.Receipts) != 1 || set.Dropped != 0 {
		t.Fatalf("worker receipts = %+v", set)
	}
	receipt := set.Receipts[0]
	body, err := TaskDataFetchBodyDigest(receipt.Request.Key, receipt.Range)
	if err != nil || receipt.Request.BodyDigest != hex.EncodeToString(body[:]) {
		t.Fatalf("body_digest does not rebuild from the kept ref and range: %v", err)
	}
	digest, err := CortexTaskDataRequestDigest(receipt.Request)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(receipt.RequesterServicePubKey, f.workerService.PubKeyCompressed()) ||
		!signer.VerifyDigestSig(receipt.RequesterServicePubKey, digest[:], receipt.Request.Signature) {
		t.Fatal("kept signature does not verify against the kept service key")
	}
	observed := receipt.Observed
	if observed.AuthorizedHeight != f.authority.height || observed.Served != *byteRange ||
		observed.BytesServed != 4 || !observed.Completed || observed.RecordedAtUnixMillis == 0 {
		t.Fatalf("builder-observed = %+v", observed)
	}

	// A response closed before the range was read out is kept as not completed.
	if err := f.fetch(t, f.worker, f.input.Key, nil, 2, false); err != nil {
		t.Fatal(err)
	}
	set = f.receipts(t)[f.worker.Address()]
	if len(set.Receipts) != 2 || set.Receipts[1].Range != nil ||
		set.Receipts[1].Observed.Completed || set.Receipts[1].Observed.BytesServed == 0 {
		t.Fatalf("partial whole-object receipt = %+v", set.Receipts[1])
	}
}

// Scope: the selected Verifier's downloads are kept, the User's OUTPUT downloads are not.
func TestFetchReceiptScope(t *testing.T) {
	f := newFetchReceiptFixture(t, nil)
	for i, key := range []ObjectKey{f.input.Key, f.output.Key} {
		if err := f.fetch(t, f.verifier, key, nil, byte(10+i), true); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.fetch(t, f.user, f.output.Key, nil, 20, true); err != nil {
		t.Fatal(err)
	}
	receipts := f.receipts(t)
	if set := receipts[f.verifier.Address()]; len(set.Receipts) != 2 ||
		!bytes.Equal(set.Receipts[0].RequesterServicePubKey, f.verifierService.PubKeyCompressed()) {
		t.Fatalf("verifier receipts = %+v", set)
	}
	if len(receipts) != 1 {
		t.Fatalf("only the verifier should have receipts, got %d requesters", len(receipts))
	}
}

// A round-2 Verifier's downloads are kept too: the scope reads every round in VerifierRounds,
// not only the round-1 Verifiers view.
func TestFetchReceiptKeepsRound2VerifierDownloads(t *testing.T) {
	f := newFetchReceiptFixture(t, nil)
	challenger := testSigner(t, 30)
	f.authority.setServiceKey(participantServiceKey(participantTypeCortex, challenger.Address(), challenger))
	f.authority.task.VerifierRounds = append(f.authority.task.VerifierRounds, chaincli.VerifierRound{
		VerifyRound: 2, Verifiers: []string{challenger.Address()}, CommitDeadlineHeight: 300,
	})
	if err := f.fetch(t, challenger, f.input.Key, nil, 40, true); err != nil {
		t.Fatal(err)
	}
	set, ok := f.receipts(t)[challenger.Address()]
	if !ok || len(set.Receipts) != 1 || !bytes.Equal(set.Receipts[0].RequesterServicePubKey, challenger.PubKeyCompressed()) {
		t.Fatalf("round-2 verifier receipts = %+v", set)
	}
}

// Past the cap a download is still served and only counted.
func TestFetchReceiptCapCountsInsteadOfRefusing(t *testing.T) {
	f := newFetchReceiptFixture(t, nil)
	template := f.fixtureFetch(t, f.worker, f.input.Key, nil, 1, 110)
	for i := 0; i < fetchReceiptLimit; i++ {
		request := template
		request.RequestNonce = bytes.Repeat([]byte{0xAA}, 32)
		request.RequestNonce[0], request.RequestNonce[1] = byte(i>>8), byte(i)
		if key, err := f.store.recordFetchReceipt(FetchReceipt{Request: request}); err != nil || key == "" {
			t.Fatalf("receipt %d: key %q, %v", i, key, err)
		}
	}
	if err := f.fetch(t, f.worker, f.input.Key, nil, 2, true); err != nil {
		t.Fatalf("download over the cap must still be served: %v", err)
	}
	set := f.receipts(t)[f.worker.Address()]
	if len(set.Receipts) != fetchReceiptLimit || set.Dropped != 1 {
		t.Fatalf("receipts = %d, dropped = %d", len(set.Receipts), set.Dropped)
	}
}

// failReceiptWrites refuses every batch that writes a fetch receipt.
type failReceiptWrites struct{ kv.Store }

func (s failReceiptWrites) WriteBatch(ops ...kv.WriteOp) error {
	for _, op := range ops {
		if op.NS == kv.NSTaskDataFetchReceipt {
			return errors.New("disk full")
		}
	}
	return s.Store.WriteBatch(ops...)
}

// A Builder that cannot keep the receipt does not serve the data.
func TestFetchReceiptWriteFailureStopsTheFetch(t *testing.T) {
	f := newFetchReceiptFixture(t, failReceiptWrites{kv.NewMemStore()})
	request := f.fixtureFetch(t, f.worker, f.input.Key, nil, 1, 110)
	reader, _, _, err := f.service.OpenFetch(context.Background(), request, nil)
	if reader != nil {
		_ = reader.Close()
		t.Fatal("a reader was returned although the receipt was not kept")
	}
	if !errors.Is(err, ErrStorage) {
		t.Fatalf("error = %v, want ErrStorage", err)
	}
}

// Receipts live exactly as long as the task's INPUT: kept while it stays, removed in the sweep
// that deletes it, and removed as orphans when no INPUT of the task is left.
func TestFetchReceiptsFollowInputRetention(t *testing.T) {
	f := newFetchReceiptFixture(t, nil)
	if err := f.fetch(t, f.worker, f.input.Key, nil, 1, true); err != nil {
		t.Fatal(err)
	}
	// An orphan: receipts of a task this store holds no INPUT for.
	orphan := f.fixtureFetch(t, f.worker, f.input.Key, nil, 3, 110)
	orphan.Key.TaskID = testOtherTaskID
	if _, err := f.store.recordFetchReceipt(FetchReceipt{Request: orphan}); err != nil {
		t.Fatal(err)
	}
	keep := RetentionDecision{Status: RetentionActive}
	resolver := recoveryResolver{retention: map[string]RetentionDecision{
		objectKeyString(f.input.Key): keep, objectKeyString(f.output.Key): keep,
	}}
	if err := f.store.Sweep(context.Background(), 100, resolver); err != nil {
		t.Fatal(err)
	}
	if len(f.receipts(t)) != 1 {
		t.Fatal("receipts of a task whose INPUT is kept were removed")
	}
	orphans, err := f.store.FetchReceipts(context.Background(), testSessionID, testOtherTaskID)
	if err != nil || len(orphans) != 0 {
		t.Fatalf("orphan receipts = %+v, %v", orphans, err)
	}

	resolver.retention[objectKeyString(f.input.Key)] = RetentionDecision{
		Status: RetentionEligibleForCleanup, RetainUntilHeight: 100, Delete: true,
	}
	if err := f.store.Sweep(context.Background(), 100, resolver); err != nil {
		t.Fatal(err)
	}
	if receipts := f.receipts(t); len(receipts) != 0 {
		t.Fatalf("receipts survived their INPUT: %+v", receipts)
	}
	if err := f.store.backend.Scan(kv.NSTaskDataFetchReceipt, func(key string, _ []byte) bool {
		t.Fatalf("receipt row %q left behind", key)
		return false
	}); err != nil {
		t.Fatal(err)
	}
}
