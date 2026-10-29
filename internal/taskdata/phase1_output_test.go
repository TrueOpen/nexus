package taskdata

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/TrueOpen/nexus/internal/attempt"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/mmr"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/signer"
)

// fakeAttempts is the attempt book: the current attempt of each task.
type fakeAttempts struct {
	mu sync.Mutex
	m  map[string]attempt.Attempt
}

func (f *fakeAttempts) Current(taskID string) (attempt.Attempt, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.m[taskID]
	return a, ok
}

func (f *fakeAttempts) set(a attempt.Attempt) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.m == nil {
		f.m = map[string]attempt.Attempt{}
	}
	f.m[a.TaskID] = a
}

func ticketOf(b byte) [32]byte {
	var t [32]byte
	for i := range t {
		t[i] = b
	}
	return t
}

// phase1Fixture is a Builder whose chain does not know the task yet: the Worker's right to the
// task comes only from the attempt book.
type phase1Fixture struct {
	*authorizerFixture
	attempts *fakeAttempts
	store    *Store
	service  *Service
}

func newPhase1Fixture(t *testing.T) *phase1Fixture {
	t.Helper()
	fx := newAuthorizerFixture(t)
	fx.authority.taskErr = chaincli.ErrNotFound
	attempts := &fakeAttempts{}
	fx.authorizer.cfg.Attempts = attempts
	store, _, _ := newTestStore(t, streamStoreConfig())
	service, err := NewService(store, fx.authorizer)
	if err != nil {
		t.Fatal(err)
	}
	service.SetOutputStreamConfig(testStreamConfig())
	return &phase1Fixture{authorizerFixture: fx, attempts: attempts, store: store, service: service}
}

// accept makes ticket the task's current attempt, won by worker, at status.
func (p *phase1Fixture) accept(worker string, ticket [32]byte, status attempt.Status) {
	p.attempts.set(attempt.Attempt{
		SessionID: testSessionID, TaskID: testTaskID, TaskHash: testTaskHash, InputHash: testContent,
		Worker: worker, TicketHash: ticket, Status: status,
	})
}

func outputStreamKey() ObjectKey {
	return ObjectKey{TaskHash: testTaskHash, SessionID: testSessionID, TaskID: testTaskID, Kind: ObjectKindOutput}
}

// open sends a stream header for ticket signed by caller's service key.
func (p *phase1Fixture) open(t *testing.T, caller, callerService signer.Signer, ticket [32]byte, nonce byte) (*OutputStreamSession, OutputStreamProgress, error) {
	t.Helper()
	key := outputStreamKey()
	body, err := OutputStreamBodyDigest(key)
	if err != nil {
		t.Fatal(err)
	}
	request := signedRequestAs(t, caller.Address(), callerService, MethodUploadStream, key, body[:], nonce, 110)
	declaration := OutputStreamHeaderRecord{
		DispatchTicketHash: ticket[:], StreamInstance: 1,
		OutputKeyCommitment: make([]byte, 32), KeyPackageHash: make([]byte, 32),
	}
	digest, err := nodecontract.OutputStreamHeader{
		ChainID: testChainID, TaskHash: mustDecodeHex(t, testTaskHash), DispatchTicketHash: ticket[:], StreamInstance: 1,
		OutputKeyCommitment: declaration.OutputKeyCommitment, KeyPackageHash: declaration.KeyPackageHash,
	}.SigningDigest()
	if err != nil {
		t.Fatal(err)
	}
	declaration.WorkerSignature = signDigestForTest(t, callerService, digest[:])
	return p.service.OpenOutputStream(context.Background(), request,
		OutputStreamHeader{Key: key, TaskHash: testTaskHash, Declaration: declaration})
}

// chunk is chunk seq of ticket, signed by the Worker's service key, cumulative tokens tokens.
func (p *phase1Fixture) chunk(t *testing.T, acc *mmr.Accumulator, ticket [32]byte, seq uint64, text string, tokens uint64) OutputChunk {
	t.Helper()
	root := acc.Append([]byte(text))
	digest, err := nodecontract.OutputChunkSigningDigest(testChainID, mustDecodeHex(t, testTaskHash), ticket[:], seq, root[:])
	if err != nil {
		t.Fatal(err)
	}
	return OutputChunk{
		Seq: seq, Text: []byte(text), MMRRoot: root[:], DispatchTicketHash: ticket[:], CumulativeGeneratedTokens: tokens,
		WorkerSignature: signDigestForTest(t, p.workerService, digest[:]),
	}
}

func (p *phase1Fixture) fin(t *testing.T, acc *mmr.Accumulator, ticket [32]byte, finalSeq uint64) OutputFin {
	t.Helper()
	root := acc.Root()
	digest, err := nodecontract.OutputFinSigningDigest(testChainID, mustDecodeHex(t, testTaskHash), ticket[:], finalSeq, root[:], 1)
	if err != nil {
		t.Fatal(err)
	}
	return OutputFin{
		FinalSeq: finalSeq, OutputMMRRoot: root[:], FinishReason: 1, DispatchTicketHash: ticket[:],
		WorkerSignature: signDigestForTest(t, p.workerService, digest[:]),
	}
}

// Before the chain knows the task, the Worker whose accept this Builder holds streams its output
// for the winner ticket: the header, every chunk and the Fin carry that ticket and its signatures
// verify. Nothing is read from the chain's task.
func TestWinnerStreamsBeforeTheRecord(t *testing.T) {
	p := newPhase1Fixture(t)
	ticket := ticketOf(0x71)
	p.accept(p.worker.Address(), ticket, attempt.Pending)
	session, progress, err := p.open(t, p.worker, p.workerService, ticket, 1)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if progress.Received {
		t.Fatalf("fresh stream progress = %+v", progress)
	}
	acc, _ := mmr.New(nodecontract.DomainOutputMMRV1)
	for i, text := range []string{"hello, ", "wor"} {
		if _, err := session.Append(context.Background(), p.chunk(t, acc, ticket, uint64(i), text, uint64(3*(i+1)))); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if _, err := session.Finish(context.Background(), p.fin(t, acc, ticket, 1)); err != nil {
		t.Fatalf("finish: %v", err)
	}
	frames, err := p.service.OutputFrames(context.Background(), outputStreamKey(), nil)
	if err != nil || len(frames) != 3 || frames[1].Chunk.CumulativeGeneratedTokens != 6 || !bytes.Equal(frames[2].Fin.DispatchTicketHash, ticket[:]) {
		t.Fatalf("frames = %+v, %v", frames, err)
	}
}

// Only the Worker whose accept this Builder holds for the header's ticket may open the stream:
// another Cortex is refused, an older attempt's ticket is stale, and with no attempt at all the
// chain's assignment does not stand in for it. A rejected attempt is stale too.
func TestStreamOpenNeedsTheLiveWinnerTicket(t *testing.T) {
	p := newPhase1Fixture(t)
	ticket := ticketOf(0x71)
	if _, _, err := p.open(t, p.worker, p.workerService, ticket, 1); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("no attempt: %v", err)
	}
	p.authority.taskErr = nil // the chain names the Worker; it no longer decides
	if _, _, err := p.open(t, p.worker, p.workerService, ticket, 2); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("no attempt, chain assignment: %v", err)
	}
	p.accept(p.worker.Address(), ticket, attempt.Pending)
	if _, _, err := p.open(t, p.other, p.other, ticket, 3); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("another Cortex: %v", err)
	}
	if _, _, err := p.open(t, p.worker, p.workerService, ticketOf(0x70), 4); !errors.Is(err, ErrAttemptStale) {
		t.Fatalf("older ticket: %v", err)
	}
	p.accept(p.worker.Address(), ticket, attempt.Rejected)
	if _, _, err := p.open(t, p.worker, p.workerService, ticket, 5); !errors.Is(err, ErrAttemptStale) {
		t.Fatalf("rejected attempt: %v", err)
	}
	p.accept(p.worker.Address(), ticket, attempt.Recorded)
	if _, _, err := p.open(t, p.worker, p.workerService, ticket, 6); err != nil {
		t.Fatalf("recorded attempt: %v", err)
	}
}

// A chunk or Fin whose ticket is not the header's closes the stream; so does any frame after the
// attempt stopped being the task's live one.
func TestFramesMustCarryTheLiveHeaderTicket(t *testing.T) {
	p := newPhase1Fixture(t)
	ticket := ticketOf(0x71)
	p.accept(p.worker.Address(), ticket, attempt.Pending)
	session, _, err := p.open(t, p.worker, p.workerService, ticket, 1)
	if err != nil {
		t.Fatal(err)
	}
	acc, _ := mmr.New(nodecontract.DomainOutputMMRV1)
	other := ticketOf(0x70)
	if _, err := session.Append(context.Background(), p.chunk(t, acc.Clone(), other, 0, "hello", 1)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("chunk of another ticket: %v", err)
	}

	session, _, err = p.open(t, p.worker, p.workerService, ticket, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Append(context.Background(), p.chunk(t, acc, ticket, 0, "hello", 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Finish(context.Background(), p.fin(t, acc.Clone(), other, 0)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("fin of another ticket: %v", err)
	}

	session, _, err = p.open(t, p.worker, p.workerService, ticket, 3)
	if err != nil {
		t.Fatal(err)
	}
	p.accept(p.worker.Address(), ticket, attempt.Rejected)
	if _, err := session.Append(context.Background(), p.chunk(t, acc, ticket, 1, "world", 2)); !errors.Is(err, ErrAttemptStale) {
		t.Fatalf("chunk after the record was rejected: %v", err)
	}
}

// Two attempts of one order won by the same Worker never share a stream: the retry's header
// starts a fresh stream, the first attempt's frames (sealed or not) are dropped, and only the
// retry's frames are replayed.
func TestRetryAttemptStartsAFreshStream(t *testing.T) {
	for _, sealFirst := range []bool{false, true} {
		p := newPhase1Fixture(t)
		first, second := ticketOf(0x71), ticketOf(0x72)
		p.accept(p.worker.Address(), first, attempt.Pending)
		session, _, err := p.open(t, p.worker, p.workerService, first, 1)
		if err != nil {
			t.Fatal(err)
		}
		acc, _ := mmr.New(nodecontract.DomainOutputMMRV1)
		if _, err := session.Append(context.Background(), p.chunk(t, acc, first, 0, "first", 4)); err != nil {
			t.Fatal(err)
		}
		if sealFirst {
			if _, err := session.Finish(context.Background(), p.fin(t, acc, first, 0)); err != nil {
				t.Fatal(err)
			}
		}
		p.accept(p.worker.Address(), first, attempt.Rejected)
		p.accept(p.worker.Address(), second, attempt.Pending)
		session, progress, err := p.open(t, p.worker, p.workerService, second, 2)
		if err != nil {
			t.Fatalf("sealed %t: retry open: %v", sealFirst, err)
		}
		if progress.Received || progress.Sealed {
			t.Fatalf("sealed %t: retry progress = %+v", sealFirst, progress)
		}
		acc2, _ := mmr.New(nodecontract.DomainOutputMMRV1)
		if _, err := session.Append(context.Background(), p.chunk(t, acc2, second, 0, "second", 5)); err != nil {
			t.Fatalf("sealed %t: retry append: %v", sealFirst, err)
		}
		frames, err := p.service.OutputFrames(context.Background(), outputStreamKey(), nil)
		if err != nil || len(frames) != 1 || string(frames[0].Chunk.Text) != "second" || !bytes.Equal(frames[0].Chunk.DispatchTicketHash, second[:]) {
			t.Fatalf("sealed %t: frames = %+v, %v", sealFirst, frames, err)
		}
		if _, err := p.store.ResolveObject(context.Background(), testSessionID, testTaskID, ObjectKindOutput); !errors.Is(err, ErrNotFound) {
			t.Fatalf("sealed %t: the dropped attempt's OUTPUT is still indexed: %v", sealFirst, err)
		}
	}
}

// Cumulative generated tokens are stored with each chunk and may not decrease.
func TestCumulativeTokensAreKeptAndNeverDecrease(t *testing.T) {
	p := newPhase1Fixture(t)
	ticket := ticketOf(0x71)
	p.accept(p.worker.Address(), ticket, attempt.Pending)
	session, _, err := p.open(t, p.worker, p.workerService, ticket, 1)
	if err != nil {
		t.Fatal(err)
	}
	acc, _ := mmr.New(nodecontract.DomainOutputMMRV1)
	if _, err := session.Append(context.Background(), p.chunk(t, acc, ticket, 0, "hello", 9)); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Append(context.Background(), p.chunk(t, acc, ticket, 1, "world", 8)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("decreasing tokens: %v", err)
	}
	frames, _ := p.service.OutputFrames(context.Background(), outputStreamKey(), nil)
	if len(frames) != 1 || frames[0].Chunk.CumulativeGeneratedTokens != 9 {
		t.Fatalf("frames = %+v", frames)
	}
}

// Before the chain knows the task, the winner reads its INPUT by the accept this Builder holds:
// the request names the order version of the attempt and its input_hash. Any other Cortex, and a
// request for another version, is refused. Once the record is admitted the chain's task decides
// again.
func TestWinnerFetchesInputByItsAcceptBeforeTheRecord(t *testing.T) {
	p := newPhase1Fixture(t)
	body := []byte("the input")
	header := testHeader(body)
	stored := prepareObject(t, p.store, header, body)
	if _, err := p.store.MarkReady(context.Background(), stored.Key); err != nil {
		t.Fatal(err)
	}
	ticket := ticketOf(0x71)
	p.accept(p.worker.Address(), ticket, attempt.Pending)
	won, _ := p.attempts.Current(testTaskID)
	won.InputHash = header.Key.ContentHash
	p.attempts.set(won)
	fetch := func(caller signer.Signer, key ObjectKey, nonce byte) ([]byte, error) {
		reader, _, _, err := p.service.OpenFetch(context.Background(), p.fixtureFetch(t, caller, key, nil, nonce, 110), nil)
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		var buf bytes.Buffer
		_, err = buf.ReadFrom(reader)
		return buf.Bytes(), err
	}
	got, err := fetch(p.worker, stored.Key, 1)
	if err != nil || string(got) != string(body) {
		t.Fatalf("winner fetch = %q, %v", got, err)
	}
	if receipts, err := p.service.FetchReceipts(context.Background(), testSessionID, testTaskID); err != nil || len(receipts) != 1 {
		t.Fatalf("the winner's fetch is not kept: %+v, %v", receipts, err)
	}
	if _, err := fetch(p.other, stored.Key, 2); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("another Cortex: %v", err)
	}
	otherVersionKey := stored.Key
	otherVersionKey.TaskHash = testContent
	if _, err := fetch(p.worker, otherVersionKey, 3); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("another order version: %v", err)
	}
	p.accept(p.worker.Address(), ticket, attempt.Recorded)
	if _, err := fetch(p.worker, stored.Key, 4); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("after the record the chain's task is read: %v", err)
	}
}
