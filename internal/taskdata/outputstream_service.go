package taskdata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/TrueOpen/nexus/internal/mmr"
	"github.com/TrueOpen/nexus/internal/nodecontract"
	"github.com/TrueOpen/nexus/internal/signer"
)

// OutputStreamHeader is the internal form of the first frame of a streamed upload.
type OutputStreamHeader struct {
	Key      ObjectKey
	TaskHash string
}

// SetOutputStreamConfig sets the streamed OUTPUT limits; without it, opening a stream is refused.
func (s *Service) SetOutputStreamConfig(cfg OutputStreamConfig) { s.outputStream = cfg }

// OutputStreamSession is a write stream whose Header has passed authorization: it holds the
// Worker's current service key and task_hash, verifying each frame's signature before
// handing it to storage.
type OutputStreamSession struct {
	service   *Service
	stream    *OutputStream
	key       ObjectKey
	chainID   string
	taskHash  []byte
	workerPub []byte
}

// OpenOutputStream handles the streamed upload Header: authorize (selected Worker, task_hash,
// task phase), open or take over the write stream, consume the request nonce. If the stream
// is already finalized or a complete object exists, it returns the progress with ErrConflict
// and a nil session: the caller replies with the progress and then ends with AlreadyExists.
func (s *Service) OpenOutputStream(ctx context.Context, request RequestAuth, header OutputStreamHeader) (*OutputStreamSession, OutputStreamProgress, error) {
	if err := s.outputStream.validate(); err != nil {
		return nil, OutputStreamProgress{}, err
	}
	_, height, workerPub, err := s.authorizer.AuthorizeOutputStream(ctx, request, header.Key, header.TaskHash)
	if err != nil {
		return nil, OutputStreamProgress{}, err
	}
	taskHash, err := hex.DecodeString(header.TaskHash)
	if err != nil || len(taskHash) != sha256.Size {
		return nil, OutputStreamProgress{}, fmt.Errorf("%w: task_hash", ErrMalformed)
	}
	// The nonce must be consumed before opening the stream: opening takes over and kicks the
	// live old stream, so if a used nonce were only detected afterwards, a validly signed
	// replayed Header could cut off a stream in progress.
	if err := s.authorizer.consumeRequestNonce(request, height); err != nil {
		return nil, OutputStreamProgress{}, err
	}
	stream, progress, err := s.store.OpenOutputStream(ctx, header.Key, request.RequesterAddress, s.outputStream)
	if err != nil {
		return nil, progress, err
	}
	return &OutputStreamSession{
		service: s, stream: stream, key: header.Key, chainID: s.authorizer.cfg.ChainID, taskHash: taskHash, workerPub: workerPub,
	}, progress, nil
}

// Progress returns the current progress.
func (sess *OutputStreamSession) Progress() OutputStreamProgress { return sess.stream.Progress() }

// Append receives one chunk: (1) verify the TRUEOPEN_OUTPUT_CHUNK_V1 signature with the
// Worker's current service key, then hand it to storage for (2)(3)(4). Any failure closes
// the stream.
func (sess *OutputStreamSession) Append(ctx context.Context, chunk OutputChunk) (mmr.Hash, error) {
	if len(chunk.MMRRoot) != sha256.Size || len(chunk.WorkerSignature) != 64 {
		return mmr.Hash{}, sess.stream.fail(fmt.Errorf("%w: chunk mmr_root or worker_signature shape", ErrMalformed))
	}
	digest, err := nodecontract.OutputChunkSigningDigest(sess.chainID, sess.taskHash, chunk.Seq, chunk.MMRRoot)
	if err != nil {
		return mmr.Hash{}, sess.stream.fail(fmt.Errorf("%w: chunk signing digest: %v", ErrMalformed, err))
	}
	if !signer.VerifyDigestSig(sess.workerPub, digest[:], chunk.WorkerSignature) {
		return mmr.Hash{}, sess.stream.fail(fmt.Errorf("%w: chunk worker_signature", ErrUnauthorized))
	}
	return sess.stream.Append(ctx, chunk)
}

// Finish receives Fin: the OUTPUT bytes are fully persisted, the MMR root is computed, and
// the object enters STORED.
//
// No storage confirmation is signed here. Fin cannot prove the OUTPUT is consistent with
// the Receipt and the Worker manifest; the consistent binding of the three is committed
// once by FinalizeTaskResult, which also issues the confirmation (§5.5).
func (sess *OutputStreamSession) Finish(ctx context.Context, fin OutputFin) (Metadata, error) {
	return sess.stream.Finish(ctx, fin)
}

// Close closes the stream on disconnect or error; persisted chunks are kept.
func (sess *OutputStreamSession) Close() { sess.stream.Close() }

// OutputFrames replays persisted chunks (seq > afterSeq), appending Fin if the stream is finalized.
func (s *Service) OutputFrames(ctx context.Context, key ObjectKey, afterSeq *uint64) ([]OutputFrame, error) {
	return s.store.OutputFrames(ctx, key, afterSeq)
}

// OutputStreamProgressOf reads the stream progress without opening the stream.
func (s *Service) OutputStreamProgressOf(ctx context.Context, key ObjectKey) (OutputStreamProgress, bool, error) {
	return s.store.OutputStreamProgressOf(ctx, key)
}
