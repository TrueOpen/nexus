package taskdata

import (
	"context"
	"errors"
	"io"
)

// Service combines storage and current-role authorization in the security
// order required by the public RPCs.
type Service struct {
	store      *Store
	authorizer *Authorizer
	chunkSize  uint64

	// Streamed OUTPUT (ADR-0017): outputStream holds the network-wide limits. The receipt
	// is not compared against the locally computed root inside the stream: the object uses
	// the MMR root as content_hash and FinalizeTaskResult looks the object up by
	// receipt.output_hash, so a successful lookup is the comparison; READY and the storage
	// confirmation are produced only there.
	outputStream OutputStreamConfig
}

func NewService(store *Store, authorizer *Authorizer) (*Service, error) {
	if store == nil || authorizer == nil {
		return nil, ErrServiceKeyUnavailable
	}
	return &Service{store: store, authorizer: authorizer, chunkSize: store.cfg.ChunkSizeBytes}, nil
}

func (s *Service) ChunkSize() uint64 { return s.chunkSize }

func (s *Service) AuthorizeOpenTaskRequest(ctx context.Context, requester string, nonce []byte, expiry uint64) error {
	return s.authorizer.AuthorizeOpenTaskRequest(ctx, requester, nonce, expiry)
}

func (s *Service) BeginInput(ctx context.Context, header UploadHeader) (*Upload, error) {
	if header.Key.Kind != ObjectKindInput || header.Receipt != nil {
		return nil, ErrMalformed
	}
	return s.store.Begin(ctx, header)
}

func (s *Service) PrepareInput(ctx context.Context, upload *Upload) (Metadata, error) {
	if upload == nil || upload.header.Key.Kind != ObjectKindInput {
		return Metadata{}, ErrMalformed
	}
	return upload.Prepare(ctx)
}

func (s *Service) MarkInputReady(ctx context.Context, key ObjectKey) (Metadata, error) {
	if key.Kind != ObjectKindInput {
		return Metadata{}, ErrMalformed
	}
	return s.store.MarkReady(ctx, key)
}

func (s *Service) RollbackInput(ctx context.Context, key ObjectKey) error {
	if key.Kind != ObjectKindInput {
		return ErrMalformed
	}
	return s.store.RollbackPrepared(ctx, key)
}

func (s *Service) GetMetadata(ctx context.Context, request RequestAuth) (Metadata, bool, error) {
	access, err := s.authorizer.verifyMetadataRequest(ctx, request)
	if err != nil {
		return Metadata{}, false, err
	}
	s.store.maintenance.RLock()
	defer s.store.maintenance.RUnlock()
	metadata, metadataErr := s.store.metadataLocked(request.Key)
	// STORED objects also count as "present": the readiness enum exists so the producer
	// can see its object is persisted while the owning bundle is not yet finalized.
	// STAGING / QUARANTINED do not count.
	var candidate *Metadata
	if metadataErr == nil && (metadata.State == StateStored || metadata.State == StateReady) {
		candidate = &metadata
	}
	if err := s.authorizer.finishMetadata(request, access, candidate); err != nil {
		return Metadata{}, false, err
	}
	if metadataErr != nil {
		if errors.Is(metadataErr, ErrNotFound) {
			return Metadata{Key: request.Key}, false, nil
		}
		return Metadata{}, false, metadataErr
	}
	if metadata.RetentionStatus == RetentionDeleted {
		return metadata, false, nil
	}
	if metadata.State != StateStored && metadata.State != StateReady {
		return Metadata{Key: request.Key}, false, nil
	}
	return metadata, true, nil
}

// OpenDownload contract §2.2: the range request carries the requester's own signature and
// authorization derives from on-chain roles, so no pre-signed download credential is needed.
// OpenFetch is the data path of FetchTaskData. It verifies the request before consulting
// local state: in the reverse order an unauthorized caller could tell from response
// differences whether the object exists.
//
// A nil byteRange means a full read. It and a present range with zero offset/length are
// two different signed commitments, and the former is not rewritten into the latter here.
// The returned served is the actual range, for echoing in headers.
func (s *Service) OpenFetch(
	ctx context.Context, request RequestAuth, byteRange *ByteRange,
) (io.ReadCloser, ByteRange, Metadata, error) {
	grant, err := s.authorizer.AuthorizeFetch(ctx, request, byteRange)
	if err != nil {
		return nil, ByteRange{}, Metadata{}, err
	}
	task := grant.Task
	metadata, err := s.store.Metadata(ctx, request.Key)
	if err != nil {
		return nil, ByteRange{}, Metadata{}, err
	}
	if metadata.State != StateReady || metadata.RetentionStatus == RetentionDeleted {
		return nil, ByteRange{}, Metadata{}, ErrUnauthorized
	}
	if err := verifyAcceptedOutputMetadata(metadata, task.InferReceipt); err != nil {
		return nil, ByteRange{}, Metadata{}, err
	}
	served := ByteRange{Offset: 0, Length: metadata.SizeBytes}
	if byteRange != nil {
		served = *byteRange
		end, overflow := served.Offset+served.Length, served.Offset+served.Length < served.Offset
		if overflow || end > metadata.SizeBytes {
			return nil, ByteRange{}, Metadata{}, ErrRangeInvalid
		}
	}
	// The receipt of a recorded fetch is kept before any byte leaves: nonce consumed, object
	// READY, range checked, then the signed request is written, and a failed write stops the
	// fetch.
	receiptKey := ""
	if recordsFetch(task, request) {
		receiptKey, err = s.store.recordFetchReceipt(newFetchReceipt(grant, request, byteRange, served))
		if err != nil {
			return nil, ByteRange{}, Metadata{}, err
		}
	}
	reader, err := s.store.OpenRange(ctx, request.Key, served.Offset, served.Length)
	if err != nil {
		return nil, ByteRange{}, Metadata{}, err
	}
	if receiptKey != "" {
		reader = &receiptReader{ReadCloser: reader, store: s.store, key: receiptKey, length: served.Length}
	}
	return reader, served, metadata, nil
}

// FetchReceipts returns the fetch receipts kept for one task, grouped by requester.
func (s *Service) FetchReceipts(ctx context.Context, sessionID, taskID string) ([]FetchReceiptSet, error) {
	return s.store.FetchReceipts(ctx, sessionID, taskID)
}

func (s *Service) BeginUpload(ctx context.Context, request RequestAuth, header UploadHeader) (*Upload, error) {
	acceptedHash, height, err := s.authorizer.AuthorizeUploadObject(ctx, request, header)
	if err != nil {
		return nil, err
	}
	header.AcceptedReceiptHash = acceptedHash
	header.Uploader = request.RequesterAddress
	upload, err := s.store.Begin(ctx, header)
	if err != nil {
		return nil, err
	}
	if err := s.authorizer.consumeRequestNonce(request, height); err != nil {
		_ = upload.Abort()
		return nil, err
	}
	return upload, nil
}

// CommitUpload crosses the first boundary of §5.5: once the complete data is persisted and
// the size and hash/root checks pass, the object enters STORED.
//
// No storage confirmation is signed here. The confirmation commits that "this bundle is
// consistently bound to the Receipt and manifest", which a single persisted object cannot
// prove; it is issued once by FinalizeTaskResult / FinalizeVerifierEvidence (§5.5).
func (s *Service) CommitUpload(ctx context.Context, upload *Upload) (Metadata, error) {
	if upload == nil {
		return Metadata{}, ErrMalformed
	}
	metadata, err := upload.Prepare(ctx)
	if err != nil {
		return Metadata{}, err
	}
	return s.store.MarkStored(ctx, metadata.Key)
}
