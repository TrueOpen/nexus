package buildersync

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/TrueOpen/nexus/internal/taskdata"
)

// StoredInputs reads and writes order inputs in the task data store: the dispatching Builder
// reads the input OpenTask stored, a member stores the synced copy the same way.
type StoredInputs struct{ Store *taskdata.Store }

// ReadInput implements InputReader.
func (s StoredInputs) ReadInput(ctx context.Context, sessionID, taskID, taskHash string) ([]byte, string, error) {
	ref, err := s.Store.ResolveObject(ctx, sessionID, taskID, taskdata.ObjectKindInput)
	if err != nil {
		return nil, "", err
	}
	if ref.TaskHash != taskHash {
		return nil, "", fmt.Errorf("stored INPUT of task %s is another order version", taskID)
	}
	metadata, err := s.Store.Metadata(ctx, ref)
	if err != nil {
		return nil, "", err
	}
	reader, err := s.Store.OpenStored(ctx, ref)
	if err != nil {
		return nil, "", err
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, "", fmt.Errorf("read stored INPUT: %w", err)
	}
	return data, metadata.MediaType, nil
}

// PutInput implements InputWriter: the input becomes READY as OpenTask leaves it. An input already
// held is left as it is.
func (s StoredInputs) PutInput(ctx context.Context, header taskdata.UploadHeader, data []byte) error {
	if metadata, err := s.Store.Metadata(ctx, header.Key); err == nil && metadata.State == taskdata.StateReady {
		return nil
	} else if err != nil && !errors.Is(err, taskdata.ErrNotFound) {
		return err
	}
	upload, err := s.Store.Begin(ctx, header)
	if err != nil {
		return err
	}
	prepared := false
	defer func() {
		if !prepared {
			_ = upload.Abort()
		}
	}()
	for offset := uint64(0); offset < uint64(len(data)); offset += s.Store.ChunkSize() {
		if err := upload.WriteChunk(data[offset:min(offset+s.Store.ChunkSize(), uint64(len(data)))]); err != nil {
			return err
		}
	}
	if _, err := upload.Prepare(ctx); err != nil {
		return err
	}
	prepared = true
	if _, err := s.Store.MarkReady(ctx, header.Key); err != nil {
		_ = s.Store.RollbackPrepared(context.Background(), header.Key)
		return err
	}
	return nil
}
