package taskdata

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// blobWatch records the blob hashes that metadata writes referenced while one blob collection ran
// without the exclusive maintenance lock.
type blobWatch struct {
	referenced map[string]struct{}
}

// watchBlobs starts recording new blob references for a collection. The collection starts it
// before it reads the metadata, so every reference is either in what it read or recorded here.
func (s *Store) watchBlobs() *blobWatch {
	watch := &blobWatch{referenced: make(map[string]struct{})}
	s.blobWatchMu.Lock()
	defer s.blobWatchMu.Unlock()
	if s.blobWatches == nil {
		s.blobWatches = make(map[*blobWatch]struct{})
	}
	s.blobWatches[watch] = struct{}{}
	return watch
}

func (s *Store) unwatchBlobs(watch *blobWatch) {
	s.blobWatchMu.Lock()
	defer s.blobWatchMu.Unlock()
	delete(s.blobWatches, watch)
}

// noteBlobReferenced records hash in every running collection. A writer calls it after the
// metadata write that references hash and before it releases the maintenance read lock, so a
// collection, which deletes only under the exclusive lock, always sees it.
func (s *Store) noteBlobReferenced(hash string) {
	s.blobWatchMu.Lock()
	defer s.blobWatchMu.Unlock()
	for watch := range s.blobWatches {
		watch.referenced[hash] = struct{}{}
	}
}

func (s *Store) watched(watch *blobWatch, hash string) bool {
	s.blobWatchMu.Lock()
	defer s.blobWatchMu.Unlock()
	_, ok := watch.referenced[hash]
	return ok
}

// collectBlob removes the blob hash names when no metadata record references it, without holding
// the exclusive maintenance lock for the metadata scan. Every other unreferenced blob is left to
// the next Sweep.
func (s *Store) collectBlob(hash string) error {
	watch := s.watchBlobs()
	defer s.unwatchBlobs(watch)
	records, err := s.loadMetadataRecords()
	if err != nil {
		return err
	}
	_, err = s.collectBlobs(watch, records, []string{hash})
	return err
}

func referencedBlobs(records map[string]metadataRecord) map[string]struct{} {
	referenced := make(map[string]struct{}, len(records))
	for _, record := range records {
		referenced[record.BlobHash] = struct{}{}
	}
	return referenced
}

// collectBlobs removes the blobs no metadata record references, among candidates, or among every
// blob on disk when candidates is nil. records must have been read after watch started. Only the
// removal takes the exclusive maintenance lock, and it skips every blob a metadata write
// referenced since then. It returns how many blobs it removed.
func (s *Store) collectBlobs(watch *blobWatch, records map[string]metadataRecord, candidates []string) (int, error) {
	referenced := referencedBlobs(records)
	var unreferenced []string
	if candidates == nil {
		var err error
		if unreferenced, err = s.unreferencedBlobFiles(referenced); err != nil {
			return 0, err
		}
	} else {
		for _, hash := range candidates {
			if _, ok := referenced[hash]; !ok && canonicalSHA256(hash) {
				unreferenced = append(unreferenced, hash)
			}
		}
	}
	if len(unreferenced) == 0 {
		return 0, nil
	}
	s.maintenance.Lock()
	defer s.maintenance.Unlock()
	removed := 0
	for _, hash := range unreferenced {
		if s.watched(watch, hash) {
			continue
		}
		if err := os.Remove(s.blobPath(hash)); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return removed, fmt.Errorf("%w: reconcile blobs: %v", ErrStorage, err)
		}
		removed++
	}
	return removed, nil
}

// unreferencedBlobFiles walks the blob directory and returns the hash of every blob file that
// referenced does not name.
func (s *Store) unreferencedBlobFiles(referenced map[string]struct{}) ([]string, error) {
	var unreferenced []string
	root := filepath.Join(s.root, "blobs", "sha256")
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		name := entry.Name()
		if !canonicalSHA256(name) || path != s.blobPath(name) {
			return fmt.Errorf("unexpected blob path %q", path)
		}
		if _, ok := referenced[name]; !ok {
			unreferenced = append(unreferenced, name)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: reconcile blobs: %v", ErrStorage, err)
	}
	return unreferenced, nil
}
