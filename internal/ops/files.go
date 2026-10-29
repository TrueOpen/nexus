package ops

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The operator files live in <data_dir>/ops: the drain request the operator leaves for the
// running daemon, and the status the daemon writes. They need no listener: the daemon reads the
// request and writes the status on every tick.
const (
	drainRequestFile = "drain-request"
	statusFile       = "status.json"
)

// Drain requests.
const (
	DrainBegin = "begin"
	DrainEnd   = "end"
)

// Dir is the operator directory under dataDir.
func Dir(dataDir string) string { return filepath.Join(dataDir, "ops") }

// StatusPath is the status file the daemon writes.
func StatusPath(dataDir string) string { return filepath.Join(Dir(dataDir), statusFile) }

// DrainRequestPath is the drain request file.
func DrainRequestPath(dataDir string) string { return filepath.Join(Dir(dataDir), drainRequestFile) }

// WriteDrainRequest leaves a drain request (DrainBegin or DrainEnd) for the daemon, replacing an
// unread one. A daemon not running takes it at its next start.
func WriteDrainRequest(dataDir, request string) error {
	if request != DrainBegin && request != DrainEnd {
		return fmt.Errorf("drain request %q is neither %q nor %q", request, DrainBegin, DrainEnd)
	}
	return writeFile(DrainRequestPath(dataDir), []byte(request+"\n"))
}

// takeDrainRequest reads and removes the drain request; false when there is none.
func takeDrainRequest(dataDir string) (string, bool, error) {
	path := DrainRequestPath(dataDir)
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if err := os.Remove(path); err != nil {
		return "", false, err
	}
	request := strings.TrimSpace(string(raw))
	if request != DrainBegin && request != DrainEnd {
		return "", false, fmt.Errorf("drain request %q is neither %q nor %q", request, DrainBegin, DrainEnd)
	}
	return request, true, nil
}

// ReadStatus returns the status file as the daemon last wrote it.
func ReadStatus(dataDir string) ([]byte, error) { return os.ReadFile(StatusPath(dataDir)) }

// writeFile replaces path with data in one rename, readable by the owner only.
func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
