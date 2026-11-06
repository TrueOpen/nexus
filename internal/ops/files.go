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
	// takenSuffix marks a request the daemon took: renamed before it is read, so a request
	// written meanwhile is a new file and is never deleted unread. A crash after the taken file
	// is removed and before the drain state is stored loses the request; the operator sends it
	// again (nexus drain status shows whether it took effect).
	takenSuffix = ".taken"
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

// takeDrainRequest takes the drain request: renamed aside first, then read and removed; false
// when there is none. A request left renamed by a crash is taken first.
func takeDrainRequest(dataDir string) (string, bool, error) {
	path := DrainRequestPath(dataDir)
	taken := path + takenSuffix
	if _, err := os.Stat(taken); errors.Is(err, os.ErrNotExist) {
		if err := os.Rename(path, taken); errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		} else if err != nil {
			return "", false, err
		}
	} else if err != nil {
		return "", false, err
	}
	raw, err := os.ReadFile(taken)
	if err != nil {
		return "", false, err
	}
	if err := os.Remove(taken); err != nil {
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
