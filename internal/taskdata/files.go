package taskdata

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type diskUsageFunc func(path string) (total, used uint64, err error)

func filesystemUsage(path string) (uint64, uint64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, 0, err
	}
	total := stat.Blocks * uint64(stat.Bsize)
	available := stat.Bavail * uint64(stat.Bsize)
	if total == 0 || available > total {
		return 0, 0, fmt.Errorf("invalid filesystem capacity")
	}
	return total, total - available, nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func ensureObjectDirectories(root string) error {
	for _, dir := range []string{root, filepath.Join(root, "blobs", "sha256"), filepath.Join(root, "spool"), filepath.Join(root, "stream")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return nil
}
