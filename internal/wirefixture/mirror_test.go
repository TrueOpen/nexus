package wirefixture

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// mirroredPackages are the proto/<pkg>/v1 directories tools/mirror_wire.py owns (its PACKAGES).
var mirroredPackages = []string{"hub", "task", "shared", "bus"}

// TestProtoMirrorMatchesPinnedWire regenerates the proto mirror from the wire module pinned in go.mod
// with tools/mirror_wire.py and requires proto/ to be identical, file for file. Moving the wire pin
// without re-running the tool (and `make proto`) fails here instead of leaving a stale mirror behind.
func TestProtoMirrorMatchesPinnedWire(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed; the proto mirror cannot be regenerated")
	}
	root := repoRoot(t)
	out := t.TempDir()
	cmd := exec.Command(python, filepath.Join(root, "tools", "mirror_wire.py"), Dir(t), out)
	cmd.Dir = root
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("tools/mirror_wire.py: %v\n%s", err, output)
	}

	for _, pkg := range mirroredPackages {
		rel := filepath.Join(pkg, "v1")
		want := protoFiles(t, filepath.Join(out, rel))
		got := protoFiles(t, filepath.Join(root, "proto", rel))
		if len(want) == 0 {
			t.Fatalf("mirror_wire.py produced no %s protos", rel)
		}
		for name, wantBody := range want {
			gotBody, ok := got[name]
			switch {
			case !ok:
				t.Errorf("proto/%s/%s is missing; run python3 tools/mirror_wire.py && make proto", rel, name)
			case !bytes.Equal(gotBody, wantBody):
				t.Errorf("proto/%s/%s differs from the pinned wire; run python3 tools/mirror_wire.py && make proto", rel, name)
			}
		}
		for name := range got {
			if _, ok := want[name]; !ok {
				t.Errorf("proto/%s/%s is not in the pinned wire; run python3 tools/mirror_wire.py && make proto", rel, name)
			}
		}
	}
}

func protoFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "*.proto"))
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string][]byte, len(matches))
	for _, path := range matches {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		files[filepath.Base(path)] = body
	}
	return files
}

// repoRoot walks up from the package directory to the module root (the directory holding go.mod).
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}
