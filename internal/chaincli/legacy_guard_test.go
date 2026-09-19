package chaincli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TrueOpen/nexus/gen/trueopen/task/v1/taskv1connect"
)

func TestNoLegacyEventServiceABI(t *testing.T) {
	if got, want := taskv1connect.TaskEventServiceSubscribeTaskEventsProcedure,
		"/task.v1.TaskEventService/SubscribeTaskEvents"; got != want {
		t.Fatalf("TaskEventService procedure = %q, want %q", got, want)
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	legacy := []string{
		"shared.v1." + "EventService",
		"SubscribeEvents" + "Request",
		"Event" + "Batch",
	}
	var found []string
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if rel == ".git" || strings.HasPrefix(rel, ".git"+string(filepath.Separator)) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, ".proto") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, marker := range legacy {
			if strings.Contains(string(body), marker) {
				found = append(found, rel+": "+marker)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("legacy EventService ABI references remain:\n%s", strings.Join(found, "\n"))
	}
}

func TestProductionCodeHasNoLegacyNodeApplicationABI(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	legacy := []string{
		"/trueopen.inference.",
		"/trueopen.v1.Msg",
		"gen/trueopen/inference",
		"gen/trueopen/v1",
	}
	var found []string
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if rel == ".git" || strings.HasPrefix(rel, ".git"+string(filepath.Separator)) {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, "_test.go") ||
			(!strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, ".proto")) {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, marker := range legacy {
			if strings.Contains(string(body), marker) {
				found = append(found, rel+": "+marker)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("legacy Node application ABI references remain:\n%s", strings.Join(found, "\n"))
	}
}
