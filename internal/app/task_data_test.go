package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
)

type taskDataTaskChainStub struct {
	heightCalls int
	taskCalls   int
}

func (s *taskDataTaskChainStub) LatestHeight(context.Context) (uint64, error) {
	s.heightCalls++
	return 12, nil
}

func (s *taskDataTaskChainStub) QueryTask(context.Context, chaincli.TaskKey) (chaincli.OnChainTask, error) {
	s.taskCalls++
	return chaincli.OnChainTask{SessionID: "session-1", TaskID: "task-1"}, nil
}

type taskDataKeyChainStub struct {
	keyCalls     int
	profileCalls int
}

func (s *taskDataKeyChainStub) QueryCurrentServiceKey(context.Context, string, string) (chaincli.ServiceKeyState, error) {
	s.keyCalls++
	return chaincli.ServiceKeyState{}, errors.New("key query reached hub")
}

func (s *taskDataKeyChainStub) QueryProfile(context.Context, string, uint32) (chaincli.ProfileState, error) {
	s.profileCalls++
	return chaincli.ProfileState{}, errors.New("profile query reached hub")
}

func TestTaskDataAuthoritySplitsTaskAndHubQueries(t *testing.T) {
	taskChain := &taskDataTaskChainStub{}
	hubChain := &taskDataKeyChainStub{}
	authority := newTaskDataAuthority(taskChain, hubChain, hubChain)
	if _, err := authority.LatestHeight(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.QueryTask(context.Background(), chaincli.TaskKey{SessionID: "session-1", TaskID: "task-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.QueryCurrentServiceKey(context.Background(), "BUILDER", "builder-1"); err == nil {
		t.Fatal("expected hub key error")
	}
	// A Profile is Hub-side data too (QueryProfile goes through hubQuery) and must not land on the Task Chain.
	if _, err := authority.QueryProfile(context.Background(), "model-1", 1); err == nil {
		t.Fatal("expected hub profile error")
	}
	if taskChain.heightCalls != 1 || taskChain.taskCalls != 1 || hubChain.keyCalls != 1 || hubChain.profileCalls != 1 {
		t.Fatalf("calls task-height=%d task=%d hub-key=%d hub-profile=%d",
			taskChain.heightCalls, taskChain.taskCalls, hubChain.keyCalls, hubChain.profileCalls)
	}
}

func TestTaskDataRootUsesDedicatedDataDirectory(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "nexus-state")
	if got, want := taskDataRoot(dataDir), filepath.Join(dataDir, "task-data"); got != want {
		t.Fatalf("task data root = %q, want %q", got, want)
	}
}

func TestNewCreatesTaskDataStoreAndOrdersRecoveryBeforeIngress(t *testing.T) {
	cfg := config.Load()
	cfg.DataDir = t.TempDir()
	cfg.NATS.Servers = nil
	cfg.Identity = config.IdentityConfig{Bech32Prefix: "trueopen"}
	created, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = created.kv.Close() })
	for _, path := range []string{
		filepath.Join(cfg.DataDir, "task-data", "spool"),
		filepath.Join(cfg.DataDir, "task-data", "blobs", "sha256"),
	} {
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() {
			t.Fatalf("task data directory %q = %+v, %v", path, info, err)
		}
	}
	names := make([]string, 0, len(created.modules))
	for _, module := range created.modules {
		names = append(names, module.name)
	}
	taskDataIndex, coordinatorIndex, ingressIndex := indexOf(names, "task-data"), indexOf(names, "coordinator"), indexOf(names, "ingress")
	if taskDataIndex < 0 || coordinatorIndex < 0 || ingressIndex < 0 || !(taskDataIndex < coordinatorIndex && coordinatorIndex < ingressIndex) {
		t.Fatalf("module order = %v", names)
	}
}

func indexOf(values []string, target string) int {
	for index, value := range values {
		if value == target {
			return index
		}
	}
	return -1
}
