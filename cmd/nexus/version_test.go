package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionCommandOutput(t *testing.T) {
	oldFlagVersion := flagVersion
	oldVersion, oldCommitID, oldBuildTime := version, commitID, buildTime
	flagVersion = false
	version, commitID, buildTime = "v1.2.3", "abc1234", "2026-07-14T00:00:00Z"
	t.Cleanup(func() {
		flagVersion = oldFlagVersion
		version, commitID, buildTime = oldVersion, oldCommitID, oldBuildTime
	})

	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"version"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("version command: %v", err)
	}
	got := out.String()
	for _, want := range []string{"nexus v1.2.3", "commit_id: abc1234", "build_time: 2026-07-14T00:00:00Z"} {
		if !strings.Contains(got, want) {
			t.Fatalf("version output missing %q:\n%s", want, got)
		}
	}
}

func TestRootVersionFlagOutput(t *testing.T) {
	oldFlagVersion := flagVersion
	oldVersion, oldCommitID, oldBuildTime := version, commitID, buildTime
	flagVersion = false
	version, commitID, buildTime = "v9.9.9", "def5678", "2026-07-14T01:02:03Z"
	t.Cleanup(func() {
		flagVersion = oldFlagVersion
		version, commitID, buildTime = oldVersion, oldCommitID, oldBuildTime
	})

	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--version"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("--version: %v", err)
	}
	got := out.String()
	for _, want := range []string{"nexus v9.9.9", "commit_id: def5678", "build_time: 2026-07-14T01:02:03Z"} {
		if !strings.Contains(got, want) {
			t.Fatalf("--version output missing %q:\n%s", want, got)
		}
	}
}
