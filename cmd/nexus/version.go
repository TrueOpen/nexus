package main

import (
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// Injected at build time via:
// -ldflags "-X main.version=... -X main.commitID=... -X main.buildTime=...".
//
// commit/date are kept for compatibility with older build scripts.
var (
	version   = "dev"
	commitID  = "none"
	buildTime = "unknown"

	commit = ""
	date   = ""
)

type BuildInfo struct {
	Version   string
	CommitID  string
	BuildTime string
	GoVersion string
	GOOS      string
	GOARCH    string
}

func currentBuildInfo() BuildInfo {
	info := BuildInfo{
		Version:   valueOr(version, "dev"),
		CommitID:  valueOr(commitID, "none"),
		BuildTime: valueOr(buildTime, "unknown"),
		GoVersion: runtime.Version(),
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
	}
	if info.CommitID == "none" && commit != "" {
		info.CommitID = commit
	}
	if info.BuildTime == "unknown" && date != "" {
		info.BuildTime = date
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if (info.Version == "" || info.Version == "dev") && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			info.Version = bi.Main.Version
		}
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if info.CommitID == "" || info.CommitID == "none" {
					info.CommitID = s.Value
				}
			case "vcs.time":
				if info.BuildTime == "" || info.BuildTime == "unknown" {
					info.BuildTime = s.Value
				}
			case "vcs.modified":
				if s.Value == "true" && info.CommitID != "" && info.CommitID != "none" {
					info.CommitID += "-dirty"
				}
			}
		}
	}
	return info
}

func valueOr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func printBuildInfo(cmd *cobra.Command) {
	info := currentBuildInfo()
	fmt.Fprintf(cmd.OutOrStdout(), "nexus %s\ncommit_id: %s\nbuild_time: %s\nruntime: %s %s/%s\n",
		info.Version, info.CommitID, info.BuildTime, info.GoVersion, info.GOOS, info.GOARCH)
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		// Overrides root's PersistentPreRunE: version does not depend on the config, so it prints even when the config is broken.
		PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
		Run: func(cmd *cobra.Command, _ []string) {
			printBuildInfo(cmd)
		},
	}
}
