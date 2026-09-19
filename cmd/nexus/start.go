package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/TrueOpen/nexus/internal/app"
)

func newStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start the nexus service",
		// cfg / logger are already prepared by root.PersistentPreRunE; this only handles startup and lifecycle.
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cfgFrom(cmd)
			log := logFrom(cmd)
			build := currentBuildInfo()
			log.Info("nexus build info",
				"version", build.Version,
				"commit_id", build.CommitID,
				"build_time", build.BuildTime,
				"runtime", build.GoVersion,
				"goos", build.GOOS,
				"goarch", build.GOARCH)

			a, err := app.New(cfg, log)
			if err != nil {
				return err
			}

			parent := cmd.Context()
			if parent == nil {
				parent = context.Background()
			}
			ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
			defer stop()

			if err := a.Start(ctx); err != nil {
				return err
			}

			<-ctx.Done()
			log.Info("shutdown signal received")

			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return a.Stop(shutdownCtx)
		},
	}
}
