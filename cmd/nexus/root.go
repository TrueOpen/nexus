package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/TrueOpen/nexus/internal/chainreset"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/logging"
)

// Global (persistent) flags; each one overrides the corresponding environment variable.
var (
	flagConfig    string
	flagLogLevel  string
	flagLogFormat string
	flagLogFile   string
	flagVersion   bool
)

// context keys used to pass the cfg / logger produced by the prepare phase into each subcommand's RunE.
type ctxKey int

const (
	cfgKey ctxKey = iota
	logKey
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "nexus",
		Short:         "TrueOpen Builder off-chain coordinator",
		Long:          "nexus — the off-chain coordinator co-located with the local node on a Builder machine: ingests orders, orchestrates the three on-chain stages (Assign / OpenVerify / Settle), and relays retrieval credentials.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if flagVersion {
				printBuildInfo(cmd)
				return nil
			}
			return cmd.Help()
		},
		// PersistentPreRunE = prepare phase shared by all subcommands:
		// resolve config (defaults < YAML < env < flags), validate it, build the logger.
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if flagVersion {
				return nil
			}
			cfg, configPath, err := loadCommandConfig(flagConfig, cmd.Root().PersistentFlags().Changed("config"), configOverrides{
				LogLevel:   flagLogLevel,
				LogFormat:  flagLogFormat,
				LogFile:    flagLogFile,
				LogFileSet: cmd.Flags().Changed("log-file"),
			})
			if err != nil {
				return err
			}

			logger := logging.Setup(cfg.Log)
			if configPath != "" {
				logger.Info("configuration loaded", "file", configPath)
			}

			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			ctx = context.WithValue(ctx, cfgKey, cfg)
			ctx = context.WithValue(ctx, logKey, logger)
			cmd.SetContext(ctx)
			return nil
		},
	}
	pf := root.PersistentFlags()
	pf.StringVar(&flagConfig, "config", "", "YAML config file (default: ./nexus.yaml when present)")
	pf.StringVar(&flagLogLevel, "log-level", "", "log level: debug/info/warn/error (overrides NEXUS_LOG_LEVEL)")
	pf.StringVar(&flagLogFormat, "log-format", "", "log format: text/json (overrides NEXUS_LOG_FORMAT)")
	pf.StringVar(&flagLogFile, "log-file", "", "log file path; enables rotation+gzip (overrides NEXUS_LOG_FILE)")
	root.Flags().BoolVar(&flagVersion, "version", false, "print version information and exit")

	root.AddCommand(newStartCmd(), newVersionCmd(), newBuilderCmd(), newKeysCmd(), newTLSCmd(), newNATSAuthCmd())
	return root
}

type configOverrides struct {
	LogLevel   string
	LogFormat  string
	LogFile    string
	LogFileSet bool
}

func loadCommandConfig(explicitPath string, explicit bool, overrides configOverrides) (config.Config, string, error) {
	path, err := resolveConfigPath(explicitPath, explicit)
	if err != nil {
		return config.Config{}, "", err
	}
	cfg, err := config.LoadFile(path)
	if err != nil {
		return config.Config{}, "", err
	}
	if overrides.LogLevel != "" {
		cfg.Log.Level = overrides.LogLevel
	}
	if overrides.LogFormat != "" {
		cfg.Log.Format = overrides.LogFormat
	}
	if overrides.LogFileSet {
		cfg.Log.File = overrides.LogFile
	}
	if err := validateLog(cfg.Log); err != nil {
		return config.Config{}, "", err
	}
	return cfg, path, nil
}

func resolveConfigPath(explicitPath string, explicit bool) (string, error) {
	if explicit {
		if strings.TrimSpace(explicitPath) == "" {
			return "", fmt.Errorf("--config requires a non-empty path")
		}
		if _, err := os.Stat(explicitPath); err != nil {
			return "", fmt.Errorf("config file %q: %w", explicitPath, err)
		}
		return explicitPath, nil
	}
	if _, err := os.Stat(config.DefaultFile); err == nil {
		return config.DefaultFile, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("config file %q: %w", config.DefaultFile, err)
	}
	return "", nil
}

// validateLog rejects an invalid config during the prepare phase so it is not discovered only inside RunE.
func validateLog(c config.LogConfig) error {
	switch c.Format {
	case "text", "json":
	default:
		return fmt.Errorf("invalid log format %q (want text|json)", c.Format)
	}
	switch c.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("invalid log level %q (want debug|info|warn|error)", c.Level)
	}
	return nil
}

// cfgFrom / logFrom retrieve what the prepare phase produced from the context.
func cfgFrom(cmd *cobra.Command) config.Config { return cmd.Context().Value(cfgKey).(config.Config) }
func logFrom(cmd *cobra.Command) *slog.Logger  { return cmd.Context().Value(logKey).(*slog.Logger) }

// Execute is the binary's entry point.
func Execute() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		if errors.Is(err, chainreset.ErrChainReset) {
			os.Exit(chainreset.ExitCode)
		}
		os.Exit(1)
	}
}
