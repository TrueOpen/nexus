// Package logging builds the slog.Logger for nexus:
// it supports the text/json formats, stdout, and optional file output (lumberjack rotation + gzip compression).
// slog stays the single front end; if maximum performance is ever needed the backend can be swapped for zap/zerolog here without touching application code.
package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/TrueOpen/nexus/internal/config"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Setup returns the logger for the given config. When a file is configured it writes to stdout and the rotating file at the same time.
func Setup(cfg config.LogConfig) *slog.Logger {
	var w io.Writer = os.Stdout
	if cfg.File != "" {
		w = io.MultiWriter(os.Stdout, &lumberjack.Logger{
			Filename:   cfg.File,
			MaxSize:    cfg.MaxSizeMB,
			MaxBackups: cfg.MaxBackups,
			MaxAge:     cfg.MaxAgeDays,
			Compress:   cfg.Compress,
		})
	}

	opts := &slog.HandlerOptions{Level: parseLevel(cfg.Level)}
	var h slog.Handler
	switch strings.ToLower(cfg.Format) {
	case "json":
		h = slog.NewJSONHandler(w, opts)
	default:
		h = slog.NewTextHandler(w, opts)
	}
	return slog.New(h)
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
