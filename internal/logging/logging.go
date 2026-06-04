// Package logging builds the process-wide slog logger from environment
// variables so every Tunnel binary shares one logging setup: readable text in
// development and JSON for cluster aggregation. The manager bridges its
// controller-runtime logr logger onto the same handler, so reconciler logs and
// the lower-level provision logs come out in a single consistent stream.
package logging

import (
	"log/slog"
	"os"
	"strings"
)

// Handler builds an slog.Handler configured from the environment:
//   - LOG_FORMAT=text selects a text handler; anything else (default) is JSON.
//   - LOG_LEVEL=debug|info|warn|error sets the minimum level (default info).
func Handler() slog.Handler {
	level := slog.LevelInfo
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	opts := &slog.HandlerOptions{Level: level}
	if strings.EqualFold(os.Getenv("LOG_FORMAT"), "text") {
		return slog.NewTextHandler(os.Stderr, opts)
	}
	return slog.NewJSONHandler(os.Stderr, opts)
}

// SetupDefault builds the handler with Handler, installs it as the slog default
// logger and returns it, so callers can also bridge it into other logging
// frameworks (for example logr.FromSlogHandler for controller-runtime).
func SetupDefault() slog.Handler {
	h := Handler()
	slog.SetDefault(slog.New(h))
	return h
}
