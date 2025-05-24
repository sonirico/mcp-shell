package main

import (
	"io"
	"os"
	"strings"

	"github.com/rs/zerolog"
)

func newLogger(cfg LoggingConfig) (zerolog.Logger, error) {
	level, err := zerolog.ParseLevel(cfg.Level)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	var output io.Writer
	switch cfg.Output {
	case "stdout":
		output = os.Stdout
	case "stderr":
		output = os.Stderr
	case "file":
		output = os.Stderr
	default:
		output = os.Stderr
	}

	var logger zerolog.Logger
	switch cfg.Format {
	case "json":
		logger = zerolog.New(output).With().Timestamp().Logger()
	case "console":
		logger = zerolog.New(zerolog.ConsoleWriter{
			Out:        output,
			TimeFormat: "15:04:05",
			NoColor:    isNoColor(),
		}).With().Timestamp().Logger()
	default:
		logger = zerolog.New(zerolog.ConsoleWriter{
			Out:        output,
			TimeFormat: "15:04:05",
			NoColor:    isNoColor(),
		}).With().Timestamp().Logger()
	}

	return logger, nil
}

func isNoColor() bool {
	return os.Getenv("NO_COLOR") != "" ||
		os.Getenv("TERM") == "dumb" ||
		!strings.Contains(os.Getenv("TERM"), "color")
}
