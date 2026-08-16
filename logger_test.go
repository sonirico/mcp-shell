package main

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLogger(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  LoggingConfig
	}{
		{
			name: "json format, stdout output, valid level",
			cfg:  LoggingConfig{Level: "info", Format: "json", Output: "stdout"},
		},
		{
			name: "json format, stderr output, valid level",
			cfg:  LoggingConfig{Level: "debug", Format: "json", Output: "stderr"},
		},
		{
			name: "console format, stdout output, valid level",
			cfg:  LoggingConfig{Level: "warn", Format: "console", Output: "stdout"},
		},
		{
			name: "console format, file output falls back to stderr",
			cfg:  LoggingConfig{Level: "error", Format: "console", Output: "file"},
		},
		{
			name: "unknown format falls back to console",
			cfg:  LoggingConfig{Level: "info", Format: "unknown-format", Output: "stdout"},
		},
		{
			name: "unknown output falls back to stderr",
			cfg:  LoggingConfig{Level: "info", Format: "json", Output: "unknown-output"},
		},
		{
			name: "empty format falls back to console",
			cfg:  LoggingConfig{Level: "info", Format: "", Output: "stdout"},
		},
		{
			name: "empty output falls back to stderr",
			cfg:  LoggingConfig{Level: "info", Format: "json", Output: ""},
		},
		{
			name: "invalid level falls back to info without erroring",
			cfg:  LoggingConfig{Level: "not-a-real-level", Format: "json", Output: "stdout"},
		},
		{
			name: "empty level parses as NoLevel without erroring",
			cfg:  LoggingConfig{Level: "", Format: "console", Output: "stderr"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			cfg := tt.cfg

			// Act
			logger, err := newLogger(cfg)

			// Assert
			require.NoError(t, err)
			assert.NotPanics(t, func() {
				logger.Info().Msg("smoke test message")
				logger.Debug().Msg("smoke test message")
				logger.Error().Msg("smoke test message")
			})
		})
	}
}

func TestNewLogger_WritesJSONToConfiguredOutput(t *testing.T) {
	// Not parallel: this test swaps the process-wide os.Stdout to observe
	// what newLogger actually writes, which would race with sibling tests
	// that also invoke newLogger with Output "stdout".

	// Arrange
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() {
		os.Stdout = origStdout
	}()

	cfg := LoggingConfig{Level: "info", Format: "json", Output: "stdout"}

	// Act
	logger, err := newLogger(cfg)
	require.NoError(t, err)
	logger.Info().Str("key", "value").Msg("hello json")

	require.NoError(t, w.Close())
	os.Stdout = origStdout

	out, readErr := io.ReadAll(r)
	require.NoError(t, readErr)

	// Assert
	var decoded map[string]any
	line := strings.TrimSpace(string(out))
	require.NotEmpty(t, line)
	require.NoError(t, json.Unmarshal([]byte(line), &decoded))
	assert.Equal(t, "hello json", decoded["message"])
	assert.Equal(t, "value", decoded["key"])
	assert.Equal(t, "info", decoded["level"])
}

func TestNewLogger_WritesConsoleToConfiguredOutput(t *testing.T) {
	// Not parallel: swaps process-wide os.Stderr, same rationale as above.

	// Arrange
	origStderr := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w
	defer func() {
		os.Stderr = origStderr
	}()

	cfg := LoggingConfig{Level: "info", Format: "console", Output: "stderr"}

	// Act
	logger, err := newLogger(cfg)
	require.NoError(t, err)
	logger.Info().Msg("hello console")

	require.NoError(t, w.Close())
	os.Stderr = origStderr

	scanner := bufio.NewScanner(r)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	require.NoError(t, scanner.Err())

	// Assert
	require.NotEmpty(t, lines)
	assert.Contains(t, lines[0], "hello console")
}

func TestNewLogger_SetsGlobalLevel(t *testing.T) {
	// Not parallel: newLogger mutates the process-wide zerolog global level,
	// which would race against other tests asserting on it concurrently.

	tests := []struct {
		name          string
		level         string
		expectedLevel string
	}{
		{
			name:          "valid level is applied globally",
			level:         "warn",
			expectedLevel: "warn",
		},
		{
			name:          "invalid level falls back to info globally",
			level:         "totally-bogus",
			expectedLevel: "info",
		},
		{
			// zerolog.ParseLevel("") returns NoLevel with a nil error
			// (NoLevel's string form is ""), so logger.go's err-based
			// fallback to Info never triggers for an empty level string.
			name:          "empty level parses as NoLevel, not the info fallback",
			level:         "",
			expectedLevel: "",
		},
	}

	for _, tt := range tests {
		// Arrange
		cfg := LoggingConfig{Level: tt.level, Format: "json", Output: "stderr"}

		// Act
		_, err := newLogger(cfg)

		// Assert
		require.NoError(t, err)
		assert.Equal(t, tt.expectedLevel, zerolog.GlobalLevel().String())
	}
}

func TestIsNoColor(t *testing.T) {
	// Not parallel: subtests use t.Setenv, which is incompatible with any
	// t.Parallel call in this test's ancestry.

	tests := []struct {
		name     string
		noColor  string
		term     string
		expected bool
	}{
		{
			name:     "NO_COLOR set forces no color regardless of TERM",
			noColor:  "1",
			term:     "xterm-256color",
			expected: true,
		},
		{
			name:     "TERM dumb forces no color",
			noColor:  "",
			term:     "dumb",
			expected: true,
		},
		{
			name:     "TERM containing color and NO_COLOR unset allows color",
			noColor:  "",
			term:     "xterm-256color",
			expected: false,
		},
		{
			name:     "TERM without color substring forces no color",
			noColor:  "",
			term:     "xterm",
			expected: true,
		},
		{
			name:     "empty TERM forces no color",
			noColor:  "",
			term:     "",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Not parallel: t.Setenv is incompatible with t.Parallel.

			// Arrange
			t.Setenv("NO_COLOR", tt.noColor)
			t.Setenv("TERM", tt.term)

			// Act
			got := isNoColor()

			// Assert
			assert.Equal(t, tt.expected, got)
		})
	}
}
