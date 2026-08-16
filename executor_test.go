package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommandExecutor_executeSecureCommand_secure_vs_legacy(t *testing.T) {
	logger := zerolog.New(zerolog.NewTestWriter(t))
	ctx := context.Background()

	tests := []struct {
		name              string
		command           string
		useShellExecution bool
		expectError       bool
		errorContains     string
	}{
		{
			name:              "safe command - secure mode",
			command:           "echo hello",
			useShellExecution: false,
			expectError:       false,
		},
		{
			name:              "safe command - legacy mode",
			command:           "echo hello",
			useShellExecution: true,
			expectError:       false,
		},
		{
			name:              "command with pipe - secure mode blocks",
			command:           "echo hello | cat",
			useShellExecution: false,
			expectError:       true,
			errorContains:     "command parsing failed",
		},
		{
			name:              "command with pipe - legacy mode allows",
			command:           "echo hello | cat",
			useShellExecution: true,
			expectError:       false,
		},
		{
			name:              "command substitution - secure mode blocks",
			command:           "echo $(whoami)",
			useShellExecution: false,
			expectError:       true,
			errorContains:     "command parsing failed",
		},
		{
			name:              "command substitution - legacy mode allows",
			command:           "echo $(whoami)",
			useShellExecution: true,
			expectError:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := SecurityConfig{
				UseShellExecution: tt.useShellExecution,
				MaxExecutionTime:  time.Second * 5,
			}
			executor := newCommandExecutor(config, logger)

			result, err := executor.executeSecureCommand(ctx, tt.command, false)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, "success", result.Status)
				assert.Equal(t, 0, result.ExitCode)
			}
		})
	}
}

func TestCommandExecutor_vulnerability_prevention(t *testing.T) {
	logger := zerolog.New(zerolog.NewTestWriter(t))
	ctx := context.Background()

	// These are actual injection payloads that should be blocked
	vulnerabilityTests := []struct {
		name        string
		command     string
		description string
	}{
		{
			name:        "VULN.md example - obfuscated chmod",
			command:     "echo $($(echo -n c; echo -n h; echo -n m; echo -n o; echo -n d))",
			description: "Command substitution to reconstruct 'chmod' command",
		},
		{
			name:        "command injection via semicolon",
			command:     "ls; rm -rf /",
			description: "Command separator to execute dangerous command",
		},
		{
			name:        "command injection via pipe",
			command:     "echo safe | rm -rf /",
			description: "Pipe to execute dangerous command",
		},
		{
			name:        "command injection via background",
			command:     "echo safe & rm -rf /",
			description: "Background execution to hide dangerous command",
		},
		{
			name:        "variable expansion injection",
			command:     "echo ${IFS}rm${IFS}-rf${IFS}/",
			description: "Using IFS variable to obfuscate dangerous command",
		},
		{
			name:        "backtick command substitution",
			command:     "echo `rm -rf /`",
			description: "Backtick command substitution for injection",
		},
	}

	// Test with secure execution (should block all)
	t.Run("secure_execution_blocks_vulnerabilities", func(t *testing.T) {
		config := SecurityConfig{
			UseShellExecution: false,
			MaxExecutionTime:  time.Second * 5,
		}
		executor := newCommandExecutor(config, logger)

		for _, vt := range vulnerabilityTests {
			t.Run(vt.name, func(t *testing.T) {
				_, err := executor.executeSecureCommand(ctx, vt.command, false)
				assert.Error(t, err, "Secure execution should block: %s", vt.description)
			})
		}
	})

	// Legacy mode interprets shell metacharacters instead of rejecting them at
	// the parse stage. Prove that with BENIGN meta commands - never run a
	// destructive payload against the real filesystem to demonstrate it.
	t.Run("legacy_execution_interprets_shell_metacharacters", func(t *testing.T) {
		config := SecurityConfig{
			UseShellExecution: true,
			MaxExecutionTime:  time.Second * 5,
		}
		executor := newCommandExecutor(config, logger)

		metaTests := []struct {
			name    string
			command string
			stdout  string
		}{
			{name: "list separator", command: "echo a && echo b", stdout: "a\nb"},
			{name: "arithmetic expansion", command: "echo $((3+4))", stdout: "7"},
			{name: "pipe", command: "printf abc | cat", stdout: "abc"},
		}

		for _, mt := range metaTests {
			t.Run(mt.name, func(t *testing.T) {
				result, err := executor.executeSecureCommand(ctx, mt.command, false)
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, "success", result.Status)
				assert.Equal(t, mt.stdout, result.Stdout)
			})
		}
	})
}

func TestCommandExecutor_failsClosedOnSetupErrors(t *testing.T) {
	logger := zerolog.New(zerolog.NewTestWriter(t))
	ctx := context.Background()

	t.Run("unresolvable run-as user returns error", func(t *testing.T) {
		config := SecurityConfig{
			RunAsUser:        "nonexistent_user_zzz_123",
			MaxExecutionTime: time.Second * 5,
		}
		executor := newCommandExecutor(config, logger)

		_, err := executor.executeSecureCommand(ctx, "echo hi", false)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "resolve run-as user")
	})

	t.Run("uncreatable working directory returns error", func(t *testing.T) {
		// A regular file cannot be a parent directory, so MkdirAll under it fails.
		blocker := filepath.Join(t.TempDir(), "afile")
		require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o644))
		config := SecurityConfig{
			WorkingDirectory: filepath.Join(blocker, "sub"),
			MaxExecutionTime: time.Second * 5,
		}
		executor := newCommandExecutor(config, logger)

		_, err := executor.executeSecureCommand(ctx, "echo hi", false)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "create working directory")
	})

	t.Run("output exceeding max size returns error", func(t *testing.T) {
		config := SecurityConfig{
			MaxOutputSize:    1,
			MaxExecutionTime: time.Second * 5,
		}
		executor := newCommandExecutor(config, logger)

		_, err := executor.executeSecureCommand(ctx, "echo hello", false)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds maximum size limit")
	})
}
