package main

import (
	"context"
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
				assert.NotNil(t, result)
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

	// Test with legacy execution (vulnerable - allows these)
	t.Run("legacy_execution_allows_vulnerabilities", func(t *testing.T) {
		config := SecurityConfig{
			UseShellExecution: true,
			MaxExecutionTime:  time.Second * 5,
		}
		executor := newCommandExecutor(config, logger)

		for _, vt := range vulnerabilityTests {
			t.Run(vt.name, func(t *testing.T) {
				// Note: We don't actually want these to succeed in tests,
				// but we verify they reach the execution stage (not blocked by parsing)
				_, err := executor.executeSecureCommand(ctx, vt.command, false)
				// These may fail due to actual command execution, but should not fail due to parsing
				if err != nil {
					assert.NotContains(t, err.Error(), "shell metacharacters",
						"Legacy mode should not block based on metacharacters")
					assert.NotContains(t, err.Error(), "command parsing failed",
						"Legacy mode should not fail at parsing stage")
				}
			})
		}
	})
}
