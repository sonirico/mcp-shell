package main

import (
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecurityValidator_validateCommand(t *testing.T) {
	logger := zerolog.New(zerolog.NewTestWriter(t))

	tests := []struct {
		name          string
		config        SecurityConfig
		command       string
		expectError   bool
		errorContains string
	}{
		{
			name: "security disabled allows everything",
			config: SecurityConfig{
				Enabled: false,
			},
			command:     "rm -rf /",
			expectError: false,
		},
		{
			name: "secure mode with allowed executables - allows ls",
			config: SecurityConfig{
				Enabled:            true,
				UseShellExecution:  false,
				AllowedExecutables: []string{"ls", "pwd", "echo"},
			},
			command:     "ls -la",
			expectError: false,
		},
		{
			name: "secure mode with allowed executables - blocks rm",
			config: SecurityConfig{
				Enabled:            true,
				UseShellExecution:  false,
				AllowedExecutables: []string{"ls", "pwd", "echo"},
			},
			command:       "rm -rf /",
			expectError:   true,
			errorContains: "not in allowed list",
		},
		{
			name: "secure mode with no allowed executables - blocks everything",
			config: SecurityConfig{
				Enabled:           true,
				UseShellExecution: false,
			},
			command:       "echo hello",
			expectError:   true,
			errorContains: "no allowed executables configured",
		},
		{
			name: "legacy mode with allowed commands - allows echo",
			config: SecurityConfig{
				Enabled:           true,
				UseShellExecution: true,
				AllowedCommands:   []string{"echo", "ls"},
			},
			command:     "echo hello",
			expectError: false,
		},
		{
			name: "legacy mode with allowed commands - blocks rm",
			config: SecurityConfig{
				Enabled:           true,
				UseShellExecution: true,
				AllowedCommands:   []string{"echo", "ls"},
			},
			command:       "rm file",
			expectError:   true,
			errorContains: "not in allowed list",
		},
		{
			name: "legacy mode with blocked commands - blocks rm",
			config: SecurityConfig{
				Enabled:           true,
				UseShellExecution: true,
				BlockedCommands:   []string{"rm", "chmod", "sudo"},
			},
			command:       "rm file",
			expectError:   true,
			errorContains: "blocked keyword",
		},
		{
			name: "legacy mode with blocked patterns - blocks rm -rf",
			config: SecurityConfig{
				Enabled:           true,
				UseShellExecution: true,
				BlockedPatterns:   []string{"rm\\s+-rf", "sudo\\s+"},
			},
			command:       "rm -rf /tmp",
			expectError:   true,
			errorContains: "blocked pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := newSecurityValidator(tt.config, logger)
			err := validator.validateCommand(tt.command)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSecurityValidator_validateExecutableCommand(t *testing.T) {
	logger := zerolog.New(zerolog.NewTestWriter(t))

	tests := []struct {
		name              string
		allowedExecutables []string
		command           string
		expectError       bool
		errorContains     string
	}{
		{
			name:               "simple command in allowlist",
			allowedExecutables: []string{"ls", "pwd", "echo"},
			command:            "ls -la",
			expectError:        false,
		},
		{
			name:               "command not in allowlist",
			allowedExecutables: []string{"ls", "pwd", "echo"},
			command:            "rm file.txt",
			expectError:        true,
			errorContains:      "not in allowed list",
		},
		{
			name:               "absolute path exact match",
			allowedExecutables: []string{"/usr/bin/git", "/bin/ls"},
			command:            "/usr/bin/git status",
			expectError:        false,
		},
		{
			name:               "absolute path mismatch",
			allowedExecutables: []string{"/usr/bin/git"},
			command:            "/bin/git status",
			expectError:        true,
			errorContains:      "not in allowed list",
		},
		{
			name:               "empty command",
			allowedExecutables: []string{"ls"},
			command:            "",
			expectError:        true,
			errorContains:      "empty command",
		},
		{
			name:               "whitespace only command",
			allowedExecutables: []string{"ls"},
			command:            "   ",
			expectError:        true,
			errorContains:      "empty command",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := SecurityConfig{
				AllowedExecutables: tt.allowedExecutables,
			}
			validator := newSecurityValidator(config, logger)
			err := validator.validateExecutableCommand(tt.command)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSecurityValidator_matchesExecutable(t *testing.T) {
	logger := zerolog.New(zerolog.NewTestWriter(t))
	validator := newSecurityValidator(SecurityConfig{}, logger)

	tests := []struct {
		name       string
		executable string
		pattern    string
		expected   bool
	}{
		{
			name:       "exact match",
			executable: "ls",
			pattern:    "ls",
			expected:   true,
		},
		{
			name:       "no match",
			executable: "ls",
			pattern:    "rm",
			expected:   false,
		},
		{
			name:       "absolute path exact match",
			executable: "/usr/bin/git",
			pattern:    "/usr/bin/git",
			expected:   true,
		},
		{
			name:       "basename match for command in PATH",
			executable: "git",
			pattern:    "git",
			expected:   true, // This should work if git is in PATH
		},
		{
			name:       "absolute path vs basename no match",
			executable: "/usr/bin/git",
			pattern:    "git",
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.matchesExecutable(tt.executable, tt.pattern)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSecurityValidator_validateLegacyCommand(t *testing.T) {
	logger := zerolog.New(zerolog.NewTestWriter(t))

	tests := []struct {
		name            string
		config          SecurityConfig
		command         string
		expectError     bool
		errorContains   string
	}{
		{
			name: "no restrictions - allows everything",
			config: SecurityConfig{
				AllowedCommands: []string{},
				BlockedCommands: []string{},
				BlockedPatterns: []string{},
			},
			command:     "any command here",
			expectError: false,
		},
		{
			name: "blocked command keyword",
			config: SecurityConfig{
				BlockedCommands: []string{"rm", "chmod"},
			},
			command:       "rm -rf /",
			expectError:   true,
			errorContains: "blocked keyword",
		},
		{
			name: "blocked pattern match",
			config: SecurityConfig{
				BlockedPatterns: []string{"rm\\s+-rf"},
			},
			command:       "rm -rf /tmp",
			expectError:   true,
			errorContains: "blocked pattern",
		},
		{
			name: "allowed command prefix match",
			config: SecurityConfig{
				AllowedCommands: []string{"echo", "ls -"},
			},
			command:     "echo hello world",
			expectError: false,
		},
		{
			name: "command not in allowed list",
			config: SecurityConfig{
				AllowedCommands: []string{"echo", "ls"},
			},
			command:       "rm file",
			expectError:   true,
			errorContains: "not in allowed list",
		},
		{
			name: "complex injection attempt blocked by keyword",
			config: SecurityConfig{
				BlockedCommands: []string{"chmod"},
			},
			command:       "chmod 777 /etc/passwd",
			expectError:   true,
			errorContains: "blocked keyword",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := newSecurityValidator(tt.config, logger)
			err := validator.validateLegacyCommand(tt.command)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSecurityValidator_vulnerability_scenarios(t *testing.T) {
	logger := zerolog.New(zerolog.NewTestWriter(t))

	// Test scenarios based on the VULN.md report
	vulnerabilityPayloads := []struct {
		name        string
		command     string
		description string
	}{
		{
			name:        "VULN.md example",
			command:     "echo $($(echo -n c; echo -n h; echo -n m; echo -n o; echo -n d))",
			description: "Obfuscated chmod reconstruction",
		},
		{
			name:        "simple command injection",
			command:     "ls; rm -rf /",
			description: "Command separator injection",
		},
		{
			name:        "pipe injection",
			command:     "echo safe | rm dangerous",
			description: "Pipe-based command injection",
		},
		{
			name:        "background injection",
			command:     "echo safe & rm dangerous",
			description: "Background process injection",
		},
	}

	t.Run("secure_mode_blocks_all_vulnerabilities", func(t *testing.T) {
		config := SecurityConfig{
			Enabled:            true,
			UseShellExecution:  false,
			AllowedExecutables: []string{"echo", "ls"}, // Only safe commands
		}
		validator := newSecurityValidator(config, logger)

		for _, payload := range vulnerabilityPayloads {
			t.Run(payload.name, func(t *testing.T) {
				err := validator.validateCommand(payload.command)
				if err != nil {
					assert.Error(t, err, "Secure mode should block: %s", payload.description)
					// Check for either error message since they both indicate blocking
					errorMsg := err.Error()
					shouldContainOne := strings.Contains(errorMsg, "not in allowed list") ||
						strings.Contains(errorMsg, "shell metacharacters") ||
						strings.Contains(errorMsg, "dangerous shell constructs")
					assert.True(t, shouldContainOne, "Error should indicate blocking: %s", errorMsg)
				} else {
					t.Errorf("Secure mode should block: %s", payload.description)
				}
			})
		}
	})

	t.Run("legacy_mode_with_proper_blocks", func(t *testing.T) {
		config := SecurityConfig{
			Enabled:           true,
			UseShellExecution: true,
			BlockedCommands:   []string{"rm", "chmod", "chown", "sudo"},
			BlockedPatterns:   []string{"rm\\s+-rf", "chmod\\s+"},
		}
		validator := newSecurityValidator(config, logger)

		// The VULN.md example demonstrates the vulnerability - obfuscated commands bypass keyword matching
		err := validator.validateCommand("echo $($(echo -n c; echo -n h; echo -n m; echo -n o; echo -n d))")
		// This should pass because "chmod" doesn't appear literally in the command
		assert.NoError(t, err, "Legacy mode cannot detect obfuscated commands")

		// But a simple rm should be blocked
		err = validator.validateCommand("rm file")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "blocked keyword")
	})

	t.Run("legacy_mode_vulnerable_without_proper_blocks", func(t *testing.T) {
		config := SecurityConfig{
			Enabled:           true,
			UseShellExecution: true,
			// No blocks configured - vulnerable
		}
		validator := newSecurityValidator(config, logger)

		// All payloads would pass validation (but still be dangerous)
		for _, payload := range vulnerabilityPayloads {
			t.Run(payload.name, func(t *testing.T) {
				err := validator.validateCommand(payload.command)
				assert.NoError(t, err, "Legacy mode without blocks allows: %s", payload.description)
			})
		}
	})
}
