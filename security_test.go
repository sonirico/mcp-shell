package main

import (
	"os"
	"path/filepath"
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
			// blocked_commands is matched against the resolved argv, so a split
			// quote that rebuilds the same argv cannot evade it.
			name: "secure mode blocked_commands - split-quote evasion is caught on argv",
			config: SecurityConfig{
				Enabled:            true,
				UseShellExecution:  false,
				AllowedExecutables: []string{"cat"},
				BlockedCommands:    []string{"/etc/passwd"},
			},
			command:       `cat /etc/pass"wd"`,
			expectError:   true,
			errorContains: "blocked keyword",
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
		// Issue #7: blocked_patterns in secure mode. The command must pass the
		// per-tool arg policy first (git log --oneline is allowed) so that the
		// operator-configured pattern is what rejects it.
		{
			name: "secure mode with blocked_patterns - operator pattern blocks allowed command",
			config: SecurityConfig{
				Enabled:            true,
				UseShellExecution:  false,
				AllowedExecutables: []string{"git"},
				BlockedPatterns:    []string{`(^|\s)--oneline(\s|$)`},
			},
			command:       "git log --oneline",
			expectError:   true,
			errorContains: "blocked pattern",
		},
		{
			name: "secure mode with blocked_patterns - allows git status",
			config: SecurityConfig{
				Enabled:            true,
				UseShellExecution:  false,
				AllowedExecutables: []string{"git"},
				BlockedPatterns:    []string{`(^|\s)remote\s+(-v|--verbose)(\s|$)`},
			},
			command:     "git status",
			expectError: false,
		},
		{
			name: "secure mode with blocked_commands - blocks flagged args of allowed ls",
			config: SecurityConfig{
				Enabled:            true,
				UseShellExecution:  false,
				AllowedExecutables: []string{"ls"},
				BlockedCommands:    []string{"-la"},
			},
			command:       "ls -la /tmp",
			expectError:   true,
			errorContains: "blocked keyword",
		},
		// GHSA-gg85-6grh-63fp follow-through: an allowlisted executable that is
		// neither data-only nor policy-governed (rm) is rejected at
		// classification, before blocked_commands even applies.
		{
			name: "secure mode rejects unclassified rm despite allowlist entry",
			config: SecurityConfig{
				Enabled:            true,
				UseShellExecution:  false,
				AllowedExecutables: []string{"ls", "rm"},
			},
			command:       "rm -rf /tmp",
			expectError:   true,
			errorContains: "not classified as safe",
		},
		// GHSA-74hp-mggr-hv58: git shell-alias bypass via `-c alias.x=!cmd`.
		// Now caught by the per-tool git argument policy, not metacharacters.
		{
			name: "secure mode blocks git shell-alias injection",
			config: SecurityConfig{
				Enabled:            true,
				UseShellExecution:  false,
				AllowedExecutables: []string{"git"},
			},
			command:       "git -c alias.pwn=!touch pwn /tmp/target",
			expectError:   true,
			errorContains: "config injection",
		},
		// GHSA-3x77-wg38-92r3: an interpreter still has to be in the allowlist
		// to be reachable; bash absent from the list is rejected outright.
		{
			name: "secure mode blocks bash -c when bash not allowlisted",
			config: SecurityConfig{
				Enabled:            true,
				UseShellExecution:  false,
				AllowedExecutables: []string{"ls", "echo"},
			},
			command:       "/bin/bash -c id",
			expectError:   true,
			errorContains: "not in allowed list",
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
		name               string
		allowedExecutables []string
		command            string
		expectError        bool
		errorContains      string
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
		// GHSA-gg85-6grh-63fp: command-wrapper utilities (env, timeout, nice, ...)
		// run an arbitrary command taken from a literal argument. Allowlisting one
		// must not grant it execution: only executables classified as data-only or
		// governed by an argument policy are accepted.
		{
			name:               "wrapper env is rejected even when allowlisted",
			allowedExecutables: []string{"env", "cat"},
			command:            "env touch /tmp/pwned",
			expectError:        true,
			errorContains:      "not classified as safe",
		},
		{
			name:               "wrapper timeout is rejected even when allowlisted",
			allowedExecutables: []string{"timeout"},
			command:            "timeout 5 touch /tmp/pwned",
			expectError:        true,
			errorContains:      "not classified as safe",
		},
		{
			name:               "wrapper nice is rejected even when allowlisted",
			allowedExecutables: []string{"nice"},
			command:            "nice touch /tmp/pwned",
			expectError:        true,
			errorContains:      "not classified as safe",
		},
		{
			name:               "unclassified allowlisted executable is rejected",
			allowedExecutables: []string{"rsync"},
			command:            "rsync a b",
			expectError:        true,
			errorContains:      "not classified as safe",
		},
		{
			// tar is no longer classified: -f names an arbitrary write path in any
			// create/extract mode, so allowlisting it must not grant execution.
			name:               "tar is rejected as unclassified",
			allowedExecutables: []string{"tar"},
			command:            "tar -cf /home/user/.bashrc x",
			expectError:        true,
			errorContains:      "not classified as safe",
		},
		{
			name:               "data-only executable in allowlist still passes",
			allowedExecutables: []string{"cat"},
			command:            "cat /etc/hostname",
			expectError:        false,
		},
		{
			name:               "policy-governed executable in allowlist still passes",
			allowedExecutables: []string{"git"},
			command:            "git status",
			expectError:        false,
		},
		{
			name:               "whitespace only command",
			allowedExecutables: []string{"ls"},
			command:            "   ",
			expectError:        true,
			errorContains:      "empty command",
		},
		// A relative argv[0] with a separator is existence-checked against the
		// server CWD but executed relative to WorkingDirectory, so validation and
		// execution can resolve different files. Reject it outright.
		{
			name:               "relative executable with leading dot is rejected",
			allowedExecutables: []string{"ls"},
			command:            "./ls -la",
			expectError:        true,
			errorContains:      "relative executable",
		},
		{
			name:               "relative executable in subdir is rejected",
			allowedExecutables: []string{"ls"},
			command:            "sub/dir/ls",
			expectError:        true,
			errorContains:      "relative executable",
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
	// Not parallel: uses t.Setenv to control PATH so the basename-in-PATH
	// branch is hermetic instead of depending on whatever the host has installed.
	logger := zerolog.New(zerolog.NewTestWriter(t))
	validator := newSecurityValidator(SecurityConfig{}, logger)

	// A real executable in a controlled PATH: exec.LookPath must resolve it.
	binDir := t.TempDir()
	toolPath := filepath.Join(binDir, "mytool")
	require.NoError(t, os.WriteFile(toolPath, []byte("#!/bin/sh\nexit 0\n"), 0o755))
	t.Setenv("PATH", binDir)

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
			executable: toolPath,
			pattern:    toolPath,
			expected:   true,
		},
		{
			name:       "absolute path pattern mismatch",
			executable: "/usr/bin/git",
			pattern:    "/bin/git",
			expected:   false,
		},
		{
			name:       "basename match resolves via PATH",
			executable: "mytool",
			pattern:    "mytool",
			expected:   true,
		},
		{
			name:       "basename not on PATH does not match",
			executable: "./definitely_absent_zzz",
			pattern:    "definitely_absent_zzz",
			expected:   false,
		},
		{
			name:       "absolute executable vs basename pattern no match",
			executable: toolPath,
			pattern:    "mytool",
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
		name          string
		config        SecurityConfig
		command       string
		expectError   bool
		errorContains string
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
					// Any of these messages indicates the command was blocked.
					errorMsg := err.Error()
					shouldContainOne := strings.Contains(errorMsg, "not in allowed list") ||
						strings.Contains(errorMsg, "rejected in secure mode")
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
