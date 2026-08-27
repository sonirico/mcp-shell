package main

import (
	"context"
	"os"
	"os/exec"
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

func TestCommandExecutor_childEnvIsMinimal(t *testing.T) {
	logger := zerolog.New(zerolog.NewTestWriter(t))
	ctx := context.Background()

	// A secret in the server's own environment must not reach the child, or an
	// allowlisted reader (`env`, `cat /proc/self/environ`) exfiltrates it.
	t.Setenv("MCP_SHELL_TEST_SECRET", "leaked-secret-value")

	config := SecurityConfig{MaxExecutionTime: 5 * time.Second}
	executor := newCommandExecutor(config, logger)

	result, err := executor.executeSecureCommand(ctx, "env", false)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotContains(t, result.Stdout, "leaked-secret-value")
	assert.NotContains(t, result.Stdout, "MCP_SHELL_TEST_SECRET")
}

func TestCommandExecutor_gitRepoConfigIsNeutralised(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	logger := zerolog.New(zerolog.NewTestWriter(t))
	ctx := context.Background()

	repo := t.TempDir()
	sentinel := filepath.Join(t.TempDir(), "git-pwned")
	hook := filepath.Join(repo, "evil.sh")
	require.NoError(t, os.WriteFile(hook, []byte("#!/bin/sh\ntouch "+sentinel+"\n"), 0o755))

	runGit := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, out)
	}
	runGit("init")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "a.txt"), []byte("one\n"), 0o644))
	runGit("add", "a.txt")
	runGit("commit", "-m", "init")
	// Every repo-local vector git reads from the filesystem instead of argv:
	// fsmonitor (status), diff.external and per-path textconv (diff/show/log -p).
	runGit("config", "core.fsmonitor", hook)
	runGit("config", "diff.external", hook)
	require.NoError(t, os.WriteFile(filepath.Join(repo, ".gitattributes"), []byte("a.txt diff=evil\n"), 0o644))
	runGit("config", "diff.evil.textconv", hook)
	require.NoError(t, os.WriteFile(filepath.Join(repo, "a.txt"), []byte("two\n"), 0o644))
	runGit("add", "a.txt", ".gitattributes")
	runGit("commit", "-m", "second")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "a.txt"), []byte("three\n"), 0o644))

	config := SecurityConfig{WorkingDirectory: repo, MaxExecutionTime: 5 * time.Second}
	executor := newCommandExecutor(config, logger)

	// None of these read-only commands may run the repo-configured program.
	for _, command := range []string{"git status", "git diff", "git show", "git log -p"} {
		t.Run(command, func(t *testing.T) {
			require.NoError(t, os.RemoveAll(sentinel))
			_, err := executor.executeSecureCommand(ctx, command, false)
			require.NoError(t, err)
			assert.NoFileExists(t, sentinel, "%q must not run a repo-configured program", command)
		})
	}

	// The hardening must not break ordinary read-only output.
	t.Run("git log --oneline still works", func(t *testing.T) {
		result, err := executor.executeSecureCommand(ctx, "git log --oneline", false)
		require.NoError(t, err)
		assert.Equal(t, "success", result.Status)
		assert.Contains(t, result.Stdout, "second")
	})
}

func TestCommandExecutor_outputCapStopsRunawayOutput(t *testing.T) {
	logger := zerolog.New(zerolog.NewTestWriter(t))
	ctx := context.Background()

	config := SecurityConfig{MaxOutputSize: 1024, MaxExecutionTime: 30 * time.Second}
	executor := newCommandExecutor(config, logger)

	start := time.Now()
	_, err := executor.executeSecureCommand(ctx, "cat /dev/zero", false)
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum size limit")
	// The overflow must stop the child promptly, not run out MaxExecutionTime
	// while /dev/zero fills memory.
	assert.Less(t, elapsed, 10*time.Second)
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
