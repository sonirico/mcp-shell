package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"
)

type ExecutionResult struct {
	Status        string        `json:"status"`
	ExitCode      int           `json:"exit_code"`
	Stdout        string        `json:"stdout"`
	Stderr        string        `json:"stderr"`
	Command       string        `json:"command"`
	ExecutionTime time.Duration `json:"execution_time"`
	SecurityInfo  *SecurityInfo `json:"security_info,omitempty"`
}

type SecurityInfo struct {
	SecurityEnabled bool   `json:"security_enabled"`
	WorkingDir      string `json:"working_dir,omitempty"`
	RunAsUser       string `json:"run_as_user,omitempty"`
	TimeoutApplied  bool   `json:"timeout_applied"`
}

type CommandExecutor struct {
	config SecurityConfig
	logger zerolog.Logger
}

func newCommandExecutor(cfg SecurityConfig, logger zerolog.Logger) *CommandExecutor {
	return &CommandExecutor{
		config: cfg,
		logger: logger.With().Str("component", "executor").Logger(),
	}
}

func (e *CommandExecutor) execute(
	ctx context.Context,
	command string,
	useBase64 bool,
) (*ExecutionResult, error) {
	start := time.Now()

	e.logger.Info().
		Str("command", command).
		Bool("base64", useBase64).
		Msg("Executing command")

	timeout := 30 * time.Second
	if e.config.MaxExecutionTime > 0 {
		timeout = e.config.MaxExecutionTime
	}

	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result, err := e.executeSecureCommand(cmdCtx, command, useBase64)
	if err != nil {
		e.logger.Error().
			Err(err).
			Str("command", command).
			Msg("Command execution failed")
		return nil, err
	}

	result.ExecutionTime = time.Since(start)
	result.SecurityInfo = &SecurityInfo{
		SecurityEnabled: e.config.Enabled,
		TimeoutApplied:  true,
	}

	if e.config.WorkingDirectory != "" {
		result.SecurityInfo.WorkingDir = e.config.WorkingDirectory
	}
	if e.config.RunAsUser != "" {
		result.SecurityInfo.RunAsUser = e.config.RunAsUser
	}

	e.logger.Info().
		Str("command", command).
		Str("status", result.Status).
		Int("exit_code", result.ExitCode).
		Dur("execution_time", result.ExecutionTime).
		Msg("Command execution completed")

	return result, nil
}

// parseCommand securely parses a command string into executable and arguments
// without using shell interpretation. This prevents command injection through
// shell metacharacters and substitution.
func (e *CommandExecutor) parseCommand(command string) (string, []string, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return "", nil, fmt.Errorf("empty command")
	}

	// Simple whitespace-based splitting - no shell interpretation
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return "", nil, fmt.Errorf("no command found")
	}

	executable := parts[0]
	args := parts[1:]

	// Validate that the executable doesn't contain shell metacharacters
	if containsShellMetacharacters(executable) {
		return "", nil, fmt.Errorf("executable contains shell metacharacters: %s", executable)
	}

	// Validate arguments don't contain dangerous shell constructs
	// In secure mode, this should be an error, not just a warning
	for _, arg := range args {
		if containsDangerousShellConstructs(arg) {
			return "", nil, fmt.Errorf("argument contains dangerous shell constructs: %s", arg)
		}
	}

	return executable, args, nil
}

func (e *CommandExecutor) executeSecureCommand(
	ctx context.Context,
	command string,
	useBase64 bool,
) (*ExecutionResult, error) {
	var cmd *exec.Cmd

	// Use secure execution unless legacy shell mode is explicitly enabled
	if e.config.UseShellExecution {
		e.logger.Warn().
			Str("command", command).
			Msg("Using legacy shell execution mode - vulnerable to injection attacks")
		cmd = exec.CommandContext(ctx, "bash", "-c", command)
	} else {
		// Secure execution: parse command and execute directly
		executable, args, err := e.parseCommand(command)
		if err != nil {
			e.logger.Error().
				Err(err).
				Str("command", command).
				Msg("Failed to parse command securely")
			return nil, fmt.Errorf("command parsing failed: %w", err)
		}

		e.logger.Debug().
			Str("executable", executable).
			Strs("args", args).
			Msg("Executing command with direct execution")

		cmd = exec.CommandContext(ctx, executable, args...)
	}

	if e.config.WorkingDirectory != "" {
		if err := os.MkdirAll(e.config.WorkingDirectory, 0755); err == nil {
			cmd.Dir = e.config.WorkingDirectory
			e.logger.Debug().
				Str("working_dir", e.config.WorkingDirectory).
				Msg("Set working directory")
		}
	}

	if e.config.RunAsUser != "" {
		if u, err := user.Lookup(e.config.RunAsUser); err == nil {
			if uid, err := strconv.Atoi(u.Uid); err == nil {
				if gid, err := strconv.Atoi(u.Gid); err == nil {
					cmd.SysProcAttr = &syscall.SysProcAttr{
						Credential: &syscall.Credential{
							Uid: uint32(uid),
							Gid: uint32(gid),
						},
					}
					e.logger.Debug().
						Str("user", e.config.RunAsUser).
						Int("uid", uid).
						Int("gid", gid).
						Msg("Set process credentials")
				}
			}
		}
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()

	if e.config.MaxOutputSize > 0 {
		if stdoutBuf.Len() > e.config.MaxOutputSize {
			e.logger.Warn().
				Int("stdout_size", stdoutBuf.Len()).
				Int("max_size", e.config.MaxOutputSize).
				Msg("Stdout exceeds maximum size limit")
			return nil, fmt.Errorf("stdout exceeds maximum size limit")
		}
		if stderrBuf.Len() > e.config.MaxOutputSize {
			e.logger.Warn().
				Int("stderr_size", stderrBuf.Len()).
				Int("max_size", e.config.MaxOutputSize).
				Msg("Stderr exceeds maximum size limit")
			return nil, fmt.Errorf("stderr exceeds maximum size limit")
		}
	}

	exitCode := 0
	status := "success"
	if err != nil {
		status = "error"
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = -1
		}
	}

	var stdout, stderr string
	if useBase64 {
		stdout = base64.StdEncoding.EncodeToString(stdoutBuf.Bytes())
		stderr = base64.StdEncoding.EncodeToString(stderrBuf.Bytes())
	} else {
		stdout = strings.TrimRight(stdoutBuf.String(), "\n")
		stderr = strings.TrimRight(stderrBuf.String(), "\n")
	}

	return &ExecutionResult{
		Status:   status,
		ExitCode: exitCode,
		Stdout:   stdout,
		Stderr:   stderr,
		Command:  command,
	}, nil
}
