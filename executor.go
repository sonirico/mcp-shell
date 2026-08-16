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

type CommandExecutor struct {
	config   SecurityConfig
	logger   zerolog.Logger
	unfurler *commandUnfurler
}

func newCommandExecutor(cfg SecurityConfig, logger zerolog.Logger) *CommandExecutor {
	return &CommandExecutor{
		config:   cfg,
		logger:   logger.With().Str("component", "executor").Logger(),
		unfurler: newCommandUnfurler(),
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
		// Secure execution: parse the command into a literal argv and execute it
		// directly, using the same unfurler the validator used.
		res := e.unfurler.unfurl(command)
		if !res.Allowed {
			return nil, fmt.Errorf("command parsing failed: %s", res.Reason)
		}

		e.logger.Debug().
			Str("executable", res.Argv[0]).
			Strs("args", res.Argv[1:]).
			Msg("Executing command with direct execution")

		cmd = exec.CommandContext(ctx, res.Argv[0], res.Argv[1:]...)
	}

	if e.config.WorkingDirectory != "" {
		if err := os.MkdirAll(e.config.WorkingDirectory, 0o755); err != nil {
			return nil, fmt.Errorf("create working directory %q: %w", e.config.WorkingDirectory, err)
		}
		cmd.Dir = e.config.WorkingDirectory
		e.logger.Debug().
			Str("working_dir", e.config.WorkingDirectory).
			Msg("Set working directory")
	}

	if e.config.RunAsUser != "" {
		u, err := user.Lookup(e.config.RunAsUser)
		if err != nil {
			return nil, fmt.Errorf("resolve run-as user %q: %w", e.config.RunAsUser, err)
		}
		uid, err := strconv.Atoi(u.Uid)
		if err != nil {
			return nil, fmt.Errorf("resolve run-as user %q: parse uid %q: %w", e.config.RunAsUser, u.Uid, err)
		}
		gid, err := strconv.Atoi(u.Gid)
		if err != nil {
			return nil, fmt.Errorf("resolve run-as user %q: parse gid %q: %w", e.config.RunAsUser, u.Gid, err)
		}
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

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()

	if e.config.MaxOutputSize > 0 {
		if stdoutBuf.Len() > e.config.MaxOutputSize {
			return nil, fmt.Errorf("stdout exceeds maximum size limit")
		}
		if stderrBuf.Len() > e.config.MaxOutputSize {
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
