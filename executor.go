package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
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
	if e.config.UseShellExecution {
		return e.runShell(ctx, command, useBase64)
	}

	res := e.unfurler.unfurl(command)
	if !res.Allowed {
		return nil, fmt.Errorf("command parsing failed: %s", res.Reason)
	}

	return e.run(ctx, res.Argv, useBase64)
}

// run execs argv[0] directly, never parsing a string into a shell. git
// invocations get the hardening -c overrides inserted first.
func (e *CommandExecutor) run(
	ctx context.Context,
	argv []string,
	useBase64 bool,
) (*ExecutionResult, error) {
	start := time.Now()
	label := strings.Join(argv, " ")

	e.logger.Info().
		Str("command", label).
		Bool("base64", useBase64).
		Msg("Executing command")

	timeout := 30 * time.Second
	if e.config.MaxExecutionTime > 0 {
		timeout = e.config.MaxExecutionTime
	}
	cmdCtx, cancelTimeout := context.WithTimeout(ctx, timeout)
	defer cancelTimeout()

	// A cancellable context lets a capped output buffer stop the child the moment
	// it overflows, instead of letting it fill memory until MaxExecutionTime.
	cmdCtx, cancel := context.WithCancel(cmdCtx)
	defer cancel()

	execArgv := argv
	if filepath.Base(argv[0]) == "git" {
		execArgv = hardenGitArgv(argv)
	}

	e.logger.Debug().
		Str("executable", execArgv[0]).
		Strs("args", execArgv[1:]).
		Msg("Executing command with direct execution")

	cmd := exec.CommandContext(cmdCtx, execArgv[0], execArgv[1:]...)
	cmd.Env = secureChildEnv(execArgv[0])

	result, err := e.runCommand(cmd, cancel, label, useBase64)
	if err != nil {
		return nil, err
	}

	return e.finish(start, result, label), nil
}

// runShell execs bash -c command, interpreting shell metacharacters. It is
// the legacy execution mode and inherits the server's own environment.
func (e *CommandExecutor) runShell(
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
	cmdCtx, cancelTimeout := context.WithTimeout(ctx, timeout)
	defer cancelTimeout()

	// A cancellable context lets a capped output buffer stop the child the moment
	// it overflows, instead of letting it fill memory until MaxExecutionTime.
	cmdCtx, cancel := context.WithCancel(cmdCtx)
	defer cancel()

	e.logger.Warn().
		Str("command", command).
		Msg("Using legacy shell execution mode - vulnerable to injection attacks")
	cmd := exec.CommandContext(cmdCtx, "bash", "-c", command)

	result, err := e.runCommand(cmd, cancel, command, useBase64)
	if err != nil {
		return nil, err
	}

	return e.finish(start, result, command), nil
}

// runCommand applies the shared process setup - working directory, run-as
// user, capped output buffers, execution and exit-code/status mapping - to a
// prepared *exec.Cmd. cancel is the cmd's own context cancel func, used to
// stop the child promptly on output overflow.
func (e *CommandExecutor) runCommand(
	cmd *exec.Cmd,
	cancel context.CancelFunc,
	command string,
	useBase64 bool,
) (*ExecutionResult, error) {
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

	stdoutBuf := &cappedBuffer{max: e.config.MaxOutputSize, cancel: cancel}
	stderrBuf := &cappedBuffer{max: e.config.MaxOutputSize, cancel: cancel}
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf

	err := cmd.Run()

	if stdoutBuf.overflowed {
		return nil, fmt.Errorf("stdout exceeds maximum size limit")
	}
	if stderrBuf.overflowed {
		return nil, fmt.Errorf("stderr exceeds maximum size limit")
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

// finish applies the execution time, SecurityInfo and completion log shared
// by run and runShell to a successfully produced result.
func (e *CommandExecutor) finish(start time.Time, result *ExecutionResult, label string) *ExecutionResult {
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
		Str("command", label).
		Str("status", result.Status).
		Int("exit_code", result.ExitCode).
		Dur("execution_time", result.ExecutionTime).
		Msg("Command execution completed")

	return result
}

// cappedBuffer collects command output up to max bytes. On the first write that
// would exceed max it keeps the prefix that fits, records the overflow and
// cancels the command's context so the child is stopped rather than left filling
// memory. A max of 0 means unbounded. Each buffer is written by a single
// os/exec copy goroutine; cancel is safe to call concurrently and more than once.
type cappedBuffer struct {
	buf        bytes.Buffer
	max        int
	cancel     context.CancelFunc
	overflowed bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.max > 0 {
		if c.overflowed {
			return len(p), nil
		}
		if c.buf.Len()+len(p) > c.max {
			if remaining := c.max - c.buf.Len(); remaining > 0 {
				c.buf.Write(p[:remaining])
			}
			c.overflowed = true
			if c.cancel != nil {
				c.cancel()
			}
			return len(p), nil
		}
	}
	return c.buf.Write(p)
}

func (c *cappedBuffer) Bytes() []byte  { return c.buf.Bytes() }
func (c *cappedBuffer) String() string { return c.buf.String() }

// secureChildEnv builds the minimal environment for a validated child. The
// server's own environment is never inherited, so an allowlisted reader
// (cat /proc/self/environ, env) cannot exfiltrate secrets the MCP client or a
// loaded .env put there. git additionally gets its system and global config
// neutralised; repo-local config is handled by hardenGitArgv.
func secureChildEnv(executable string) []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"LANG=C",
	}
	if filepath.Base(executable) == "git" {
		env = append(env,
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL=/dev/null",
		)
	}
	return env
}

// gitHardeningFlags are server-supplied -c overrides inserted right after the
// git executable. core.fsmonitor runs an arbitrary program during
// status/diff/ls-files and is disabled here; core.pager runs its value as a
// command and is pinned to cat. The git argument policy rejects caller-supplied
// -c, so these cannot be spoofed. Repo config an -c override cannot neutralise
// (diff.external, per-path textconv drivers) is handled per-subcommand below.
var gitHardeningFlags = []string{
	"-c", "core.fsmonitor=false",
	"-c", "core.pager=cat",
}

// gitDiffSuppressionFlags maps a git subcommand that can run a repo-configured
// diff or textconv program to the flags that disable them. They are inserted
// right after the subcommand token so a hostile repository's diff.external or
// textconv driver cannot execute during an otherwise read-only command. An
// empty diff.external cannot be set via -c (it breaks diff instead), so the
// per-subcommand --no-ext-diff flag is the only reliable off switch. blame
// rejects --no-ext-diff and does not run an external diff, so it takes only
// --no-textconv.
var gitDiffSuppressionFlags = map[string][]string{
	"log":         {"--no-ext-diff", "--no-textconv"},
	"diff":        {"--no-ext-diff", "--no-textconv"},
	"show":        {"--no-ext-diff", "--no-textconv"},
	"whatchanged": {"--no-ext-diff", "--no-textconv"},
	"blame":       {"--no-textconv"},
}

// hardenGitArgv inserts the global -c overrides after the git executable and the
// per-subcommand diff-suppression flags right after the subcommand token (the
// first non-flag argument). User arguments keep their order and position, so a
// trailing "-- <pathspec>" is unaffected.
func hardenGitArgv(argv []string) []string {
	hardened := make([]string, 0, len(argv)+len(gitHardeningFlags)+2)
	hardened = append(hardened, argv[0])
	hardened = append(hardened, gitHardeningFlags...)
	for i, tok := range argv[1:] {
		hardened = append(hardened, tok)
		if !strings.HasPrefix(tok, "-") {
			hardened = append(hardened, gitDiffSuppressionFlags[tok]...)
			hardened = append(hardened, argv[1+i+1:]...)
			break
		}
	}
	return hardened
}
