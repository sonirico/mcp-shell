package main

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/rs/zerolog"
)

type SecurityValidator struct {
	config   SecurityConfig
	logger   zerolog.Logger
	unfurler *commandUnfurler
	policies *policySet
}

func newSecurityValidator(cfg SecurityConfig, logger zerolog.Logger) *SecurityValidator {
	v := &SecurityValidator{
		config:   cfg,
		logger:   logger.With().Str("component", "security").Logger(),
		unfurler: newCommandUnfurler(),
		policies: newDefaultPolicySet(),
	}
	v.warnOnUnclassified()
	return v
}

// warnOnUnclassified flags allowlisted executables that secure mode will
// reject anyway because they are neither data-only nor governed by an argument
// policy (GHSA-gg85-6grh-63fp: enumerating dangerous binaries is inherently
// incomplete, so unclassified means denied). The warning surfaces the dead
// allowlist entry at startup instead of failing every call silently.
func (v *SecurityValidator) warnOnUnclassified() {
	if !v.config.Enabled || v.config.UseShellExecution {
		return
	}
	for _, exe := range v.config.AllowedExecutables {
		if !v.isClassifiedExecutable(exe) {
			v.logger.Warn().
				Str("executable", exe).
				Msg("allowed executable is not classified as safe (no argument policy, not data-only) - secure mode will reject it")
		}
	}
}

// dataOnlyExecutables names utilities that transform or report data and
// nothing else: they cannot execute other programs and cannot write to a
// caller-chosen path. Executables outside this set need an argPolicy to run in
// secure mode; interpreters and command wrappers (env, timeout, nice, xargs,
// busybox, ...) are excluded by construction rather than enumerated.
var dataOnlyExecutables = newStringSet(
	"ls", "pwd", "whoami", "date", "echo", "printf",
	"cat", "grep", "wc", "head", "tail", "tr", "cut",
	"basename", "dirname", "realpath", "readlink", "stat", "du", "df",
	"uname", "id",
	"md5sum", "sha1sum", "sha256sum", "sha512sum", "base64",
)

// isClassifiedExecutable reports whether secure mode knows the executable to
// be safe: either data-only, or restricted by a per-tool argument policy.
func (v *SecurityValidator) isClassifiedExecutable(executable string) bool {
	return v.policies.governs(executable) || dataOnlyExecutables.has(filepath.Base(executable))
}

func (v *SecurityValidator) validateCommand(command string) error {
	if !v.config.Enabled {
		v.logger.Debug().Str("command", command).Msg("Security disabled, allowing command")
		return nil
	}

	v.logger.Debug().Str("command", command).Msg("Validating command")

	// If shell execution is disabled and we have allowed executables configured,
	// use the secure validation approach
	if !v.config.UseShellExecution && len(v.config.AllowedExecutables) > 0 {
		return v.validateExecutableCommand(command)
	}

	// Legacy validation for backwards compatibility
	if v.config.UseShellExecution {
		v.logger.Warn().
			Str("command", command).
			Msg("Using legacy shell execution mode - this is vulnerable to injection attacks")
		return v.validateLegacyCommand(command)
	}

	// If no allowed executables are configured but security is enabled,
	// block everything for safety
	if len(v.config.AllowedExecutables) == 0 {
		return fmt.Errorf("no allowed executables configured - all commands blocked for security")
	}

	return v.validateExecutableCommand(command)
}

// validateExecutableCommand validates commands using the secure executable
// allowlist approach. The command is parsed into an AST and accepted only if it
// is a single, fully-literal simple command (structural whitelist); the
// resolved argv is then checked against the executable allowlist, per-tool
// argument policies, and the blocked_patterns/blocked_commands filters.
func (v *SecurityValidator) validateExecutableCommand(command string) error {
	res := v.unfurler.unfurl(command)
	if !res.Allowed {
		return fmt.Errorf("command rejected in secure mode: %s", res.Reason)
	}

	executable := res.Argv[0]

	// A relative argv[0] with a path separator ("./ls", "sub/ls") is
	// existence-checked against the server CWD but executed relative to the
	// configured WorkingDirectory, so validation and execution can resolve
	// different files. Only a bare name (PATH lookup) or an absolute path is
	// unambiguous; reject anything in between.
	if !filepath.IsAbs(executable) && strings.ContainsRune(executable, filepath.Separator) {
		return fmt.Errorf("relative executable paths are not allowed in secure mode: %q", executable)
	}

	for _, allowed := range v.config.AllowedExecutables {
		if v.matchesExecutable(executable, allowed) {
			// Deny-by-default classification: enumerating binaries that can run
			// arbitrary commands (interpreters, wrappers like env/timeout/nice)
			// is inherently incomplete, so anything not affirmatively known safe
			// is rejected even when allowlisted (GHSA-gg85-6grh-63fp).
			if !v.isClassifiedExecutable(executable) {
				return fmt.Errorf(
					"executable '%s' is not classified as safe in secure mode: it is not a data-only utility and has no argument policy",
					executable,
				)
			}
			if err := v.policies.check(res.Argv); err != nil {
				return err
			}
			// Apply blocked_patterns and blocked_commands to the resolved argv,
			// not the raw command: matching the source string lets split quotes
			// ("cat /etc/pass\"wd\"") produce the target argv while evading the
			// filter. The normalised argv is what actually runs.
			if err := v.checkBlockedPatternsAndCommands(strings.Join(res.Argv, " ")); err != nil {
				return err
			}
			v.logger.Debug().
				Str("executable", executable).
				Str("allowed_pattern", allowed).
				Msg("Command validated against allowed executable")
			return nil
		}
	}

	return fmt.Errorf("executable '%s' not in allowed list", executable)
}

// matchesExecutable checks if an executable matches an allowed pattern
func (v *SecurityValidator) matchesExecutable(executable, pattern string) bool {
	// Exact match
	if executable == pattern {
		return true
	}

	// Check if it's a full path match
	if filepath.IsAbs(pattern) {
		if absExec, err := filepath.Abs(executable); err == nil {
			return absExec == pattern
		}
		return false
	}

	// Check if it's a basename match for simple commands (only if executable is not absolute)
	if !filepath.IsAbs(executable) && filepath.Base(executable) == pattern {
		// Verify the executable exists in PATH
		if _, err := exec.LookPath(executable); err == nil {
			return true
		}
	}

	return false
}

// checkBlockedPatternsAndCommands checks if the command matches any blocked pattern or contains blocked keywords.
// Used by both secure mode (validateExecutableCommand) and legacy mode (validateLegacyCommand).
func (v *SecurityValidator) checkBlockedPatternsAndCommands(command string) error {
	for _, pattern := range v.config.BlockedPatterns {
		if matched, err := regexp.MatchString(pattern, command); err == nil && matched {
			return fmt.Errorf("command matches blocked pattern: %s", pattern)
		}
	}

	for _, blocked := range v.config.BlockedCommands {
		if strings.Contains(command, blocked) {
			return fmt.Errorf("command contains blocked keyword: %s", blocked)
		}
	}
	return nil
}

// validateLegacyCommand performs the old validation for backwards compatibility
func (v *SecurityValidator) validateLegacyCommand(command string) error {
	if err := v.checkBlockedPatternsAndCommands(command); err != nil {
		return err
	}

	if len(v.config.AllowedCommands) > 0 {
		allowed := false
		for _, allowedCmd := range v.config.AllowedCommands {
			if strings.HasPrefix(strings.TrimSpace(command), allowedCmd) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("command not in allowed list")
		}
	}

	v.logger.Debug().Str("command", command).Msg("Legacy command validation passed")
	return nil
}

func (v *SecurityValidator) isEnabled() bool {
	return v.config.Enabled
}
