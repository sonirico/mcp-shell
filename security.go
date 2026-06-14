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
	v.warnOnInterpreters()
	return v
}

// warnOnInterpreters flags allowlisted executables that can execute arbitrary
// commands regardless of metacharacter checks (shell/language interpreters, and
// git via `-c alias.x=!cmd`). Allowing one defeats secure mode; the warning
// surfaces the misconfiguration at startup instead of silently trusting it.
func (v *SecurityValidator) warnOnInterpreters() {
	if !v.config.Enabled || v.config.UseShellExecution {
		return
	}
	for _, exe := range v.config.AllowedExecutables {
		if isInterpreterExecutable(filepath.Base(exe)) {
			v.logger.Warn().
				Str("executable", exe).
				Msg("allowed executable can run arbitrary commands (interpreter or alias-capable) - this defeats secure mode regardless of metacharacter filtering")
		}
	}
}

// isInterpreterExecutable reports whether base names an executable that can
// itself run arbitrary commands, making executable-allowlisting ineffective.
func isInterpreterExecutable(base string) bool {
	switch base {
	case "bash", "sh", "zsh", "fish", "dash", "ksh", "csh", "tcsh",
		"python", "python2", "python3", "perl", "ruby", "node", "php", "git":
		return true
	}
	return false
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
		v.logger.Warn().
			Str("command", command).
			Msg("No allowed executables configured - blocking all commands")
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

	for _, allowed := range v.config.AllowedExecutables {
		if v.matchesExecutable(executable, allowed) {
			// An interpreter defeats the allowlist by executing whatever it is
			// handed. Hard-deny it unless a per-tool policy governs its arguments.
			if isInterpreterExecutable(filepath.Base(executable)) && !v.policies.governs(executable) {
				return fmt.Errorf("executable '%s' is an interpreter and cannot be allowed in secure mode", executable)
			}
			if err := v.policies.check(res.Argv); err != nil {
				return err
			}
			// Apply blocked_patterns and blocked_commands to restrict specific
			// arguments (e.g. block "git remote -v" while allowing git).
			if err := v.checkBlockedPatternsAndCommands(command); err != nil {
				return err
			}
			v.logger.Debug().
				Str("executable", executable).
				Str("allowed_pattern", allowed).
				Msg("Command validated against allowed executable")
			return nil
		}
	}

	v.logger.Warn().
		Str("executable", executable).
		Strs("allowed_executables", v.config.AllowedExecutables).
		Msg("Executable not in allowed list")
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
			v.logger.Warn().
				Str("command", command).
				Str("pattern", pattern).
				Msg("Command blocked by pattern")
			return fmt.Errorf("command matches blocked pattern: %s", pattern)
		}
	}

	for _, blocked := range v.config.BlockedCommands {
		if strings.Contains(command, blocked) {
			v.logger.Warn().
				Str("command", command).
				Str("blocked_keyword", blocked).
				Msg("Command contains blocked keyword")
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
			v.logger.Warn().
				Str("command", command).
				Strs("allowed_commands", v.config.AllowedCommands).
				Msg("Command not in allowed list")
			return fmt.Errorf("command not in allowed list")
		}
	}

	v.logger.Debug().Str("command", command).Msg("Legacy command validation passed")
	return nil
}

func (v *SecurityValidator) isEnabled() bool {
	return v.config.Enabled
}
