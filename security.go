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
	config SecurityConfig
	logger zerolog.Logger
}

func newSecurityValidator(cfg SecurityConfig, logger zerolog.Logger) *SecurityValidator {
	return &SecurityValidator{
		config: cfg,
		logger: logger.With().Str("component", "security").Logger(),
	}
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

// validateExecutableCommand validates commands using the secure executable allowlist approach
func (v *SecurityValidator) validateExecutableCommand(command string) error {
	command = strings.TrimSpace(command)
	if command == "" {
		return fmt.Errorf("empty command")
	}

	// Check for shell metacharacters first - reject commands that try to use shell features
	if containsShellMetacharacters(command) {
		return fmt.Errorf("command contains shell metacharacters (not allowed in secure mode): %s", command)
	}

	// Check for dangerous shell constructs in the entire command
	if containsDangerousShellConstructs(command) {
		return fmt.Errorf("command contains dangerous shell constructs (not allowed in secure mode): %s", command)
	}

	// Simple whitespace-based splitting to get the executable
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return fmt.Errorf("no command found")
	}

	executable := parts[0]

	// Check if the executable is in the allowlist
	for _, allowed := range v.config.AllowedExecutables {
		if v.matchesExecutable(executable, allowed) {
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

// containsShellMetacharacters checks if a string contains shell metacharacters
// that could be used for command injection
func containsShellMetacharacters(s string) bool {
	metachars := "|&;<>(){}[]$`\\"
	for _, char := range s {
		if strings.ContainsRune(metachars, char) {
			return true
		}
	}
	return false
}

// containsDangerousShellConstructs checks for potentially dangerous shell constructs
func containsDangerousShellConstructs(s string) bool {
	dangerous := []string{
		"$(", "`", "${", "&&", "||", ";", "|", ">", "<", ">>", "<<", "&",
	}
	for _, construct := range dangerous {
		if strings.Contains(s, construct) {
			return true
		}
	}
	return false
}

// validateLegacyCommand performs the old validation for backwards compatibility
func (v *SecurityValidator) validateLegacyCommand(command string) error {
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
