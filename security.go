package main

import (
	"fmt"
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

	v.logger.Debug().Str("command", command).Msg("Command validation passed")
	return nil
}

func (v *SecurityValidator) isEnabled() bool {
	return v.config.Enabled
}
