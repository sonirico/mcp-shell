package main

import (
	"fmt"
	"os"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	if version != "dev" {
		cfg.Server.Version = version
	}

	log, err := newLogger(cfg.Logging)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}

	configFile := os.Getenv("MCP_SHELL_SEC_CONFIG_FILE")
	if configFile != "" {
		log.Info().Str("config_file", configFile).Msg("Loading security config")
	} else {
		log.Info().Msg("No security config file specified, security disabled")
	}

	log.Info().
		Str("server_name", cfg.Server.Name).
		Str("version", cfg.Server.Version).
		Str("log_level", cfg.Logging.Level).
		Str("log_format", cfg.Logging.Format).
		Bool("security_enabled", cfg.Security.Enabled).
		Msg("Configuration loaded")

	if cfg.Security.Enabled {
		log.Info().
			Str("working_dir", cfg.Security.WorkingDirectory).
			Dur("max_execution_time", cfg.Security.MaxExecutionTime).
			Int("max_output_size", cfg.Security.MaxOutputSize).
			Int("allowed_commands", len(cfg.Security.AllowedCommands)).
			Int("blocked_commands", len(cfg.Security.BlockedCommands)).
			Int("blocked_patterns", len(cfg.Security.BlockedPatterns)).
			Bool("audit_log", cfg.Security.AuditLog).
			Msg("Security configuration")

		log.Debug().
			Strs("allowed_commands", cfg.Security.AllowedCommands).
			Msg("Allowed commands list")

		log.Debug().
			Strs("blocked_commands", cfg.Security.BlockedCommands).
			Msg("Blocked commands list")

		log.Debug().
			Strs("blocked_patterns", cfg.Security.BlockedPatterns).
			Msg("Blocked patterns list")
	}

	validator := newSecurityValidator(cfg.Security, log)
	executor := newCommandExecutor(cfg.Security, log)
	shellHandler := newShellHandler(validator, executor, log)

	s := server.NewMCPServer(
		cfg.Server.Name,
		cfg.Server.Version,
		server.WithToolCapabilities(false),
	)

	shellTool := mcp.NewTool(
		"shell_exec",
		mcp.WithDescription(
			"Execute shell commands with configurable security constraints. Returns structured JSON with stdout, stderr, exit code and execution metadata.",
		),
		mcp.WithString("command",
			mcp.Required(),
			mcp.Description("Shell command to execute"),
		),
		mcp.WithBoolean(
			"base64",
			mcp.DefaultBool(false),
			mcp.Description(
				"Return stdout/stderr as base64-encoded strings (useful for binary data)",
			),
		),
	)

	s.AddTool(shellTool, shellHandler.handle)

	log.Info().Msg("MCP server initialized, serving on stdio")

	if err := server.ServeStdio(s); err != nil {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}
