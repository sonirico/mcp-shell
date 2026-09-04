package main

import (
	"fmt"
	"os"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog"
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
	switch {
	case configFile != "":
		log.Info().Str("config_file", configFile).Msg("Loading security config from file")
	case cfg.Security.Enabled:
		log.Info().Msg("No security config file specified, using built-in secure defaults")
	default:
		log.Warn().Msg("SECURITY DISABLED via MCP_SHELL_ALLOW_UNSAFE - all commands run unrestricted")
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
			Bool("audit_log", cfg.Security.AuditLog).
			Bool("writes_enabled", cfg.Security.WritesEnabled).
			Int("scripts", len(cfg.Security.Scripts)).
			Msg("Security configuration")
	}

	executor := newCommandExecutor(cfg.Security, log)

	s := server.NewMCPServer(
		cfg.Server.Name,
		cfg.Server.Version,
		server.WithToolCapabilities(false),
	)

	if err := registerTools(s, cfg, executor, log); err != nil {
		return fmt.Errorf("register tools: %w", err)
	}

	log.Info().Msg("MCP server initialized, serving on stdio")

	if err := server.ServeStdio(s); err != nil {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}

func registerTools(s *server.MCPServer, cfg *Config, executor *CommandExecutor, log zerolog.Logger) error {
	if cfg.Security.Enabled {
		ws, err := newWorkspace(cfg.Security.WorkingDirectory)
		if err != nil {
			return fmt.Errorf("workspace: %w", err)
		}
		if cfg.Security.WritesEnabled {
			log.Warn().Msg("writes_enabled: file and git write tools are exposed")
		}
		newFSTools(ws, cfg.Security.MaxOutputSize, cfg.Security.WritesEnabled, log).register(s)
		newGitTools(ws, executor, cfg.Security.WritesEnabled, log).register(s)
		newScriptTools(cfg.Security.Scripts, executor, log).register(s)
		return nil
	}

	shellHandler := newShellHandler(executor, log)

	shellTool := mcp.NewTool(
		"shell_exec",
		mcp.WithDescription(
			"UNRESTRICTED: runs the command through bash -c with no validation. Only available with MCP_SHELL_ALLOW_UNSAFE=1.",
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

	return nil
}
