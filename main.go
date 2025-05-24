package main

import (
	"fmt"
	"os"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var version = "dev" // Set at compile time

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Load configuration
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Override version if set at compile time
	if version != "dev" {
		cfg.Server.Version = version
	}

	// Initialize logger
	log, err := newLogger(cfg.Logging)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}

	log.Info().
		Str("version", cfg.Server.Version).
		Bool("security_enabled", cfg.Security.Enabled).
		Msg("Starting mcp-shell server")

	// Initialize components with dependency injection
	validator := newSecurityValidator(cfg.Security, log)
	executor := newCommandExecutor(cfg.Security, log)
	shellHandler := newShellHandler(validator, executor, log)

	// Create MCP server
	s := server.NewMCPServer(
		cfg.Server.Name,
		cfg.Server.Version,
		server.WithToolCapabilities(false),
	)

	// Define shell tool
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

	// Register tool handler
	s.AddTool(shellTool, shellHandler.handle)

	log.Info().Msg("MCP server initialized, serving on stdio")

	// Serve stdio
	if err := server.ServeStdio(s); err != nil {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}
