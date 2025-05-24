package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Security SecurityConfig `json:"security"`
	Server   ServerConfig   `json:"server"`
	Logging  LoggingConfig  `json:"logging"`
}

type SecurityConfig struct {
	Enabled          bool     `json:"enabled"`
	AllowedCommands  []string `json:"allowed_commands"`
	BlockedCommands  []string `json:"blocked_commands"`
	BlockedPatterns  []string `json:"blocked_patterns"`
	MaxExecutionTime string   `json:"max_execution_time"`
	WorkingDirectory string   `json:"working_directory"`
	RunAsUser        string   `json:"run_as_user"`
	MaxOutputSize    int      `json:"max_output_size"`
	AuditLog         bool     `json:"audit_log"`
}

type ServerConfig struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type LoggingConfig struct {
	Level  string `json:"level"`
	Format string `json:"format"` // json, console
	Output string `json:"output"` // stdout, stderr, file
}

func loadConfig() (*Config, error) {
	// Load .env file if it exists (ignore error if file doesn't exist)
	_ = godotenv.Load()

	config := defaultConfig()

	// Load from config file if specified
	configFile := getEnv("MCP_SHELL_CONFIG_FILE", "")
	if configFile != "" {
		if err := loadFromFile(config, configFile); err != nil {
			return nil, fmt.Errorf("failed to load config file: %w", err)
		}
	}

	// Override only server and logging with environment variables
	loadFromEnv(config)

	// Validate configuration
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

func defaultConfig() *Config {
	return &Config{
		Security: SecurityConfig{
			Enabled:         false,
			AllowedCommands: []string{},
			BlockedCommands: []string{"rm -rf", "sudo", "chmod 777", "dd", "mkfs", "fdisk"},
			BlockedPatterns: []string{
				"rm\\s+.*-rf.*",
				"sudo\\s+.*",
				"chmod\\s+(777|666)",
				">/dev/",
				"format\\s+",
			},
			MaxExecutionTime: "30s",
			WorkingDirectory: "/tmp/mcp-workspace",
			RunAsUser:        "",
			MaxOutputSize:    1024 * 1024,
			AuditLog:         true,
		},
		Server: ServerConfig{
			Name:    getEnv("MCP_SHELL_SERVER_NAME", "mcp-shell 🐚"),
			Version: getEnv("MCP_SHELL_VERSION", "dev"),
		},
		Logging: LoggingConfig{
			Level:  getEnv("MCP_SHELL_LOG_LEVEL", "info"),
			Format: getEnv("MCP_SHELL_LOG_FORMAT", "console"),
			Output: getEnv("MCP_SHELL_LOG_OUTPUT", "stderr"),
		},
	}
}

func loadFromFile(config *Config, filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, config)
}

func loadFromEnv(config *Config) {
	// Only override server and logging config from environment
	// Security config comes only from JSON file

	// Server overrides
	if name := getEnv("MCP_SHELL_SERVER_NAME", ""); name != "" {
		config.Server.Name = name
	}
	if version := getEnv("MCP_SHELL_VERSION", ""); version != "" {
		config.Server.Version = version
	}

	// Logging overrides
	if level := getEnv("MCP_SHELL_LOG_LEVEL", ""); level != "" {
		config.Logging.Level = level
	}
	if format := getEnv("MCP_SHELL_LOG_FORMAT", ""); format != "" {
		config.Logging.Format = format
	}
	if output := getEnv("MCP_SHELL_LOG_OUTPUT", ""); output != "" {
		config.Logging.Output = output
	}
}

func validateConfig(config *Config) error {
	if config.Security.MaxExecutionTime != "" {
		if _, err := time.ParseDuration(config.Security.MaxExecutionTime); err != nil {
			return fmt.Errorf("invalid max_execution_time: %w", err)
		}
	}

	if config.Security.MaxOutputSize < 0 {
		return fmt.Errorf("max_output_size cannot be negative")
	}

	validLogLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true, "fatal": true,
	}
	if !validLogLevels[config.Logging.Level] {
		return fmt.Errorf("invalid log level: %s", config.Logging.Level)
	}

	return nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func getIntEnv(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}
