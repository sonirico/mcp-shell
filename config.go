package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Security SecurityConfig
	Server   ServerConfig
	Logging  LoggingConfig
}

type SecurityConfig struct {
	Enabled          bool          `yaml:"enabled"`
	AllowedCommands  []string      `yaml:"allowed_commands"`
	BlockedCommands  []string      `yaml:"blocked_commands"`
	BlockedPatterns  []string      `yaml:"blocked_patterns"`
	MaxExecutionTime time.Duration `yaml:"max_execution_time"`
	WorkingDirectory string        `yaml:"working_directory"`
	RunAsUser        string        `yaml:"run_as_user"`
	MaxOutputSize    int           `yaml:"max_output_size"`
	AuditLog         bool          `yaml:"audit_log"`
}

type ServerConfig struct {
	Name    string
	Version string
}

type LoggingConfig struct {
	Level  string
	Format string
	Output string
}

func loadConfig() (*Config, error) {
	_ = godotenv.Load()

	config := &Config{
		Security: SecurityConfig{
			Enabled: false,
		},
		Server: ServerConfig{
			Name:    getEnv("MCP_SHELL_SERVER_NAME", "mcp-shell 🐚"),
			Version: version,
		},
		Logging: LoggingConfig{
			Level:  getEnv("MCP_SHELL_LOG_LEVEL", "info"),
			Format: getEnv("MCP_SHELL_LOG_FORMAT", "console"),
			Output: getEnv("MCP_SHELL_LOG_OUTPUT", "stderr"),
		},
	}

	configFile := getEnv("MCP_SHELL_SEC_CONFIG_FILE", "")
	if configFile != "" {
		if err := loadSecurityFromFile(config, configFile); err != nil {
			return nil, fmt.Errorf("failed to load security config: %w", err)
		}
	}

	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

func loadSecurityFromFile(config *Config, filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	var yamlConfig struct {
		Security struct {
			Enabled          bool     `yaml:"enabled"`
			AllowedCommands  []string `yaml:"allowed_commands"`
			BlockedCommands  []string `yaml:"blocked_commands"`
			BlockedPatterns  []string `yaml:"blocked_patterns"`
			MaxExecutionTime string   `yaml:"max_execution_time"`
			WorkingDirectory string   `yaml:"working_directory"`
			RunAsUser        string   `yaml:"run_as_user"`
			MaxOutputSize    int      `yaml:"max_output_size"`
			AuditLog         bool     `yaml:"audit_log"`
		} `yaml:"security"`
	}

	if err := yaml.Unmarshal(data, &yamlConfig); err != nil {
		return err
	}

	config.Security.Enabled = yamlConfig.Security.Enabled
	config.Security.AllowedCommands = yamlConfig.Security.AllowedCommands
	config.Security.BlockedCommands = yamlConfig.Security.BlockedCommands
	config.Security.BlockedPatterns = yamlConfig.Security.BlockedPatterns
	config.Security.WorkingDirectory = yamlConfig.Security.WorkingDirectory
	config.Security.RunAsUser = yamlConfig.Security.RunAsUser
	config.Security.MaxOutputSize = yamlConfig.Security.MaxOutputSize
	config.Security.AuditLog = yamlConfig.Security.AuditLog

	if yamlConfig.Security.MaxExecutionTime != "" {
		duration, err := time.ParseDuration(yamlConfig.Security.MaxExecutionTime)
		if err != nil {
			return fmt.Errorf("invalid max_execution_time: %w", err)
		}
		config.Security.MaxExecutionTime = duration
	}

	return nil
}

func validateConfig(config *Config) error {
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
