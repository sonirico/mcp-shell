package main

import (
	"fmt"
	"os"
	"regexp"
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
	Enabled            bool                `yaml:"enabled"`
	AllowedCommands    []string            `yaml:"allowed_commands"`    // Deprecated: use AllowedExecutables
	BlockedCommands    []string            `yaml:"blocked_commands"`    // Deprecated: use validation instead
	BlockedPatterns    []string            `yaml:"blocked_patterns"`    // Deprecated: use validation instead
	AllowedExecutables []string            `yaml:"allowed_executables"` // Secure: list of allowed executable paths
	MaxExecutionTime   time.Duration       `yaml:"max_execution_time"`
	WorkingDirectory   string              `yaml:"working_directory"`
	RunAsUser          string              `yaml:"run_as_user"`
	MaxOutputSize      int                 `yaml:"max_output_size"`
	AuditLog           bool                `yaml:"audit_log"`
	UseShellExecution  bool                `yaml:"use_shell_execution"` // Legacy mode - enables shell execution (DANGEROUS)
	WritesEnabled      bool                `yaml:"writes_enabled"`
	Scripts            map[string][]string `yaml:"scripts"`
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

// newDefaultSecurityConfig returns the built-in secure defaults applied when no
// MCP_SHELL_SEC_CONFIG_FILE is provided. Secure mode is the operating default:
// the server boots restricted to a narrow allowlist of utilities that cannot
// themselves spawn arbitrary processes. Every entry is classified as safe
// (data-only, or governed by an argument policy); unclassified executables
// would be rejected by secure mode anyway, so none ship here.
func newDefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		Enabled:           true,
		UseShellExecution: false,
		AllowedExecutables: []string{
			"ls", "pwd", "whoami", "date", "echo",
			"cat", "grep", "find", "wc", "head", "tail", "sort", "uniq",
		},
		MaxExecutionTime: 30 * time.Second,
		MaxOutputSize:    1048576,
		WorkingDirectory: "/tmp",
		AuditLog:         true,
	}
}

func loadConfig() (*Config, error) {
	_ = godotenv.Load()

	security := newDefaultSecurityConfig()
	// Unrestricted mode requires affirmative opt-in, never silence.
	if getBoolEnv("MCP_SHELL_ALLOW_UNSAFE", false) {
		security.Enabled = false
	}

	config := &Config{
		Security: security,
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

	// Disabling security must be an affirmative choice, never a side effect of a
	// config file. Whether it comes from the env opt-out or an explicit
	// `enabled: false`, it is only honoured alongside MCP_SHELL_ALLOW_UNSAFE.
	if !config.Security.Enabled && !getBoolEnv("MCP_SHELL_ALLOW_UNSAFE", false) {
		return nil, fmt.Errorf("security is disabled but MCP_SHELL_ALLOW_UNSAFE is not set; refusing to start unrestricted")
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
			Enabled            bool                `yaml:"enabled"`
			AllowedCommands    []string            `yaml:"allowed_commands"`
			BlockedCommands    []string            `yaml:"blocked_commands"`
			BlockedPatterns    []string            `yaml:"blocked_patterns"`
			AllowedExecutables []string            `yaml:"allowed_executables"`
			MaxExecutionTime   string              `yaml:"max_execution_time"`
			WorkingDirectory   string              `yaml:"working_directory"`
			RunAsUser          string              `yaml:"run_as_user"`
			MaxOutputSize      int                 `yaml:"max_output_size"`
			AuditLog           bool                `yaml:"audit_log"`
			UseShellExecution  bool                `yaml:"use_shell_execution"`
			WritesEnabled      bool                `yaml:"writes_enabled"`
			Scripts            map[string][]string `yaml:"scripts"`
		} `yaml:"security"`
	}

	// Seed the decode target with the current secure defaults so keys the file
	// omits keep those defaults instead of decoding to zero values. Otherwise a
	// file that only narrows the allowlist would silently set enabled=false,
	// max_output_size=0 (unlimited) and working_directory="" - failing open.
	sec := config.Security
	yamlConfig.Security.Enabled = sec.Enabled
	yamlConfig.Security.AllowedCommands = sec.AllowedCommands
	yamlConfig.Security.BlockedCommands = sec.BlockedCommands
	yamlConfig.Security.BlockedPatterns = sec.BlockedPatterns
	yamlConfig.Security.AllowedExecutables = sec.AllowedExecutables
	yamlConfig.Security.WorkingDirectory = sec.WorkingDirectory
	yamlConfig.Security.RunAsUser = sec.RunAsUser
	yamlConfig.Security.MaxOutputSize = sec.MaxOutputSize
	yamlConfig.Security.AuditLog = sec.AuditLog
	yamlConfig.Security.UseShellExecution = sec.UseShellExecution
	yamlConfig.Security.WritesEnabled = sec.WritesEnabled
	yamlConfig.Security.Scripts = sec.Scripts

	if err := yaml.Unmarshal(data, &yamlConfig); err != nil {
		return err
	}

	config.Security.Enabled = yamlConfig.Security.Enabled
	config.Security.AllowedCommands = yamlConfig.Security.AllowedCommands
	config.Security.BlockedCommands = yamlConfig.Security.BlockedCommands
	config.Security.BlockedPatterns = yamlConfig.Security.BlockedPatterns
	config.Security.AllowedExecutables = yamlConfig.Security.AllowedExecutables
	config.Security.WorkingDirectory = yamlConfig.Security.WorkingDirectory
	config.Security.RunAsUser = yamlConfig.Security.RunAsUser
	config.Security.MaxOutputSize = yamlConfig.Security.MaxOutputSize
	config.Security.AuditLog = yamlConfig.Security.AuditLog
	config.Security.UseShellExecution = yamlConfig.Security.UseShellExecution
	config.Security.WritesEnabled = yamlConfig.Security.WritesEnabled
	config.Security.Scripts = yamlConfig.Security.Scripts

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

	for name, argv := range config.Security.Scripts {
		if !scriptNamePattern.MatchString(name) {
			return fmt.Errorf("scripts: invalid script %q: name must match ^[a-z0-9_-]+$", name)
		}
		if len(argv) == 0 {
			return fmt.Errorf("scripts: invalid script %q: argv is empty", name)
		}
	}

	return nil
}

var scriptNamePattern = regexp.MustCompile(`^[a-z0-9_-]+$`)

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
