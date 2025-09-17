package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig_defaults(t *testing.T) {
	// Clear environment variables
	os.Unsetenv("MCP_SHELL_SEC_CONFIG_FILE")
	os.Unsetenv("MCP_SHELL_SERVER_NAME")
	os.Unsetenv("MCP_SHELL_LOG_LEVEL")

	config, err := loadConfig()
	require.NoError(t, err)

	// Check defaults
	assert.False(t, config.Security.Enabled)
	assert.Equal(t, "mcp-shell 🐚", config.Server.Name)
	assert.Equal(t, "info", config.Logging.Level)
	assert.Equal(t, "console", config.Logging.Format)
	assert.Equal(t, "stderr", config.Logging.Output)
}

func TestLoadConfig_environment_variables(t *testing.T) {
	// Set environment variables
	os.Setenv("MCP_SHELL_SERVER_NAME", "test-server")
	os.Setenv("MCP_SHELL_LOG_LEVEL", "debug")
	os.Setenv("MCP_SHELL_LOG_FORMAT", "json")
	os.Setenv("MCP_SHELL_LOG_OUTPUT", "stdout")
	
	defer func() {
		os.Unsetenv("MCP_SHELL_SERVER_NAME")
		os.Unsetenv("MCP_SHELL_LOG_LEVEL")
		os.Unsetenv("MCP_SHELL_LOG_FORMAT")
		os.Unsetenv("MCP_SHELL_LOG_OUTPUT")
	}()

	config, err := loadConfig()
	require.NoError(t, err)

	assert.Equal(t, "test-server", config.Server.Name)
	assert.Equal(t, "debug", config.Logging.Level)
	assert.Equal(t, "json", config.Logging.Format)
	assert.Equal(t, "stdout", config.Logging.Output)
}

func TestLoadSecurityFromFile(t *testing.T) {
	tests := []struct {
		name           string
		yamlContent    string
		expectError    bool
		validateConfig func(t *testing.T, config *Config)
	}{
		{
			name: "secure configuration",
			yamlContent: `
security:
  enabled: true
  use_shell_execution: false
  allowed_executables:
    - "ls"
    - "echo"
    - "/usr/bin/git"
  max_execution_time: "10s"
  working_directory: "/tmp"
  run_as_user: "nobody"
  max_output_size: 2048
  audit_log: true
`,
			expectError: false,
			validateConfig: func(t *testing.T, config *Config) {
				assert.True(t, config.Security.Enabled)
				assert.False(t, config.Security.UseShellExecution)
				assert.Equal(t, []string{"ls", "echo", "/usr/bin/git"}, config.Security.AllowedExecutables)
				assert.Equal(t, 10*time.Second, config.Security.MaxExecutionTime)
				assert.Equal(t, "/tmp", config.Security.WorkingDirectory)
				assert.Equal(t, "nobody", config.Security.RunAsUser)
				assert.Equal(t, 2048, config.Security.MaxOutputSize)
				assert.True(t, config.Security.AuditLog)
			},
		},
		{
			name: "legacy configuration",
			yamlContent: `
security:
  enabled: true
  use_shell_execution: true
  allowed_commands:
    - "echo"
    - "ls"
  blocked_commands:
    - "rm"
    - "chmod"
  blocked_patterns:
    - "rm\\s+-rf"
  max_execution_time: "30s"
  audit_log: false
`,
			expectError: false,
			validateConfig: func(t *testing.T, config *Config) {
				assert.True(t, config.Security.Enabled)
				assert.True(t, config.Security.UseShellExecution)
				assert.Equal(t, []string{"echo", "ls"}, config.Security.AllowedCommands)
				assert.Equal(t, []string{"rm", "chmod"}, config.Security.BlockedCommands)
				assert.Equal(t, []string{"rm\\s+-rf"}, config.Security.BlockedPatterns)
				assert.Equal(t, 30*time.Second, config.Security.MaxExecutionTime)
				assert.False(t, config.Security.AuditLog)
			},
		},
		{
			name: "invalid max_execution_time",
			yamlContent: `
security:
  enabled: true
  max_execution_time: "invalid_duration"
`,
			expectError: true,
		},
		{
			name: "invalid yaml",
			yamlContent: `
security:
  enabled: true
  invalid_yaml: [unclosed
`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file
			tmpDir := t.TempDir()
			configFile := filepath.Join(tmpDir, "security.yaml")
			
			err := os.WriteFile(configFile, []byte(tt.yamlContent), 0644)
			require.NoError(t, err)

			// Set environment variable
			os.Setenv("MCP_SHELL_SEC_CONFIG_FILE", configFile)
			defer os.Unsetenv("MCP_SHELL_SEC_CONFIG_FILE")

			config, err := loadConfig()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.validateConfig != nil {
					tt.validateConfig(t, config)
				}
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config",
			config: Config{
				Security: SecurityConfig{
					MaxOutputSize: 1024,
				},
				Logging: LoggingConfig{
					Level: "info",
				},
			},
			expectError: false,
		},
		{
			name: "negative max_output_size",
			config: Config{
				Security: SecurityConfig{
					MaxOutputSize: -1,
				},
				Logging: LoggingConfig{
					Level: "info",
				},
			},
			expectError: true,
			errorMsg:    "max_output_size cannot be negative",
		},
		{
			name: "invalid log level",
			config: Config{
				Security: SecurityConfig{
					MaxOutputSize: 1024,
				},
				Logging: LoggingConfig{
					Level: "invalid",
				},
			},
			expectError: true,
			errorMsg:    "invalid log level",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(&tt.config)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGetEnv_functions(t *testing.T) {
	t.Run("getEnv", func(t *testing.T) {
		// Test with existing environment variable
		os.Setenv("TEST_VAR", "test_value")
		defer os.Unsetenv("TEST_VAR")
		
		value := getEnv("TEST_VAR", "default")
		assert.Equal(t, "test_value", value)

		// Test with non-existing environment variable
		value = getEnv("NON_EXISTING_VAR", "default")
		assert.Equal(t, "default", value)
	})

	t.Run("getBoolEnv", func(t *testing.T) {
		// Test with true value
		os.Setenv("TEST_BOOL", "true")
		defer os.Unsetenv("TEST_BOOL")
		
		value := getBoolEnv("TEST_BOOL", false)
		assert.True(t, value)

		// Test with false value
		os.Setenv("TEST_BOOL", "false")
		value = getBoolEnv("TEST_BOOL", true)
		assert.False(t, value)

		// Test with invalid value (should return default)
		os.Setenv("TEST_BOOL", "invalid")
		value = getBoolEnv("TEST_BOOL", true)
		assert.True(t, value)

		// Test with non-existing variable
		value = getBoolEnv("NON_EXISTING_BOOL", false)
		assert.False(t, value)
	})

	t.Run("getIntEnv", func(t *testing.T) {
		// Test with valid integer
		os.Setenv("TEST_INT", "42")
		defer os.Unsetenv("TEST_INT")
		
		value := getIntEnv("TEST_INT", 0)
		assert.Equal(t, 42, value)

		// Test with invalid integer (should return default)
		os.Setenv("TEST_INT", "invalid")
		value = getIntEnv("TEST_INT", 100)
		assert.Equal(t, 100, value)

		// Test with non-existing variable
		value = getIntEnv("NON_EXISTING_INT", 50)
		assert.Equal(t, 50, value)
	})
}

func TestConfig_security_model_examples(t *testing.T) {
	t.Run("secure_example_config", func(t *testing.T) {
		yamlContent := `
security:
  enabled: true
  use_shell_execution: false
  allowed_executables:
    - "ls"
    - "pwd"
    - "echo"
    - "cat"
    - "/usr/bin/git"
  max_execution_time: "30s"
  working_directory: "/tmp"
  audit_log: true
`
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "secure.yaml")
		
		err := os.WriteFile(configFile, []byte(yamlContent), 0644)
		require.NoError(t, err)

		os.Setenv("MCP_SHELL_SEC_CONFIG_FILE", configFile)
		defer os.Unsetenv("MCP_SHELL_SEC_CONFIG_FILE")

		config, err := loadConfig()
		require.NoError(t, err)

		// Verify secure configuration
		assert.True(t, config.Security.Enabled)
		assert.False(t, config.Security.UseShellExecution)
		assert.Contains(t, config.Security.AllowedExecutables, "ls")
		assert.Contains(t, config.Security.AllowedExecutables, "/usr/bin/git")
		assert.Equal(t, 30*time.Second, config.Security.MaxExecutionTime)
		assert.Equal(t, "/tmp", config.Security.WorkingDirectory)
		assert.True(t, config.Security.AuditLog)
	})

	t.Run("legacy_example_config", func(t *testing.T) {
		yamlContent := `
security:
  enabled: true
  use_shell_execution: true
  allowed_commands:
    - "ls"
    - "echo"
  blocked_commands:
    - "rm"
    - "chmod"
    - "sudo"
  blocked_patterns:
    - "rm\\s+-rf"
    - "sudo\\s+"
  max_execution_time: "30s"
  audit_log: true
`
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "legacy.yaml")
		
		err := os.WriteFile(configFile, []byte(yamlContent), 0644)
		require.NoError(t, err)

		os.Setenv("MCP_SHELL_SEC_CONFIG_FILE", configFile)
		defer os.Unsetenv("MCP_SHELL_SEC_CONFIG_FILE")

		config, err := loadConfig()
		require.NoError(t, err)

		// Verify legacy configuration
		assert.True(t, config.Security.Enabled)
		assert.True(t, config.Security.UseShellExecution)
		assert.Contains(t, config.Security.AllowedCommands, "ls")
		assert.Contains(t, config.Security.BlockedCommands, "rm")
		assert.Contains(t, config.Security.BlockedPatterns, "rm\\s+-rf")
		assert.True(t, config.Security.AuditLog)
	})
}
