package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig_defaults(t *testing.T) {
	// Clear environment variables (getEnv/getBoolEnv treat "" as unset).
	t.Setenv("MCP_SHELL_SEC_CONFIG_FILE", "")
	t.Setenv("MCP_SHELL_SERVER_NAME", "")
	t.Setenv("MCP_SHELL_LOG_LEVEL", "")
	t.Setenv("MCP_SHELL_ALLOW_UNSAFE", "")

	config, err := loadConfig()
	require.NoError(t, err)

	// Secure mode is the built-in default, no config file required.
	assert.True(t, config.Security.Enabled)
	assert.Equal(t, "mcp-shell 🐚", config.Server.Name)
	assert.Equal(t, "info", config.Logging.Level)
	assert.Equal(t, "console", config.Logging.Format)
	assert.Equal(t, "stderr", config.Logging.Output)
}

func TestLoadConfig_allowUnsafeOptOut(t *testing.T) {
	t.Setenv("MCP_SHELL_SEC_CONFIG_FILE", "")
	t.Setenv("MCP_SHELL_ALLOW_UNSAFE", "true")

	config, err := loadConfig()
	require.NoError(t, err)

	// Unrestricted mode only via affirmative opt-in.
	assert.False(t, config.Security.Enabled)
}

func TestLoadConfig_environment_variables(t *testing.T) {
	// Set environment variables
	t.Setenv("MCP_SHELL_SERVER_NAME", "test-server")
	t.Setenv("MCP_SHELL_LOG_LEVEL", "debug")
	t.Setenv("MCP_SHELL_LOG_FORMAT", "json")
	t.Setenv("MCP_SHELL_LOG_OUTPUT", "stdout")

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
  max_execution_time: "10s"
  working_directory: "/tmp"
  run_as_user: "nobody"
  max_output_size: 2048
  audit_log: true
`,
			expectError: false,
			validateConfig: func(t *testing.T, config *Config) {
				assert.True(t, config.Security.Enabled)
				assert.Equal(t, 10*time.Second, config.Security.MaxExecutionTime)
				assert.Equal(t, "/tmp", config.Security.WorkingDirectory)
				assert.Equal(t, "nobody", config.Security.RunAsUser)
				assert.Equal(t, 2048, config.Security.MaxOutputSize)
				assert.True(t, config.Security.AuditLog)
			},
		},
		{
			name: "writes_enabled true is loaded",
			yamlContent: `
security:
  enabled: true
  writes_enabled: true
`,
			expectError: false,
			validateConfig: func(t *testing.T, config *Config) {
				assert.True(t, config.Security.WritesEnabled)
			},
		},
		{
			name: "writes_enabled omitted stays false",
			yamlContent: `
security:
  enabled: true
`,
			expectError: false,
			validateConfig: func(t *testing.T, config *Config) {
				assert.False(t, config.Security.WritesEnabled)
			},
		},
		{
			name: "scripts is loaded",
			yamlContent: `
security:
  enabled: true
  scripts:
    test: ["go", "test", "./..."]
`,
			expectError: false,
			validateConfig: func(t *testing.T, config *Config) {
				assert.Equal(t, map[string][]string{"test": {"go", "test", "./..."}}, config.Security.Scripts)
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
			t.Setenv("MCP_SHELL_SEC_CONFIG_FILE", configFile)

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

func TestLoadSecurityFromFile_removedKeys(t *testing.T) {
	removedKeys := []struct {
		key   string
		value string
	}{
		{"use_shell_execution", "false"},
		{"allowed_executables", `["ls"]`},
		{"allowed_commands", `["ls"]`},
		{"blocked_commands", `["rm"]`},
		{"blocked_patterns", `["rm\\s+-rf"]`},
	}

	for _, rk := range removedKeys {
		t.Run(rk.key, func(t *testing.T) {
			tmpDir := t.TempDir()
			configFile := filepath.Join(tmpDir, "security.yaml")
			yamlContent := fmt.Sprintf("security:\n  enabled: true\n  %s: %s\n", rk.key, rk.value)
			require.NoError(t, os.WriteFile(configFile, []byte(yamlContent), 0o644))

			t.Setenv("MCP_SHELL_SEC_CONFIG_FILE", configFile)

			_, err := loadConfig()

			require.Error(t, err)
			assert.Contains(t, err.Error(), "removed in 1.0.0")
			assert.Contains(t, err.Error(), rk.key)
		})
	}
}

func TestLoadSecurityFromFile_failsClosed(t *testing.T) {
	writeConfig := func(t *testing.T, yamlContent string) {
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "security.yaml")
		require.NoError(t, os.WriteFile(configFile, []byte(yamlContent), 0o644))
		t.Setenv("MCP_SHELL_SEC_CONFIG_FILE", configFile)
		t.Setenv("MCP_SHELL_ALLOW_UNSAFE", "")
	}

	t.Run("omitted enabled keeps secure defaults", func(t *testing.T) {
		// A file that only narrows the working directory must not silently
		// disable security: absent keys keep their secure defaults, not zero
		// values.
		writeConfig(t, `
security:
  working_directory: "/tmp"
`)
		config, err := loadConfig()
		require.NoError(t, err)

		assert.True(t, config.Security.Enabled)
		assert.Equal(t, "/tmp", config.Security.WorkingDirectory)
		assert.Equal(t, 1048576, config.Security.MaxOutputSize)
	})

	t.Run("explicit enabled false without opt-in refuses to start", func(t *testing.T) {
		writeConfig(t, `
security:
  enabled: false
  working_directory: "/tmp"
`)
		_, err := loadConfig()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "MCP_SHELL_ALLOW_UNSAFE")
	})

	t.Run("explicit enabled false with opt-in is allowed", func(t *testing.T) {
		writeConfig(t, `
security:
  enabled: false
`)
		t.Setenv("MCP_SHELL_ALLOW_UNSAFE", "true")
		config, err := loadConfig()
		require.NoError(t, err)
		assert.False(t, config.Security.Enabled)
	})
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
		{
			name: "empty script argv",
			config: Config{
				Security: SecurityConfig{
					MaxOutputSize: 1024,
					Scripts:       map[string][]string{"test": {}},
				},
				Logging: LoggingConfig{
					Level: "info",
				},
			},
			expectError: true,
			errorMsg:    "argv is empty",
		},
		{
			name: "valid scripts",
			config: Config{
				Security: SecurityConfig{
					MaxOutputSize: 1024,
					Scripts:       map[string][]string{"test": {"go", "test", "./..."}},
				},
				Logging: LoggingConfig{
					Level: "info",
				},
			},
			expectError: false,
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

func TestValidateConfig_invalidScriptName(t *testing.T) {
	config := Config{
		Security: SecurityConfig{
			MaxOutputSize: 1024,
			Scripts:       map[string][]string{"Bad Name": {"echo", "hi"}},
		},
		Logging: LoggingConfig{
			Level: "info",
		},
	}

	err := validateConfig(&config)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "scripts")
	assert.Contains(t, err.Error(), "Bad Name")
}

func TestGetEnv_functions(t *testing.T) {
	t.Run("getEnv", func(t *testing.T) {
		// Test with existing environment variable
		t.Setenv("TEST_VAR", "test_value")

		value := getEnv("TEST_VAR", "default")
		assert.Equal(t, "test_value", value)

		// Test with non-existing environment variable
		value = getEnv("NON_EXISTING_VAR", "default")
		assert.Equal(t, "default", value)
	})

	t.Run("getBoolEnv", func(t *testing.T) {
		// Test with true value
		t.Setenv("TEST_BOOL", "true")

		value := getBoolEnv("TEST_BOOL", false)
		assert.True(t, value)

		// Test with false value
		t.Setenv("TEST_BOOL", "false")
		value = getBoolEnv("TEST_BOOL", true)
		assert.False(t, value)

		// Test with invalid value (should return default)
		t.Setenv("TEST_BOOL", "invalid")
		value = getBoolEnv("TEST_BOOL", true)
		assert.True(t, value)

		// Test with non-existing variable
		value = getBoolEnv("NON_EXISTING_BOOL", false)
		assert.False(t, value)
	})

	t.Run("getIntEnv", func(t *testing.T) {
		// Test with valid integer
		t.Setenv("TEST_INT", "42")

		value := getIntEnv("TEST_INT", 0)
		assert.Equal(t, 42, value)

		// Test with invalid integer (should return default)
		t.Setenv("TEST_INT", "invalid")
		value = getIntEnv("TEST_INT", 100)
		assert.Equal(t, 100, value)

		// Test with non-existing variable
		value = getIntEnv("NON_EXISTING_INT", 50)
		assert.Equal(t, 50, value)
	})
}
