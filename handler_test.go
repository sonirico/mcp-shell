package main

import (
	"context"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShellHandler_handle_secure_mode(t *testing.T) {
	logger := zerolog.New(zerolog.NewTestWriter(t))
	ctx := context.Background()

	tests := []struct {
		name              string
		config            SecurityConfig
		requestArgs       map[string]interface{}
		expectError       bool
		expectErrorText   string
	}{
		{
			name: "secure mode allows safe command",
			config: SecurityConfig{
				Enabled:            true,
				UseShellExecution:  false,
				AllowedExecutables: []string{"echo", "pwd"},
				MaxExecutionTime:   time.Second * 5,
			},
			requestArgs: map[string]interface{}{
				"command": "echo hello world",
				"base64":  false,
			},
			expectError: false,
		},
		{
			name: "secure mode blocks dangerous command",
			config: SecurityConfig{
				Enabled:            true,
				UseShellExecution:  false,
				AllowedExecutables: []string{"echo", "pwd"},
			},
			requestArgs: map[string]interface{}{
				"command": "rm -rf /",
			},
			expectError:     true,
			expectErrorText: "not in allowed list",
		},
		{
			name: "secure mode blocks injection attempt",
			config: SecurityConfig{
				Enabled:            true,
				UseShellExecution:  false,
				AllowedExecutables: []string{"echo"},
			},
			requestArgs: map[string]interface{}{
				"command": "echo $($(echo -n c; echo -n h; echo -n m; echo -n o; echo -n d))",
			},
			expectError:     true,
			expectErrorText: "not in allowed list",
		},
		{
			name: "missing command parameter",
			config: SecurityConfig{
				Enabled: false,
			},
			requestArgs: map[string]interface{}{
				"base64": false,
			},
			expectError:     true,
			expectErrorText: "Missing 'command' parameter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := newSecurityValidator(tt.config, logger)
			executor := newCommandExecutor(tt.config, logger)
			handler := newShellHandler(validator, executor, logger)

			// Create MCP request using the arguments map
			request := mcp.CallToolRequest{}
			request.Params.Arguments = tt.requestArgs
			request.Params.Name = "shell_exec"

			result, err := handler.handle(ctx, request)

			require.NoError(t, err, "Handler should not return error, but result should contain error")
			require.NotNil(t, result)

			if tt.expectError {
				// Check if result contains error
				assert.True(t, result.IsError)
			} else {
				// Check if result is successful
				assert.False(t, result.IsError)
			}
		})
	}
}

func TestShellHandler_vulnerability_prevention_integration(t *testing.T) {
	logger := zerolog.New(zerolog.NewTestWriter(t))
	ctx := context.Background()

	// Test the exact vulnerability from VULN.md
	vulnerabilityRequest := mcp.CallToolRequest{}
	vulnerabilityRequest.Params.Arguments = map[string]interface{}{
		"command": "echo $($(echo -n c; echo -n h; echo -n m; echo -n o; echo -n d))",
		"base64":  false,
	}

	t.Run("secure_mode_blocks_vuln_md_example", func(t *testing.T) {
		config := SecurityConfig{
			Enabled:            true,
			UseShellExecution:  false,
			AllowedExecutables: []string{"echo", "ls", "pwd"},
		}

		validator := newSecurityValidator(config, logger)
		executor := newCommandExecutor(config, logger)
		handler := newShellHandler(validator, executor, logger)

		result, err := handler.handle(ctx, vulnerabilityRequest)
		require.NoError(t, err)
		
		// Should be blocked at validation stage
		assert.True(t, result.IsError, "Secure mode should block the injection attempt")
	})

	t.Run("legacy_mode_vulnerable_without_blocks", func(t *testing.T) {
		config := SecurityConfig{
			Enabled:           true,
			UseShellExecution: true,
			// No blocks - vulnerable
			MaxExecutionTime: time.Second * 1,
		}

		validator := newSecurityValidator(config, logger)
		executor := newCommandExecutor(config, logger)
		handler := newShellHandler(validator, executor, logger)

		result, err := handler.handle(ctx, vulnerabilityRequest)
		require.NoError(t, err)
		
		// This demonstrates the vulnerability - legacy mode allows dangerous commands
		// In a real attack, this would execute the obfuscated chmod
		t.Logf("Legacy mode result - IsError: %v", result.IsError)
	})

	t.Run("legacy_mode_with_proper_blocks", func(t *testing.T) {
		config := SecurityConfig{
			Enabled:           true,
			UseShellExecution: true,
			BlockedCommands:   []string{"chmod"}, // This should catch the obfuscated chmod
		}

		validator := newSecurityValidator(config, logger)
		executor := newCommandExecutor(config, logger)
		handler := newShellHandler(validator, executor, logger)

		result, err := handler.handle(ctx, vulnerabilityRequest)
		require.NoError(t, err)
		
		// This demonstrates the vulnerability - legacy mode cannot detect obfuscated commands
		// even with keyword blocking, since "chmod" doesn't appear literally
		assert.False(t, result.IsError, "Legacy mode with blocks still vulnerable to obfuscation")
	})
}

func TestShellHandler_base64_encoding(t *testing.T) {
	logger := zerolog.New(zerolog.NewTestWriter(t))
	ctx := context.Background()

	config := SecurityConfig{
		Enabled:            true,
		UseShellExecution:  false,
		AllowedExecutables: []string{"echo"},
		MaxExecutionTime:   time.Second * 5,
	}

	validator := newSecurityValidator(config, logger)
	executor := newCommandExecutor(config, logger)
	handler := newShellHandler(validator, executor, logger)

	tests := []struct {
		name    string
		base64  bool
		command string
	}{
		{
			name:    "without base64 encoding",
			base64:  false,
			command: "echo hello world",
		},
		{
			name:    "with base64 encoding",
			base64:  true,
			command: "echo hello world",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := mcp.CallToolRequest{}
			request.Params.Arguments = map[string]interface{}{
				"command": tt.command,
				"base64":  tt.base64,
			}

			result, err := handler.handle(ctx, request)
			require.NoError(t, err)
			assert.False(t, result.IsError, "Base64 encoding test should succeed")
		})
	}
}

// Test direct security validation and execution without MCP wrapper
func TestShellHandler_direct_security_tests(t *testing.T) {
	logger := zerolog.New(zerolog.NewTestWriter(t))

	t.Run("secure_execution_blocks_injection", func(t *testing.T) {
		config := SecurityConfig{
			Enabled:            true,
			UseShellExecution:  false,
			AllowedExecutables: []string{"echo"},
		}

		validator := newSecurityValidator(config, logger)
		executor := newCommandExecutor(config, logger)

		// Test validation - should pass (this is the vulnerability)
		err := validator.validateCommand("echo $(rm -rf /)")
		assert.Error(t, err, "Should block command with shell metacharacters")

		// Test parsing - would also fail in executor
		_, _, err = executor.parseCommand("echo $(rm -rf /)")
		assert.Error(t, err, "Should fail to parse command with shell metacharacters")
	})

	t.Run("legacy_execution_allows_injection", func(t *testing.T) {
		config := SecurityConfig{
			Enabled:           true,
			UseShellExecution: true,
			// No restrictions - vulnerable
		}

		validator := newSecurityValidator(config, logger)

		// Test validation - should pass (this is the vulnerability)
		err := validator.validateCommand("echo $(rm -rf /)")
		assert.NoError(t, err, "Legacy mode without blocks allows dangerous commands")
	})

	t.Run("VULN_MD_example_security_comparison", func(t *testing.T) {
		vulnCommand := "echo $($(echo -n c; echo -n h; echo -n m; echo -n o; echo -n d))"

		// Secure mode
		secureConfig := SecurityConfig{
			Enabled:            true,
			UseShellExecution:  false,
			AllowedExecutables: []string{"echo"},
		}
		secureValidator := newSecurityValidator(secureConfig, logger)
		err := secureValidator.validateCommand(vulnCommand)
		assert.Error(t, err, "Secure mode should block VULN.md example")

		// Legacy mode without proper blocks (vulnerable)
		vulnerableConfig := SecurityConfig{
			Enabled:           true,
			UseShellExecution: true,
		}
		vulnerableValidator := newSecurityValidator(vulnerableConfig, logger)
		err = vulnerableValidator.validateCommand(vulnCommand)
		assert.NoError(t, err, "Legacy mode without blocks is vulnerable")

		// Legacy mode with proper blocks - still vulnerable to obfuscated commands
		protectedConfig := SecurityConfig{
			Enabled:           true,
			UseShellExecution: true,
			BlockedCommands:   []string{"chmod"},
		}
		protectedValidator := newSecurityValidator(protectedConfig, logger)
		err = protectedValidator.validateCommand(vulnCommand)
		assert.NoError(t, err, "Legacy mode cannot detect obfuscated commands even with blocks")
	})
}
