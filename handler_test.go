package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestShellHandler(t *testing.T) *ShellHandler {
	t.Helper()
	logger := zerolog.Nop()
	executor := newCommandExecutor(SecurityConfig{
		Enabled:          false,
		WorkingDirectory: t.TempDir(),
		MaxExecutionTime: 30 * time.Second,
		MaxOutputSize:    1 << 20,
	}, logger)
	return newShellHandler(executor, logger)
}

func TestShellHandler_handle(t *testing.T) {
	ctx := context.Background()

	t.Run("runs the command through bash -c", func(t *testing.T) {
		handler := newTestShellHandler(t)

		request := mcp.CallToolRequest{}
		request.Params.Arguments = map[string]interface{}{
			"command": "echo hi | tr a-z A-Z",
		}

		result, err := handler.handle(ctx, request)

		require.NoError(t, err)
		require.NotNil(t, result)
		require.False(t, result.IsError)
		require.Len(t, result.Content, 1)

		textContent, ok := mcp.AsTextContent(result.Content[0])
		require.True(t, ok)

		var response map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(textContent.Text), &response))
		assert.Equal(t, "HI", response["stdout"])
	})

	t.Run("missing command parameter is an error", func(t *testing.T) {
		handler := newTestShellHandler(t)

		request := mcp.CallToolRequest{}
		request.Params.Arguments = map[string]interface{}{}

		result, err := handler.handle(ctx, request)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.IsError)
	})

	t.Run("base64 true encodes stdout", func(t *testing.T) {
		handler := newTestShellHandler(t)

		request := mcp.CallToolRequest{}
		request.Params.Arguments = map[string]interface{}{
			"command": "echo hi",
			"base64":  true,
		}

		result, err := handler.handle(ctx, request)

		require.NoError(t, err)
		require.NotNil(t, result)
		require.False(t, result.IsError)
		require.Len(t, result.Content, 1)

		textContent, ok := mcp.AsTextContent(result.Content[0])
		require.True(t, ok)

		var response map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(textContent.Text), &response))
		assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("hi\n")), response["stdout"])
	})

	t.Run("response has no security_info key", func(t *testing.T) {
		handler := newTestShellHandler(t)

		request := mcp.CallToolRequest{}
		request.Params.Arguments = map[string]interface{}{
			"command": "echo hi",
		}

		result, err := handler.handle(ctx, request)

		require.NoError(t, err)
		require.NotNil(t, result)
		require.Len(t, result.Content, 1)

		textContent, ok := mcp.AsTextContent(result.Content[0])
		require.True(t, ok)

		var response map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(textContent.Text), &response))
		_, present := response["security_info"]
		assert.False(t, present)
	})
}
