package main

import (
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestScriptServer(t *testing.T, scripts map[string][]string) *server.MCPServer {
	t.Helper()

	cfg := SecurityConfig{
		Enabled:          true,
		WorkingDirectory: t.TempDir(),
		MaxExecutionTime: 30 * time.Second,
	}
	executor := newCommandExecutor(cfg, zerolog.Nop())

	s := server.NewMCPServer("t", "0")
	newScriptTools(scripts, executor, zerolog.Nop()).register(s)

	return s
}

func TestScriptTools(t *testing.T) {
	t.Parallel()

	scripts := map[string][]string{
		"ok":   {"sh", "-c", "echo ok"},
		"fail": {"sh", "-c", "exit 2"},
	}

	t.Run("run_script succeeds", func(t *testing.T) {
		t.Parallel()
		s := newTestScriptServer(t, scripts)

		res := callTool(t, s, "run_script", map[string]any{"name": "ok"})

		text := resultText(t, res)
		assert.Equal(t, "ok", text)
	})

	t.Run("run_script non-zero exit", func(t *testing.T) {
		t.Parallel()
		s := newTestScriptServer(t, scripts)

		res := callTool(t, s, "run_script", map[string]any{"name": "fail"})

		require.True(t, res.IsError)
		textContent, ok := res.Content[0].(mcp.TextContent)
		require.True(t, ok)
		assert.Contains(t, textContent.Text, "exit 2")
	})

	t.Run("run_script unknown name", func(t *testing.T) {
		t.Parallel()
		s := newTestScriptServer(t, scripts)

		res := callTool(t, s, "run_script", map[string]any{"name": "missing"})

		require.True(t, res.IsError)
		textContent, ok := res.Content[0].(mcp.TextContent)
		require.True(t, ok)
		assert.Contains(t, textContent.Text, "unknown script")
		assert.Contains(t, textContent.Text, "ok")
	})

	t.Run("empty scripts registers no tool", func(t *testing.T) {
		t.Parallel()
		s := newTestScriptServer(t, map[string][]string{})

		tools := s.ListTools()

		assert.NotContains(t, tools, "run_script")
	})

	t.Run("description lists sorted names", func(t *testing.T) {
		t.Parallel()
		s := newTestScriptServer(t, scripts)

		tools := s.ListTools()
		tool, ok := tools["run_script"]
		assert.True(t, ok)
		assert.Contains(t, tool.Tool.Description, "fail, ok")
	})
}
