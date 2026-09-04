package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestToolRequest(name string, args map[string]any) mcp.CallToolRequest {
	return mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      name,
			Arguments: args,
		},
	}
}

func callTool(t *testing.T, s *server.MCPServer, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()

	tools := s.ListTools()
	tool, ok := tools[name]
	require.True(t, ok, "tool %q not registered", name)
	require.NotNil(t, tool)

	res, err := tool.Handler(context.Background(), newTestToolRequest(name, args))
	require.NoError(t, err)

	return res
}

func resultText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()

	require.False(t, res.IsError, "unexpected error result")
	textContent, ok := res.Content[0].(mcp.TextContent)
	require.True(t, ok)

	return textContent.Text
}

func newTestFSServer(t *testing.T) (*server.MCPServer, *workspace) {
	t.Helper()

	ws := newTestWorkspace(t)

	require.NoError(t, os.WriteFile(filepath.Join(ws.root, "a.txt"), []byte("l1\nl2\nl3\n"), 0o644))
	require.NoError(t, os.Mkdir(filepath.Join(ws.root, "sub"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(ws.root, "sub", "b.go"), []byte("package b\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(ws.root, ".hidden"), []byte("h\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(ws.root, "bin.dat"), []byte{0x00, 0x01, 0x02}, 0o644))

	s := server.NewMCPServer("t", "0")
	newFSTools(ws, 0, false, zerolog.Nop()).register(s)

	return s, ws
}

func TestFSTools(t *testing.T) {
	t.Parallel()

	t.Run("read_file full", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestFSServer(t)

		res := callTool(t, s, "read_file", map[string]any{"path": "a.txt"})

		text := resultText(t, res)
		assert.Equal(t, "     1\tl1\n     2\tl2\n     3\tl3", text)
	})

	t.Run("read_file offset and limit", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestFSServer(t)

		res := callTool(t, s, "read_file", map[string]any{"path": "a.txt", "offset": 2, "limit": 1})

		text := resultText(t, res)
		assert.Equal(t, "     2\tl2", text)
	})

	t.Run("read_file tail", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestFSServer(t)

		res := callTool(t, s, "read_file", map[string]any{"path": "a.txt", "tail": 1})

		text := resultText(t, res)
		assert.Equal(t, "     3\tl3", text)
	})

	t.Run("read_file binary is rejected", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestFSServer(t)

		res := callTool(t, s, "read_file", map[string]any{"path": "bin.dat"})

		assert.True(t, res.IsError)
	})

	t.Run("list_dir depth 1", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestFSServer(t)

		res := callTool(t, s, "list_dir", map[string]any{"depth": 1})

		text := resultText(t, res)
		assert.NotContains(t, text, "b.go")
		assert.NotContains(t, text, ".hidden")
	})

	t.Run("list_dir depth 2", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestFSServer(t)

		res := callTool(t, s, "list_dir", map[string]any{"depth": 2})

		text := resultText(t, res)
		assert.Contains(t, text, "sub/b.go")
	})

	t.Run("list_dir include_hidden", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestFSServer(t)

		res := callTool(t, s, "list_dir", map[string]any{"depth": 1, "include_hidden": true})

		text := resultText(t, res)
		assert.Contains(t, text, ".hidden")
	})

	t.Run("glob", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestFSServer(t)

		res := callTool(t, s, "glob", map[string]any{"pattern": "**/*.go"})

		text := resultText(t, res)
		assert.Equal(t, "sub/b.go", text)
	})

	t.Run("grep matches", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestFSServer(t)

		res := callTool(t, s, "grep", map[string]any{"pattern": "l2"})

		text := resultText(t, res)
		assert.Equal(t, "a.txt:2:l2", text)
	})

	t.Run("grep ignore_case", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestFSServer(t)

		res := callTool(t, s, "grep", map[string]any{"pattern": "L2", "ignore_case": true})

		text := resultText(t, res)
		assert.Equal(t, "a.txt:2:l2", text)
	})

	t.Run("grep files_only", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestFSServer(t)

		res := callTool(t, s, "grep", map[string]any{"pattern": "l2", "files_only": true})

		text := resultText(t, res)
		assert.Equal(t, "a.txt", text)
	})

	t.Run("grep count", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestFSServer(t)

		res := callTool(t, s, "grep", map[string]any{"pattern": "l2", "count": true})

		text := resultText(t, res)
		assert.Equal(t, "a.txt:1", text)
	})

	t.Run("grep context", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestFSServer(t)

		res := callTool(t, s, "grep", map[string]any{"pattern": "l2", "context": 1})

		text := resultText(t, res)
		assert.Contains(t, text, "a.txt-1-l1")
		assert.Contains(t, text, "a.txt-3-l3")
	})

	t.Run("stat file", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestFSServer(t)

		res := callTool(t, s, "stat", map[string]any{"path": "a.txt"})

		text := resultText(t, res)
		assert.Contains(t, text, "lines: 3")
	})

	t.Run("diff_files", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestFSServer(t)

		res := callTool(t, s, "diff_files", map[string]any{"path_a": "a.txt", "path_b": "sub/b.go"})

		text := resultText(t, res)
		assert.Contains(t, text, "-l1")
		assert.Contains(t, text, "+package b")
	})

	t.Run("system_info", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestFSServer(t)

		res := callTool(t, s, "system_info", map[string]any{})

		text := resultText(t, res)
		assert.Contains(t, text, "cwd: ")
	})

	t.Run("path escape is rejected", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestFSServer(t)

		tests := []struct {
			name string
			args map[string]any
		}{
			{"read_file", map[string]any{"path": "../x"}},
			{"list_dir", map[string]any{"path": "../x"}},
			{"glob", map[string]any{"pattern": "*", "path": "../x"}},
			{"grep", map[string]any{"pattern": "x", "path": "../x"}},
			{"stat", map[string]any{"path": "../x"}},
			{"diff_files", map[string]any{"path_a": "../x", "path_b": "a.txt"}},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				res := callTool(t, s, tc.name, tc.args)

				require.True(t, res.IsError)
				textContent, ok := res.Content[0].(mcp.TextContent)
				require.True(t, ok)
				assert.Contains(t, textContent.Text, "escapes")
			})
		}
	})

	t.Run("truncation", func(t *testing.T) {
		t.Parallel()
		ws := newTestWorkspace(t)
		require.NoError(t, os.WriteFile(filepath.Join(ws.root, "a.txt"), []byte("l1\nl2\nl3\n"), 0o644))

		s := server.NewMCPServer("t", "0")
		newFSTools(ws, 5, false, zerolog.Nop()).register(s)

		res := callTool(t, s, "read_file", map[string]any{"path": "a.txt"})

		text := resultText(t, res)
		assert.True(t, len(text) > 5)
		assert.Contains(t, text, "[truncated]")
		assert.Equal(t, "[truncated]", text[len(text)-len("[truncated]"):])
	})

	t.Run("registration", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestFSServer(t)

		tools := s.ListTools()

		names := []string{"read_file", "list_dir", "glob", "grep", "stat", "diff_files", "system_info"}
		assert.Len(t, tools, len(names))
		for _, name := range names {
			assert.Contains(t, tools, name)
		}
	})
}
