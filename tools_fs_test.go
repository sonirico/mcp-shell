package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

	t.Run("required argument missing", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestFSServer(t)

		tests := []struct {
			label string
			tool  string
			args  map[string]any
		}{
			{"read_file", "read_file", map[string]any{}},
			{"glob", "glob", map[string]any{}},
			{"grep", "grep", map[string]any{}},
			{"stat", "stat", map[string]any{}},
			{"diff_files missing path_a", "diff_files", map[string]any{"path_b": "a.txt"}},
			{"diff_files missing path_b", "diff_files", map[string]any{"path_a": "a.txt"}},
		}

		for _, tc := range tests {
			t.Run(tc.label, func(t *testing.T) {
				t.Parallel()
				res := callTool(t, s, tc.tool, tc.args)

				assert.True(t, res.IsError)
			})
		}
	})

	t.Run("read_file offset and limit clamp out of range", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestFSServer(t)

		tests := []struct {
			label string
			args  map[string]any
			want  string
		}{
			{"tail larger than file", map[string]any{"path": "a.txt", "tail": 100}, "     1\tl1\n     2\tl2\n     3\tl3"},
			{"offset zero clamps to start", map[string]any{"path": "a.txt", "offset": 0}, "     1\tl1\n     2\tl2\n     3\tl3"},
			{"offset past end yields nothing", map[string]any{"path": "a.txt", "offset": 100}, ""},
			{"limit past end clamps to file length", map[string]any{"path": "a.txt", "offset": 2, "limit": 100}, "     2\tl2\n     3\tl3"},
		}

		for _, tc := range tests {
			t.Run(tc.label, func(t *testing.T) {
				t.Parallel()
				res := callTool(t, s, "read_file", tc.args)

				assert.Equal(t, tc.want, resultText(t, res))
			})
		}
	})

	t.Run("read_file nonexistent path errors", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestFSServer(t)

		res := callTool(t, s, "read_file", map[string]any{"path": "missing.txt"})

		assert.True(t, res.IsError)
	})

	t.Run("list_dir nonexistent path errors", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestFSServer(t)

		res := callTool(t, s, "list_dir", map[string]any{"path": "missing"})

		assert.True(t, res.IsError)
	})

	t.Run("list_dir skips hidden directories", func(t *testing.T) {
		t.Parallel()
		ws := newTestWorkspace(t)
		require.NoError(t, os.MkdirAll(filepath.Join(ws.root, ".hiddendir"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(ws.root, ".hiddendir", "f.txt"), []byte("x"), 0o644))

		s := server.NewMCPServer("t", "0")
		newFSTools(ws, 0, false, zerolog.Nop()).register(s)

		res := callTool(t, s, "list_dir", map[string]any{"depth": 3})

		text := resultText(t, res)
		assert.NotContains(t, text, "hiddendir")
	})

	t.Run("list_dir skips .git even with hidden entries included", func(t *testing.T) {
		t.Parallel()
		ws := newTestWorkspace(t)
		require.NoError(t, os.MkdirAll(filepath.Join(ws.root, ".git"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(ws.root, ".git", "config"), []byte("x"), 0o644))

		s := server.NewMCPServer("t", "0")
		newFSTools(ws, 0, false, zerolog.Nop()).register(s)

		res := callTool(t, s, "list_dir", map[string]any{"depth": 3, "include_hidden": true})

		text := resultText(t, res)
		assert.NotContains(t, text, "config")
	})

	t.Run("list_dir skips directories beyond depth", func(t *testing.T) {
		t.Parallel()
		ws := newTestWorkspace(t)
		require.NoError(t, os.MkdirAll(filepath.Join(ws.root, "sub", "inner"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(ws.root, "sub", "inner", "f.txt"), []byte("x"), 0o644))

		s := server.NewMCPServer("t", "0")
		newFSTools(ws, 0, false, zerolog.Nop()).register(s)

		res := callTool(t, s, "list_dir", map[string]any{"depth": 1})

		text := resultText(t, res)
		assert.Contains(t, text, "sub\t")
		assert.NotContains(t, text, "inner")
	})

	t.Run("list_dir reports symlinks", func(t *testing.T) {
		t.Parallel()
		ws := newTestWorkspace(t)
		require.NoError(t, os.WriteFile(filepath.Join(ws.root, "target.txt"), []byte("x"), 0o644))
		require.NoError(t, os.Symlink(filepath.Join(ws.root, "target.txt"), filepath.Join(ws.root, "link.txt")))

		s := server.NewMCPServer("t", "0")
		newFSTools(ws, 0, false, zerolog.Nop()).register(s)

		res := callTool(t, s, "list_dir", map[string]any{})

		text := resultText(t, res)
		assert.Contains(t, text, "link.txt\tl\t")
	})

	t.Run("glob filters", func(t *testing.T) {
		t.Parallel()
		ws := newTestWorkspace(t)

		writeAt := func(rel string, mtime time.Time) {
			p := filepath.Join(ws.root, rel)
			require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
			require.NoError(t, os.WriteFile(p, []byte("x"), 0o644))
			require.NoError(t, os.Chtimes(p, mtime, mtime))
		}
		now := time.Now()
		writeAt("old.txt", now.Add(-2*time.Hour))
		writeAt("new.txt", now)
		writeAt(".git/inside.txt", now)

		s := server.NewMCPServer("t", "0")
		newFSTools(ws, 0, false, zerolog.Nop()).register(s)

		t.Run("newer_than excludes stale matches", func(t *testing.T) {
			t.Parallel()
			res := callTool(t, s, "glob", map[string]any{"pattern": "*.txt", "newer_than": "1h"})

			text := resultText(t, res)
			assert.Contains(t, text, "new.txt")
			assert.NotContains(t, text, "old.txt")
		})

		t.Run("newer_than invalid duration errors", func(t *testing.T) {
			t.Parallel()
			res := callTool(t, s, "glob", map[string]any{"pattern": "*.txt", "newer_than": "bogus"})

			assert.True(t, res.IsError)
		})

		t.Run("invalid pattern errors", func(t *testing.T) {
			t.Parallel()
			res := callTool(t, s, "glob", map[string]any{"pattern": "["})

			assert.True(t, res.IsError)
		})

		t.Run("skips matches under .git", func(t *testing.T) {
			t.Parallel()
			res := callTool(t, s, "glob", map[string]any{"pattern": "**/*.txt"})

			text := resultText(t, res)
			assert.NotContains(t, text, ".git")
		})

		t.Run("max_results truncates", func(t *testing.T) {
			t.Parallel()
			res := callTool(t, s, "glob", map[string]any{"pattern": "*.txt", "max_results": 1})

			text := resultText(t, res)
			assert.Len(t, strings.Split(text, "\n"), 1)
		})
	})

	t.Run("glob broken symlink errors", func(t *testing.T) {
		t.Parallel()
		ws := newTestWorkspace(t)
		require.NoError(t, os.Symlink(
			filepath.Join(ws.root, "missing-target"),
			filepath.Join(ws.root, "broken.txt"),
		))

		s := server.NewMCPServer("t", "0")
		newFSTools(ws, 0, false, zerolog.Nop()).register(s)

		res := callTool(t, s, "glob", map[string]any{"pattern": "*.txt"})

		assert.True(t, res.IsError)
	})

	t.Run("grep edge cases", func(t *testing.T) {
		t.Parallel()

		t.Run("invalid regex errors", func(t *testing.T) {
			t.Parallel()
			s, _ := newTestFSServer(t)
			res := callTool(t, s, "grep", map[string]any{"pattern": "("})

			assert.True(t, res.IsError)
		})

		t.Run("nonexistent path errors", func(t *testing.T) {
			t.Parallel()
			s, _ := newTestFSServer(t)
			res := callTool(t, s, "grep", map[string]any{"pattern": "x", "path": "missing"})

			assert.True(t, res.IsError)
		})

		t.Run("skips .git and honours glob filter", func(t *testing.T) {
			t.Parallel()
			ws := newTestWorkspace(t)
			require.NoError(t, os.WriteFile(filepath.Join(ws.root, "regular.txt"), []byte("MATCH\n"), 0o644))
			require.NoError(t, os.WriteFile(filepath.Join(ws.root, "other.go"), []byte("MATCH\n"), 0o644))
			require.NoError(t, os.MkdirAll(filepath.Join(ws.root, ".git"), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(ws.root, ".git", "hidden.txt"), []byte("MATCH\n"), 0o644))

			s := server.NewMCPServer("t", "0")
			newFSTools(ws, 0, false, zerolog.Nop()).register(s)

			res := callTool(t, s, "grep", map[string]any{"pattern": "MATCH", "glob": "*.txt"})

			text := resultText(t, res)
			assert.Contains(t, text, "regular.txt")
			assert.NotContains(t, text, ".git")
			assert.NotContains(t, text, "other.go")
		})

		t.Run("invalid glob filter errors", func(t *testing.T) {
			t.Parallel()
			s, _ := newTestFSServer(t)
			res := callTool(t, s, "grep", map[string]any{"pattern": "x", "glob": "["})

			assert.True(t, res.IsError)
		})

		t.Run("context clamps and separates non-contiguous matches", func(t *testing.T) {
			t.Parallel()
			ws := newTestWorkspace(t)
			require.NoError(t, os.WriteFile(
				filepath.Join(ws.root, "ctx.txt"),
				[]byte("MATCH\nMATCH\nplain\nplain\nplain\nMATCH\n"),
				0o644,
			))

			s := server.NewMCPServer("t", "0")
			newFSTools(ws, 0, false, zerolog.Nop()).register(s)

			res := callTool(t, s, "grep", map[string]any{"pattern": "MATCH", "context": 1})

			text := resultText(t, res)
			assert.Contains(t, text, "--")
			assert.Equal(t, 1, strings.Count(text, "--"))
		})

		t.Run("max_results stops within and across files", func(t *testing.T) {
			t.Parallel()
			ws := newTestWorkspace(t)
			require.NoError(t, os.WriteFile(filepath.Join(ws.root, "many.txt"), []byte("M\nM\nM\n"), 0o644))
			require.NoError(t, os.WriteFile(filepath.Join(ws.root, "other.txt"), []byte("M\n"), 0o644))

			s := server.NewMCPServer("t", "0")
			newFSTools(ws, 0, false, zerolog.Nop()).register(s)

			res := callTool(t, s, "grep", map[string]any{"pattern": "M", "max_results": 2})

			text := resultText(t, res)
			assert.NotContains(t, text, "other.txt")
			assert.Equal(t, 2, strings.Count(text, "many.txt"))
		})

		t.Run("unreadable file errors", func(t *testing.T) {
			if os.Geteuid() == 0 {
				t.Skip("root ignores file permissions")
			}
			t.Parallel()
			ws := newTestWorkspace(t)
			p := filepath.Join(ws.root, "secret.txt")
			require.NoError(t, os.WriteFile(p, []byte("x"), 0o644))
			require.NoError(t, os.Chmod(p, 0o000))
			t.Cleanup(func() { _ = os.Chmod(p, 0o644) })

			s := server.NewMCPServer("t", "0")
			newFSTools(ws, 0, false, zerolog.Nop()).register(s)

			res := callTool(t, s, "grep", map[string]any{"pattern": "x"})

			assert.True(t, res.IsError)
		})
	})

	t.Run("stat nonexistent path errors", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestFSServer(t)

		res := callTool(t, s, "stat", map[string]any{"path": "missing.txt"})

		assert.True(t, res.IsError)
	})

	t.Run("stat directory", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestFSServer(t)

		res := callTool(t, s, "stat", map[string]any{"path": "sub"})

		text := resultText(t, res)
		assert.Contains(t, text, "type: dir")
	})

	t.Run("stat unreadable file errors", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root ignores file permissions")
		}
		t.Parallel()
		ws := newTestWorkspace(t)
		p := filepath.Join(ws.root, "secret.txt")
		require.NoError(t, os.WriteFile(p, []byte("x"), 0o644))
		require.NoError(t, os.Chmod(p, 0o000))
		t.Cleanup(func() { _ = os.Chmod(p, 0o644) })

		s := server.NewMCPServer("t", "0")
		newFSTools(ws, 0, false, zerolog.Nop()).register(s)

		res := callTool(t, s, "stat", map[string]any{"path": "secret.txt"})

		assert.True(t, res.IsError)
	})

	t.Run("diff_files path_b escape is rejected", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestFSServer(t)

		res := callTool(t, s, "diff_files", map[string]any{"path_a": "a.txt", "path_b": "../x"})

		require.True(t, res.IsError)
	})

	t.Run("diff_files nonexistent paths error", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestFSServer(t)

		tests := []struct {
			label string
			args  map[string]any
		}{
			{"path_a missing", map[string]any{"path_a": "missing.txt", "path_b": "a.txt"}},
			{"path_b missing", map[string]any{"path_a": "a.txt", "path_b": "missing.txt"}},
		}

		for _, tc := range tests {
			t.Run(tc.label, func(t *testing.T) {
				t.Parallel()
				res := callTool(t, s, "diff_files", tc.args)

				assert.True(t, res.IsError)
			})
		}
	})

	t.Run("system_info finds enclosing git root", func(t *testing.T) {
		t.Parallel()
		ws := newTestWorkspace(t)
		require.NoError(t, os.MkdirAll(filepath.Join(ws.root, ".git"), 0o755))

		s := server.NewMCPServer("t", "0")
		newFSTools(ws, 0, false, zerolog.Nop()).register(s)

		res := callTool(t, s, "system_info", map[string]any{})

		text := resultText(t, res)
		assert.Contains(t, text, "git_root: "+ws.root)
	})
}

func TestIsBinary(t *testing.T) {
	t.Parallel()

	t.Run("clean input longer than the sniff window is not binary", func(t *testing.T) {
		t.Parallel()

		data := bytes.Repeat([]byte("a"), binarySniffLen+100)

		assert.False(t, isBinary(data))
	})
}
