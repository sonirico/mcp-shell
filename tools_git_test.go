package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestRepo(t *testing.T) *workspace {
	t.Helper()

	ws := newTestWorkspace(t)

	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = ws.root
		cmd.Env = []string{
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL=/dev/null",
			"HOME=" + ws.root,
			"PATH=" + os.Getenv("PATH"),
		}
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
	}

	runGit("init", "-q")
	runGit("config", "user.email", "t@t")
	runGit("config", "user.name", "t")
	runGit("config", "commit.gpgsign", "false")

	require.NoError(t, os.WriteFile(filepath.Join(ws.root, "a.txt"), []byte("one\n"), 0o644))
	runGit("add", "a.txt")
	runGit("commit", "-q", "-m", "first")

	f, err := os.OpenFile(filepath.Join(ws.root, "a.txt"), os.O_APPEND|os.O_WRONLY, 0o644)
	require.NoError(t, err)
	_, err = f.WriteString("two\n")
	require.NoError(t, err)
	require.NoError(t, f.Close())
	require.NoError(t, os.WriteFile(filepath.Join(ws.root, "b.txt"), []byte("b\n"), 0o644))
	runGit("add", "a.txt", "b.txt")
	runGit("commit", "-q", "-m", "second")

	return ws
}

func newTestGitServer(t *testing.T) (*server.MCPServer, *workspace) {
	t.Helper()

	ws := newTestRepo(t)
	executor := newCommandExecutor(SecurityConfig{
		Enabled:          true,
		WorkingDirectory: ws.root,
		MaxExecutionTime: 30 * time.Second,
	}, zerolog.Nop())

	s := server.NewMCPServer("t", "0")
	newGitTools(ws, executor, false, zerolog.Nop()).register(s)

	return s, ws
}

func TestGitTools(t *testing.T) {
	t.Parallel()

	t.Run("git_status contains branch header", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestGitServer(t)

		res := callTool(t, s, "git_status", map[string]any{})

		text := resultText(t, res)
		assert.Contains(t, text, "# branch.head")
	})

	t.Run("git_log default contains both commits", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestGitServer(t)

		res := callTool(t, s, "git_log", map[string]any{})

		text := resultText(t, res)
		assert.Contains(t, text, "first")
		assert.Contains(t, text, "second")
	})

	t.Run("git_log oneline gives exactly 2 lines", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestGitServer(t)

		res := callTool(t, s, "git_log", map[string]any{"oneline": true})

		text := resultText(t, res)
		assert.Len(t, strings.Split(text, "\n"), 2)
	})

	t.Run("git_log max_count 1 gives 1 line", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestGitServer(t)

		res := callTool(t, s, "git_log", map[string]any{"oneline": true, "max_count": 1})

		text := resultText(t, res)
		assert.Len(t, strings.Split(text, "\n"), 1)
	})

	t.Run("git_diff ref to ref contains b.txt", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestGitServer(t)

		res := callTool(t, s, "git_diff", map[string]any{"ref": "HEAD~1", "ref_to": "HEAD"})

		text := resultText(t, res)
		assert.Contains(t, text, "b.txt")
	})

	t.Run("git_diff name_only lists b.txt", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestGitServer(t)

		res := callTool(t, s, "git_diff", map[string]any{"ref": "HEAD~1", "ref_to": "HEAD", "name_only": true})

		text := resultText(t, res)
		assert.Contains(t, text, "b.txt")
	})

	t.Run("git_show HEAD contains second", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestGitServer(t)

		res := callTool(t, s, "git_show", map[string]any{})

		text := resultText(t, res)
		assert.Contains(t, text, "second")
	})

	t.Run("git_show ref path returns blob content", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestGitServer(t)

		res := callTool(t, s, "git_show", map[string]any{"ref": "HEAD", "path": "a.txt"})

		text := resultText(t, res)
		assert.Equal(t, "one\ntwo", text)
	})

	t.Run("git_blame a.txt has 2 lines", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestGitServer(t)

		res := callTool(t, s, "git_blame", map[string]any{"path": "a.txt"})

		text := resultText(t, res)
		assert.Len(t, strings.Split(text, "\n"), 2)
	})

	t.Run("git_blame line range has 1 line", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestGitServer(t)

		res := callTool(t, s, "git_blame", map[string]any{"path": "a.txt", "line_start": 2, "line_end": 2})

		text := resultText(t, res)
		assert.Len(t, strings.Split(text, "\n"), 1)
	})

	t.Run("git_branches non-empty", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestGitServer(t)

		res := callTool(t, s, "git_branches", map[string]any{})

		text := resultText(t, res)
		assert.NotEmpty(t, text)
	})

	t.Run("git_rev_parse HEAD returns 40 hex chars", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestGitServer(t)

		res := callTool(t, s, "git_rev_parse", map[string]any{"ref": "HEAD"})

		text := resultText(t, res)
		assert.Regexp(t, regexp.MustCompile(`^[0-9a-f]{40}$`), text)
	})

	t.Run("git_ls_files contains both files", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestGitServer(t)

		res := callTool(t, s, "git_ls_files", map[string]any{})

		text := resultText(t, res)
		assert.Contains(t, text, "a.txt")
		assert.Contains(t, text, "b.txt")
	})

	t.Run("git_ls_files untracked contains c.txt", func(t *testing.T) {
		t.Parallel()
		s, ws := newTestGitServer(t)
		require.NoError(t, os.WriteFile(filepath.Join(ws.root, "c.txt"), []byte("c\n"), 0o644))

		res := callTool(t, s, "git_ls_files", map[string]any{"untracked": true})

		text := resultText(t, res)
		assert.Contains(t, text, "c.txt")
	})

	t.Run("git_stash_list empty", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestGitServer(t)

		res := callTool(t, s, "git_stash_list", map[string]any{})

		text := resultText(t, res)
		assert.Empty(t, text)
	})

	t.Run("git_remotes empty", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestGitServer(t)

		res := callTool(t, s, "git_remotes", map[string]any{})

		text := resultText(t, res)
		assert.Empty(t, text)
	})

	t.Run("git_tags contains v1 after tag", func(t *testing.T) {
		t.Parallel()
		s, ws := newTestGitServer(t)
		cmd := exec.Command("git", "tag", "v1")
		cmd.Dir = ws.root
		cmd.Env = []string{
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL=/dev/null",
			"HOME=" + ws.root,
			"PATH=" + os.Getenv("PATH"),
		}
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))

		res := callTool(t, s, "git_tags", map[string]any{})

		text := resultText(t, res)
		assert.Contains(t, text, "v1")
	})

	t.Run("invalid ref is rejected", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestGitServer(t)

		tests := []struct {
			tool string
			args map[string]any
		}{
			{"git_log", map[string]any{"ref": "-x"}},
			{"git_log", map[string]any{"ref": "--output=/tmp/x"}},
			{"git_show", map[string]any{"ref": "-x"}},
			{"git_show", map[string]any{"ref": "--output=/tmp/x"}},
			{"git_rev_parse", map[string]any{"ref": "-x"}},
			{"git_rev_parse", map[string]any{"ref": "--output=/tmp/x"}},
		}

		for _, tc := range tests {
			t.Run(tc.tool, func(t *testing.T) {
				t.Parallel()
				res := callTool(t, s, tc.tool, tc.args)

				require.True(t, res.IsError)
				textContent, ok := res.Content[0].(mcp.TextContent)
				require.True(t, ok)
				assert.Contains(t, textContent.Text, "invalid ref")
			})
		}
	})

	t.Run("path escape is rejected", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestGitServer(t)

		tests := []struct {
			tool string
			args map[string]any
		}{
			{"git_log", map[string]any{"path": "../x"}},
			{"git_blame", map[string]any{"path": "../x"}},
			{"git_ls_files", map[string]any{"path": "../x"}},
		}

		for _, tc := range tests {
			t.Run(tc.tool, func(t *testing.T) {
				t.Parallel()
				res := callTool(t, s, tc.tool, tc.args)

				require.True(t, res.IsError)
				textContent, ok := res.Content[0].(mcp.TextContent)
				require.True(t, ok)
				assert.Contains(t, textContent.Text, "escapes")
			})
		}
	})

	t.Run("git_log path resembling a flag is rejected", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestGitServer(t)

		passwdFirstLine, err := os.ReadFile("/etc/passwd")
		require.NoError(t, err)
		firstLine := strings.SplitN(string(passwdFirstLine), "\n", 2)[0]

		res := callTool(t, s, "git_log", map[string]any{"path": "--cont=/etc/passwd"})

		require.True(t, res.IsError)
		textContent, ok := res.Content[0].(mcp.TextContent)
		require.True(t, ok)
		assert.NotContains(t, textContent.Text, firstLine)
	})

	t.Run("registration lists exactly the git tools", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestGitServer(t)

		tools := s.ListTools()

		names := []string{
			"git_status", "git_log", "git_diff", "git_show", "git_blame",
			"git_branches", "git_tags", "git_rev_parse", "git_ls_files",
			"git_stash_list", "git_remotes",
		}
		assert.Len(t, tools, len(names))
		for _, name := range names {
			assert.Contains(t, tools, name)
		}
	})
}
