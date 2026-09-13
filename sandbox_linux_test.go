//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"time"

	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMain turns this test binary into the Landlock shim when it is re-exec'd
// with the sandbox argument, so the confinement tests can drive the real shim
// path instead of a stub.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == sandboxArg {
		if err := runSandboxShim(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(127)
		}
	}
	os.Exit(m.Run())
}

func requireLandlock(t *testing.T) {
	t.Helper()
	data, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil || !strings.Contains(string(data), "landlock") {
		t.Skip("landlock not active in this kernel")
	}
}

func TestSandbox_confinesWrites(t *testing.T) {
	requireLandlock(t)

	ws := t.TempDir()
	outside := filepath.Join(t.TempDir(), "canary")
	self, err := os.Executable()
	require.NoError(t, err)

	inside := filepath.Join(ws, "inside")
	script := fmt.Sprintf("touch %q; touch %q", inside, outside)
	cmd := exec.Command(self, sandboxArg, ws, "--", "/bin/sh", "-c", script)

	out, err := cmd.CombinedOutput()

	require.Error(t, err, "sandboxed write outside workspace should fail; output=%s", out)
	_, statIn := os.Stat(inside)
	assert.NoError(t, statIn, "write inside workspace should succeed")
	_, statOut := os.Stat(outside)
	assert.True(t, os.IsNotExist(statOut), "write outside workspace must not land")
}

func TestSandbox_allowsWorkspaceWrites(t *testing.T) {
	requireLandlock(t)

	ws := t.TempDir()
	self, err := os.Executable()
	require.NoError(t, err)

	target := filepath.Join(ws, "sub", "file")
	script := fmt.Sprintf("mkdir -p %q && echo ok > %q", filepath.Join(ws, "sub"), target)
	cmd := exec.Command(self, sandboxArg, ws, "--", "/bin/sh", "-c", script)

	out, err := cmd.CombinedOutput()

	require.NoError(t, err, "workspace write should succeed; output=%s", out)
	data, readErr := os.ReadFile(target)
	require.NoError(t, readErr)
	assert.Equal(t, "ok\n", string(data))
}

// TestGitTools_underSandbox runs the read-only git tools with the Landlock
// sandbox enabled, proving the confinement does not break normal git execution.
// The executor re-execs the test binary as the shim (see TestMain), which
// applies Landlock and then execs git.
func TestGitTools_underSandbox(t *testing.T) {
	requireLandlock(t)

	ws := newTestRepo(t)
	executor := newCommandExecutor(SecurityConfig{
		Enabled:          true,
		WorkingDirectory: ws.root,
		MaxExecutionTime: 30 * time.Second,
		Sandbox:          true,
	}, zerolog.Nop())

	s := server.NewMCPServer("t", "0")
	newGitTools(ws, executor, false, zerolog.Nop()).register(s)

	statusRes := callTool(t, s, "git_status", map[string]any{})
	require.False(t, statusRes.IsError, "git_status should run under the sandbox")

	diffRes := callTool(t, s, "git_diff", map[string]any{})
	require.False(t, diffRes.IsError, "git_diff should run under the sandbox")
}

func TestParseSandboxArgs(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		args    []string
		wantErr bool
	}

	cases := []testCase{
		{name: "well formed", args: []string{"self", sandboxArg, "/ws", "--", "git", "diff"}, wantErr: false},
		{name: "missing separator", args: []string{"self", sandboxArg, "/ws", "git"}, wantErr: true},
		{name: "empty target", args: []string{"self", sandboxArg, "/ws", "--"}, wantErr: true},
		{name: "too short", args: []string{"self", sandboxArg}, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ws, target, err := parseSandboxArgs(tc.args)

			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "/ws", ws)
			assert.Equal(t, []string{"git", "diff"}, target)
		})
	}
}
