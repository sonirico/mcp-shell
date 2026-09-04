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

func TestRun(t *testing.T) {
	t.Run("workspace resolution error is wrapped and returned", func(t *testing.T) {
		// Arrange
		dir := t.TempDir()
		blocker := filepath.Join(dir, "blocker")
		require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o644))

		cfgPath := filepath.Join(dir, "sec.yaml")
		cfgYAML := fmt.Sprintf("security:\n  working_directory: %q\n", filepath.Join(blocker, "sub"))
		require.NoError(t, os.WriteFile(cfgPath, []byte(cfgYAML), 0o644))

		t.Setenv("MCP_SHELL_SEC_CONFIG_FILE", cfgPath)
		t.Setenv("MCP_SHELL_ALLOW_UNSAFE", "")

		// Act
		err := run()

		// Assert
		require.Error(t, err)
		assert.Contains(t, err.Error(), "workspace:")
	})

	t.Run("security enabled registers fs tools and serves until stdin closes", func(t *testing.T) {
		// Arrange
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "sec.yaml")
		cfgYAML := fmt.Sprintf("security:\n  working_directory: %q\n", dir)
		require.NoError(t, os.WriteFile(cfgPath, []byte(cfgYAML), 0o644))

		t.Setenv("MCP_SHELL_SEC_CONFIG_FILE", cfgPath)
		t.Setenv("MCP_SHELL_ALLOW_UNSAFE", "")

		r, w, err := os.Pipe()
		require.NoError(t, err)
		origStdin := os.Stdin
		os.Stdin = r
		t.Cleanup(func() { os.Stdin = origStdin })
		require.NoError(t, w.Close())

		done := make(chan error, 1)
		go func() { done <- run() }()

		// Act & Assert
		select {
		case err := <-done:
			assert.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("run() did not return after stdin closed")
		}
	})

	t.Run("writes_enabled registers write tools and serves until stdin closes", func(t *testing.T) {
		// Arrange
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "sec.yaml")
		cfgYAML := fmt.Sprintf("security:\n  working_directory: %q\n  writes_enabled: true\n", dir)
		require.NoError(t, os.WriteFile(cfgPath, []byte(cfgYAML), 0o644))

		t.Setenv("MCP_SHELL_SEC_CONFIG_FILE", cfgPath)
		t.Setenv("MCP_SHELL_ALLOW_UNSAFE", "")

		r, w, err := os.Pipe()
		require.NoError(t, err)
		origStdin := os.Stdin
		os.Stdin = r
		t.Cleanup(func() { os.Stdin = origStdin })
		require.NoError(t, w.Close())

		done := make(chan error, 1)
		go func() { done <- run() }()

		// Act & Assert
		select {
		case err := <-done:
			assert.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("run() did not return after stdin closed")
		}
	})
}
