package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestWorkspace(t *testing.T) *workspace {
	ws, err := newWorkspace(t.TempDir())
	require.NoError(t, err)
	return ws
}

func TestWorkspace_resolve(t *testing.T) {
	t.Parallel()

	t.Run("empty rel returns root", func(t *testing.T) {
		t.Parallel()
		ws := newTestWorkspace(t)

		got, err := ws.resolve("")

		require.NoError(t, err)
		assert.Equal(t, ws.root, got)
	})

	t.Run("nonexistent relative path joins onto root", func(t *testing.T) {
		t.Parallel()
		ws := newTestWorkspace(t)

		got, err := ws.resolve("a/b.txt")

		require.NoError(t, err)
		assert.Equal(t, filepath.Join(ws.root, "a", "b.txt"), got)
	})

	t.Run("parent traversal escapes workspace", func(t *testing.T) {
		t.Parallel()
		ws := newTestWorkspace(t)

		_, err := ws.resolve("../x")

		require.Error(t, err)
		assert.Contains(t, err.Error(), "escapes")
	})

	t.Run("absolute path outside root escapes workspace", func(t *testing.T) {
		t.Parallel()
		ws := newTestWorkspace(t)
		outside := t.TempDir()

		_, err := ws.resolve(outside)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "escapes")
	})

	t.Run("symlink inside root pointing outside escapes workspace", func(t *testing.T) {
		t.Parallel()
		ws := newTestWorkspace(t)
		link := filepath.Join(ws.root, "etc-link")
		require.NoError(t, os.Symlink("/etc", link))

		_, err := ws.resolve("etc-link")

		require.Error(t, err)
		assert.Contains(t, err.Error(), "escapes")
	})

	t.Run("symlink inside root pointing inside root resolves to target", func(t *testing.T) {
		t.Parallel()
		ws := newTestWorkspace(t)
		target := filepath.Join(ws.root, "target")
		require.NoError(t, os.Mkdir(target, 0o755))
		link := filepath.Join(ws.root, "link")
		require.NoError(t, os.Symlink(target, link))

		got, err := ws.resolve("link")

		require.NoError(t, err)
		resolvedTarget, err := filepath.EvalSymlinks(target)
		require.NoError(t, err)
		assert.Equal(t, resolvedTarget, got)
	})

	t.Run("absolute path inside root resolves to itself", func(t *testing.T) {
		t.Parallel()
		ws := newTestWorkspace(t)
		inside := filepath.Join(ws.root, "inside.txt")

		got, err := ws.resolve(inside)

		require.NoError(t, err)
		assert.Equal(t, inside, got)
	})
}

func TestNewWorkspace(t *testing.T) {
	t.Parallel()

	t.Run("nonexistent dir is created", func(t *testing.T) {
		t.Parallel()
		root := filepath.Join(t.TempDir(), "nested", "dir")

		ws, err := newWorkspace(root)

		require.NoError(t, err)
		info, err := os.Stat(ws.root)
		require.NoError(t, err)
		assert.True(t, info.IsDir())
	})

	t.Run("root is stored symlink-resolved", func(t *testing.T) {
		t.Parallel()
		base := t.TempDir()
		real := filepath.Join(base, "real")
		require.NoError(t, os.Mkdir(real, 0o755))
		link := filepath.Join(base, "link")
		require.NoError(t, os.Symlink(real, link))

		ws, err := newWorkspace(link)

		require.NoError(t, err)
		resolved, err := filepath.EvalSymlinks(link)
		require.NoError(t, err)
		assert.Equal(t, resolved, ws.root)
	})
}

func TestWorkspace_resolveSymlinkLoop(t *testing.T) {
	t.Parallel()
	ws := newTestWorkspace(t)

	a := filepath.Join(ws.root, "a")
	b := filepath.Join(ws.root, "b")
	require.NoError(t, os.Symlink(b, a))
	require.NoError(t, os.Symlink(a, b))

	_, err := ws.resolve("a")

	require.Error(t, err)
}

func TestResolveSymlinks_nonexistentAncestorsToRoot(t *testing.T) {
	t.Parallel()

	got, err := resolveSymlinks("/definitely-nonexistent-xyz-mcpshell/foo/bar")

	require.NoError(t, err)
	assert.Equal(t, "/definitely-nonexistent-xyz-mcpshell/foo/bar", got)
}
