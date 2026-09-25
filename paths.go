package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type workspace struct {
	root string
}

func newWorkspace(root string) (*workspace, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}

	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}

	abs, err := filepath.Abs(resolved)
	if err != nil {
		return nil, err
	}

	return &workspace{root: abs}, nil
}

func (w *workspace) resolve(rel string) (string, error) {
	if rel == "" || rel == "." {
		return w.root, nil
	}

	var candidate string
	if filepath.IsAbs(rel) {
		candidate = filepath.Clean(rel)
	} else {
		candidate = filepath.Clean(filepath.Join(w.root, rel))
	}

	resolved, err := resolveSymlinks(candidate)
	if err != nil {
		return "", err
	}

	if resolved != w.root && !strings.HasPrefix(resolved, w.root+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes the workspace", rel)
	}

	return resolved, nil
}

// resolveForWrite is resolve plus a refusal to hand back any path inside git's
// control surface. The .git directory and .gitattributes files change which
// programs git runs during ordinary read operations (content filters, hooks,
// aliases, pager, external diff). Those files are the server's to own, not the
// client's: a client that could write them could turn a read-only git tool such
// as git_diff into arbitrary command execution. Every mutating filesystem tool
// resolves through here, so the guarantee holds no matter which tool is called.
// Names are compared case-folded: on a case-insensitive filesystem (macOS APFS
// default) ".GIT" and ".gitattributeſ" open the same files (GHSA-vv99-jjh6-3c8x).
func (w *workspace) resolveForWrite(rel string) (string, error) {
	abs, err := w.resolve(rel)
	if err != nil {
		return "", err
	}

	within, err := filepath.Rel(w.root, abs)
	if err != nil {
		return "", err
	}

	for _, seg := range strings.Split(within, string(filepath.Separator)) {
		if strings.EqualFold(seg, ".git") || strings.EqualFold(seg, ".gitattributes") {
			return "", fmt.Errorf("path %q is inside git's control surface and is not writable", rel)
		}
	}

	return abs, nil
}

func resolveSymlinks(candidate string) (string, error) {
	ancestor := candidate
	var suffix []string

	for {
		if _, err := os.Lstat(ancestor); err == nil {
			break
		}

		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			break
		}

		suffix = append([]string{filepath.Base(ancestor)}, suffix...)
		ancestor = parent
	}

	resolvedAncestor, err := filepath.EvalSymlinks(ancestor)
	if err != nil {
		return "", err
	}

	return filepath.Join(append([]string{resolvedAncestor}, suffix...)...), nil
}
