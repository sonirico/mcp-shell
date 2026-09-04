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
