package main

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/pmezard/go-difflib/difflib"
	"github.com/rs/zerolog"
)

const binarySniffLen = 8192

type fsTools struct {
	ws            *workspace
	maxOutput     int
	writesEnabled bool
	logger        zerolog.Logger
}

func newFSTools(ws *workspace, maxOutput int, writesEnabled bool, logger zerolog.Logger) *fsTools {
	return &fsTools{
		ws:            ws,
		maxOutput:     maxOutput,
		writesEnabled: writesEnabled,
		logger:        logger.With().Str("component", "fs_tools").Logger(),
	}
}

func (t *fsTools) register(s *server.MCPServer) {
	s.AddTool(
		mcp.NewTool(
			"read_file",
			mcp.WithDescription("Read a text file, optionally by line offset/limit or tail"),
			mcp.WithString("path", mcp.Required(), mcp.Description("Path relative to the workspace root")),
			mcp.WithNumber("offset", mcp.DefaultNumber(1), mcp.Description("1-based first line to read")),
			mcp.WithNumber("limit", mcp.DefaultNumber(0), mcp.Description("Number of lines to read, 0 for all")),
			mcp.WithNumber("tail", mcp.DefaultNumber(0), mcp.Description("Number of trailing lines to read, overrides offset/limit")),
		),
		t.readFile,
	)

	s.AddTool(
		mcp.NewTool(
			"list_dir",
			mcp.WithDescription("List directory entries up to a given depth"),
			mcp.WithString("path", mcp.DefaultString("."), mcp.Description("Path relative to the workspace root")),
			mcp.WithNumber("depth", mcp.DefaultNumber(1), mcp.Description("Levels below path to descend")),
			mcp.WithBoolean("include_hidden", mcp.DefaultBool(false), mcp.Description("Include dotfiles and dot-directories")),
		),
		t.listDir,
	)

	s.AddTool(
		mcp.NewTool(
			"glob",
			mcp.WithDescription("Find files matching a glob pattern"),
			mcp.WithString("pattern", mcp.Required(), mcp.Description("Doublestar glob pattern")),
			mcp.WithString("path", mcp.DefaultString("."), mcp.Description("Base path relative to the workspace root")),
			mcp.WithString("newer_than", mcp.DefaultString(""), mcp.Description("Only include files modified within this duration, e.g. \"24h\"")),
			mcp.WithNumber("max_results", mcp.DefaultNumber(500), mcp.Description("Maximum number of results")),
		),
		t.glob,
	)

	s.AddTool(
		mcp.NewTool(
			"grep",
			mcp.WithDescription("Search file contents with a regular expression"),
			mcp.WithString("pattern", mcp.Required(), mcp.Description("Regular expression pattern")),
			mcp.WithString("path", mcp.DefaultString("."), mcp.Description("Base path relative to the workspace root")),
			mcp.WithString("glob", mcp.DefaultString(""), mcp.Description("Restrict search to files matching this doublestar pattern")),
			mcp.WithBoolean("ignore_case", mcp.DefaultBool(false), mcp.Description("Case-insensitive matching")),
			mcp.WithNumber("context", mcp.DefaultNumber(0), mcp.Description("Lines of context before/after each match")),
			mcp.WithBoolean("files_only", mcp.DefaultBool(false), mcp.Description("Only list matching file names")),
			mcp.WithBoolean("count", mcp.DefaultBool(false), mcp.Description("Only list match counts per file")),
			mcp.WithNumber("max_results", mcp.DefaultNumber(200), mcp.Description("Maximum number of matches")),
		),
		t.grep,
	)

	s.AddTool(
		mcp.NewTool(
			"stat",
			mcp.WithDescription("Show metadata for a file or directory"),
			mcp.WithString("path", mcp.Required(), mcp.Description("Path relative to the workspace root")),
		),
		t.stat,
	)

	s.AddTool(
		mcp.NewTool(
			"diff_files",
			mcp.WithDescription("Show a unified diff between two files"),
			mcp.WithString("path_a", mcp.Required(), mcp.Description("First file, relative to the workspace root")),
			mcp.WithString("path_b", mcp.Required(), mcp.Description("Second file, relative to the workspace root")),
		),
		t.diffFiles,
	)

	s.AddTool(
		mcp.NewTool(
			"system_info",
			mcp.WithDescription("Show information about the host and workspace"),
		),
		t.systemInfo,
	)
}

func (t *fsTools) output(text string) *mcp.CallToolResult {
	if t.maxOutput > 0 && len(text) > t.maxOutput {
		text = text[:t.maxOutput] + "\n[truncated]"
	}
	return mcp.NewToolResultText(text)
}

func (t *fsTools) readFile(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path, err := req.RequireString("path")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	offset := req.GetInt("offset", 1)
	limit := req.GetInt("limit", 0)
	tail := req.GetInt("tail", 0)

	abs, err := t.ws.resolve(path)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	data, err := os.ReadFile(abs)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if isBinary(data) {
		return mcp.NewToolResultError("binary file"), nil
	}

	lines := strings.Split(string(data), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	var start, end int
	if tail > 0 {
		start = len(lines) - tail
		if start < 0 {
			start = 0
		}
		end = len(lines)
	} else {
		start = offset - 1
		if start < 0 {
			start = 0
		}
		if start > len(lines) {
			start = len(lines)
		}
		if limit > 0 {
			end = start + limit
			if end > len(lines) {
				end = len(lines)
			}
		} else {
			end = len(lines)
		}
	}

	out := make([]string, 0, end-start)
	for i := start; i < end; i++ {
		out = append(out, fmt.Sprintf("%6d\t%s", i+1, lines[i]))
	}

	return t.output(strings.Join(out, "\n")), nil
}

func (t *fsTools) listDir(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path := req.GetString("path", ".")
	depth := req.GetInt("depth", 1)
	includeHidden := req.GetBool("include_hidden", false)

	base, err := t.ws.resolve(path)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	var out []string
	err = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == base {
			return nil
		}

		name := d.Name()
		if !includeHidden && strings.HasPrefix(name, ".") {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() && name == ".git" {
			return fs.SkipDir
		}

		rel, err := filepath.Rel(base, p)
		if err != nil {
			return err
		}

		if strings.Count(rel, string(filepath.Separator))+1 > depth {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		kind := "f"
		info, err := d.Info()
		if err != nil {
			return err
		}
		var size int64
		switch {
		case d.IsDir():
			kind = "d"
		case d.Type()&fs.ModeSymlink != 0:
			kind = "l"
		default:
			size = info.Size()
		}

		out = append(out, fmt.Sprintf("%s\t%s\t%d", rel, kind, size))
		return nil
	})
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	return t.output(strings.Join(out, "\n")), nil
}

func (t *fsTools) glob(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	pattern, err := req.RequireString("pattern")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	path := req.GetString("path", ".")
	newerThan := req.GetString("newer_than", "")
	maxResults := req.GetInt("max_results", 500)

	base, err := t.ws.resolve(path)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	var cutoff time.Time
	if newerThan != "" {
		d, err := time.ParseDuration(newerThan)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		cutoff = time.Now().Add(-d)
	}

	matches, err := doublestar.Glob(os.DirFS(base), pattern)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	type entry struct {
		rel   string
		mtime time.Time
	}
	entries := make([]entry, 0, len(matches))
	for _, m := range matches {
		if isUnderGit(m) {
			continue
		}
		info, err := os.Stat(filepath.Join(base, m))
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		if !cutoff.IsZero() && info.ModTime().Before(cutoff) {
			continue
		}
		entries = append(entries, entry{rel: m, mtime: info.ModTime()})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].mtime.After(entries[j].mtime)
	})

	if len(entries) > maxResults {
		entries = entries[:maxResults]
	}

	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.rel
	}

	return t.output(strings.Join(out, "\n")), nil
}

func (t *fsTools) grep(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	pattern, err := req.RequireString("pattern")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	path := req.GetString("path", ".")
	globPattern := req.GetString("glob", "")
	ignoreCase := req.GetBool("ignore_case", false)
	contextLines := req.GetInt("context", 0)
	filesOnly := req.GetBool("files_only", false)
	countOnly := req.GetBool("count", false)
	maxResults := req.GetInt("max_results", 200)

	base, err := t.ws.resolve(path)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	if ignoreCase {
		pattern = "(?i)" + pattern
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	var out []string
	total := 0
	err = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		if total >= maxResults {
			return nil
		}

		rel, err := filepath.Rel(base, p)
		if err != nil {
			return err
		}
		if globPattern != "" {
			matched, err := doublestar.Match(globPattern, rel)
			if err != nil {
				return err
			}
			if !matched {
				return nil
			}
		}

		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if isBinary(data) {
			return nil
		}

		lines := strings.Split(string(data), "\n")
		if len(lines) > 0 && lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}

		matchedLines := make([]int, 0)
		for i, line := range lines {
			if re.MatchString(line) {
				matchedLines = append(matchedLines, i)
			}
		}
		if len(matchedLines) == 0 {
			return nil
		}

		switch {
		case filesOnly:
			out = append(out, rel)
			total++
		case countOnly:
			out = append(out, fmt.Sprintf("%s:%d", rel, len(matchedLines)))
			total++
		default:
			lastPrinted := -1
			for _, m := range matchedLines {
				if total >= maxResults {
					break
				}
				from := m - contextLines
				if from < 0 {
					from = 0
				}
				to := m + contextLines
				if to > len(lines)-1 {
					to = len(lines) - 1
				}
				if lastPrinted >= 0 && from > lastPrinted+1 {
					out = append(out, "--")
				}
				start := from
				if lastPrinted >= from {
					start = lastPrinted + 1
				}
				for i := start; i <= to; i++ {
					if i == m {
						out = append(out, fmt.Sprintf("%s:%d:%s", rel, i+1, lines[i]))
					} else {
						out = append(out, fmt.Sprintf("%s-%d-%s", rel, i+1, lines[i]))
					}
				}
				lastPrinted = to
				total++
			}
		}

		return nil
	})
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	return t.output(strings.Join(out, "\n")), nil
}

func (t *fsTools) stat(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path, err := req.RequireString("path")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	abs, err := t.ws.resolve(path)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	info, err := os.Stat(abs)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	if info.IsDir() {
		out := fmt.Sprintf(
			"type: dir\nsize: %d\nmtime: %s",
			info.Size(), info.ModTime().Format(time.RFC3339),
		)
		return t.output(out), nil
	}

	data, err := os.ReadFile(abs)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	lines := strings.Count(string(data), "\n")

	out := fmt.Sprintf(
		"size: %d\nmode: %s\nmtime: %s\nlines: %d",
		info.Size(), info.Mode().String(), info.ModTime().Format(time.RFC3339), lines,
	)
	return t.output(out), nil
}

func (t *fsTools) diffFiles(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	pathA, err := req.RequireString("path_a")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	pathB, err := req.RequireString("path_b")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	absA, err := t.ws.resolve(pathA)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	absB, err := t.ws.resolve(pathB)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	dataA, err := os.ReadFile(absA)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	dataB, err := os.ReadFile(absB)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	diff := difflib.UnifiedDiff{
		A:        difflib.SplitLines(string(dataA)),
		B:        difflib.SplitLines(string(dataB)),
		FromFile: pathA,
		ToFile:   pathB,
		Context:  3,
	}
	out, err := difflib.GetUnifiedDiffString(diff)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	return t.output(out), nil
}

func (t *fsTools) systemInfo(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	username := ""
	if u, err := user.Current(); err == nil {
		username = u.Username
	}

	hostname, err := os.Hostname()
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	gitRoot := "none"
	dir := t.ws.root
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			gitRoot = dir
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	out := fmt.Sprintf(
		"cwd: %s\nuser: %s\nhostname: %s\nos: %s\narch: %s\ntime: %s\ngit_root: %s",
		t.ws.root, username, hostname, runtime.GOOS, runtime.GOARCH,
		time.Now().Format(time.RFC3339), gitRoot,
	)
	return t.output(out), nil
}

func isBinary(data []byte) bool {
	n := len(data)
	if n > binarySniffLen {
		n = binarySniffLen
	}
	return bytes.IndexByte(data[:n], 0) != -1
}

func isUnderGit(rel string) bool {
	return rel == ".git" || strings.HasPrefix(rel, ".git"+string(filepath.Separator))
}
