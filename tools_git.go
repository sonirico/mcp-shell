package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog"
)

type gitTools struct {
	ws            *workspace
	executor      *CommandExecutor
	writesEnabled bool
	logger        zerolog.Logger
}

func newGitTools(ws *workspace, executor *CommandExecutor, writesEnabled bool, logger zerolog.Logger) *gitTools {
	return &gitTools{
		ws:            ws,
		executor:      executor,
		writesEnabled: writesEnabled,
		logger:        logger.With().Str("component", "git_tools").Logger(),
	}
}

func (t *gitTools) register(s *server.MCPServer) {
	s.AddTool(
		mcp.NewTool(
			"git_status",
			mcp.WithDescription("Show the working tree status"),
		),
		t.gitStatus,
	)

	s.AddTool(
		mcp.NewTool(
			"git_log",
			mcp.WithDescription("Show commit logs"),
			mcp.WithNumber("max_count", mcp.DefaultNumber(20), mcp.Description("Maximum number of commits to show")),
			mcp.WithString("ref", mcp.DefaultString("HEAD"), mcp.Description("Commit or ref to start from")),
			mcp.WithString("path", mcp.DefaultString(""), mcp.Description("Restrict log to this path, relative to the workspace root")),
			mcp.WithString("author", mcp.DefaultString(""), mcp.Description("Filter by author")),
			mcp.WithString("grep", mcp.DefaultString(""), mcp.Description("Filter by commit message pattern")),
			mcp.WithString("since", mcp.DefaultString(""), mcp.Description("Only commits after this date")),
			mcp.WithString("until", mcp.DefaultString(""), mcp.Description("Only commits before this date")),
			mcp.WithBoolean("oneline", mcp.DefaultBool(false), mcp.Description("One line per commit")),
			mcp.WithBoolean("follow", mcp.DefaultBool(false), mcp.Description("Follow file history across renames")),
		),
		t.gitLog,
	)

	s.AddTool(
		mcp.NewTool(
			"git_diff",
			mcp.WithDescription("Show changes between commits, the working tree, or the index"),
			mcp.WithString("ref", mcp.DefaultString(""), mcp.Description("Base ref to diff from")),
			mcp.WithString("ref_to", mcp.DefaultString(""), mcp.Description("Ref to diff to, requires ref")),
			mcp.WithBoolean("staged", mcp.DefaultBool(false), mcp.Description("Show staged changes")),
			mcp.WithString("path", mcp.DefaultString(""), mcp.Description("Restrict diff to this path, relative to the workspace root")),
			mcp.WithBoolean("stat_only", mcp.DefaultBool(false), mcp.Description("Show only the diffstat")),
			mcp.WithBoolean("name_only", mcp.DefaultBool(false), mcp.Description("Show only changed file names")),
		),
		t.gitDiff,
	)

	s.AddTool(
		mcp.NewTool(
			"git_show",
			mcp.WithDescription("Show a commit or a file at a given ref"),
			mcp.WithString("ref", mcp.DefaultString("HEAD"), mcp.Description("Commit or ref to show")),
			mcp.WithString("path", mcp.DefaultString(""), mcp.Description("File to show, relative to the workspace root")),
			mcp.WithBoolean("stat_only", mcp.DefaultBool(false), mcp.Description("Show only the diffstat")),
		),
		t.gitShow,
	)

	s.AddTool(
		mcp.NewTool(
			"git_blame",
			mcp.WithDescription("Show what revision and author last modified each line of a file"),
			mcp.WithString("path", mcp.Required(), mcp.Description("File to blame, relative to the workspace root")),
			mcp.WithString("ref", mcp.DefaultString("HEAD"), mcp.Description("Commit or ref to blame at")),
			mcp.WithNumber("line_start", mcp.DefaultNumber(0), mcp.Description("First line to blame, 1-based")),
			mcp.WithNumber("line_end", mcp.DefaultNumber(0), mcp.Description("Last line to blame, 1-based")),
		),
		t.gitBlame,
	)

	s.AddTool(
		mcp.NewTool(
			"git_branches",
			mcp.WithDescription("List branches"),
			mcp.WithBoolean("all", mcp.DefaultBool(false), mcp.Description("Include remote-tracking branches")),
			mcp.WithBoolean("merged", mcp.DefaultBool(false), mcp.Description("Only branches merged into HEAD")),
		),
		t.gitBranches,
	)

	s.AddTool(
		mcp.NewTool(
			"git_tags",
			mcp.WithDescription("List tags"),
			mcp.WithString("pattern", mcp.DefaultString(""), mcp.Description("Only list tags matching this pattern")),
		),
		t.gitTags,
	)

	s.AddTool(
		mcp.NewTool(
			"git_rev_parse",
			mcp.WithDescription("Resolve a ref to a commit hash"),
			mcp.WithString("ref", mcp.Required(), mcp.Description("Ref to resolve")),
		),
		t.gitRevParse,
	)

	s.AddTool(
		mcp.NewTool(
			"git_ls_files",
			mcp.WithDescription("List tracked (or untracked) files"),
			mcp.WithString("path", mcp.DefaultString(""), mcp.Description("Restrict listing to this path, relative to the workspace root")),
			mcp.WithBoolean("untracked", mcp.DefaultBool(false), mcp.Description("List untracked files instead of tracked ones")),
		),
		t.gitLsFiles,
	)

	s.AddTool(
		mcp.NewTool(
			"git_stash_list",
			mcp.WithDescription("List the stash entries"),
		),
		t.gitStashList,
	)

	s.AddTool(
		mcp.NewTool(
			"git_remotes",
			mcp.WithDescription("List remotes and their URLs"),
		),
		t.gitRemotes,
	)
}

func validateRef(ref string) error {
	if ref == "" {
		return fmt.Errorf("invalid ref %q", ref)
	}
	if ref[0] == '-' {
		return fmt.Errorf("invalid ref %q", ref)
	}
	for i := 0; i < len(ref); i++ {
		if ref[i] < 0x20 || ref[i] == 0x7f {
			return fmt.Errorf("invalid ref %q", ref)
		}
	}
	return nil
}

// relPath resolves path against the workspace and converts it back to a path
// relative to the workspace root, for use as a git pathspec after "--". The
// result is rejected if it starts with "-": even placed after "--", such a
// pathspec risks being reinterpreted as a flag by git's option parser.
func (t *gitTools) relPath(path string) (string, error) {
	abs, err := t.ws.resolve(path)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(t.ws.root, abs)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(rel, "-") {
		return "", fmt.Errorf("path %q resembles a flag", path)
	}
	return rel, nil
}

func (t *gitTools) run(ctx context.Context, toolName string, argv []string) (*mcp.CallToolResult, error) {
	result, err := t.executor.run(ctx, argv, false)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if result.ExitCode != 0 {
		return mcp.NewToolResultError(fmt.Sprintf("%s (exit %d): %s", toolName, result.ExitCode, result.Stderr)), nil
	}
	return mcp.NewToolResultText(result.Stdout), nil
}

func (t *gitTools) gitStatus(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	argv := []string{"git", "status", "--porcelain=v2", "--branch"}
	return t.run(ctx, "git_status", argv)
}

func (t *gitTools) gitLog(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	maxCount := req.GetInt("max_count", 20)
	ref := req.GetString("ref", "HEAD")
	path := req.GetString("path", "")
	author := req.GetString("author", "")
	grep := req.GetString("grep", "")
	since := req.GetString("since", "")
	until := req.GetString("until", "")
	oneline := req.GetBool("oneline", false)
	follow := req.GetBool("follow", false)

	if err := validateRef(ref); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	argv := []string{"git", "log", "--no-color", fmt.Sprintf("-n%d", maxCount)}
	if oneline {
		argv = append(argv, "--oneline")
	} else {
		argv = append(argv, "--format=%H%n%an <%ae>%n%ad%n%n%B")
	}
	if author != "" {
		argv = append(argv, "--author="+author)
	}
	if grep != "" {
		argv = append(argv, "--grep="+grep)
	}
	if since != "" {
		argv = append(argv, "--since="+since)
	}
	if until != "" {
		argv = append(argv, "--until="+until)
	}
	if follow {
		argv = append(argv, "--follow")
	}
	argv = append(argv, "--end-of-options", ref)

	if path != "" {
		rel, err := t.relPath(path)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		argv = append(argv, "--", rel)
	}

	return t.run(ctx, "git_log", argv)
}

func (t *gitTools) gitDiff(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ref := req.GetString("ref", "")
	refTo := req.GetString("ref_to", "")
	staged := req.GetBool("staged", false)
	path := req.GetString("path", "")
	statOnly := req.GetBool("stat_only", false)
	nameOnly := req.GetBool("name_only", false)

	if ref != "" {
		if err := validateRef(ref); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
	}
	if refTo != "" {
		if err := validateRef(refTo); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
	}

	argv := []string{"git", "diff", "--no-color"}
	if statOnly {
		argv = append(argv, "--stat")
	}
	if nameOnly {
		argv = append(argv, "--name-only")
	}
	if staged {
		argv = append(argv, "--cached")
	}
	if ref != "" {
		argv = append(argv, "--end-of-options", ref)
		if refTo != "" {
			argv = append(argv, refTo)
		}
	}
	if path != "" {
		rel, err := t.relPath(path)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		argv = append(argv, "--", rel)
	}

	return t.run(ctx, "git_diff", argv)
}

func (t *gitTools) gitShow(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ref := req.GetString("ref", "HEAD")
	path := req.GetString("path", "")
	statOnly := req.GetBool("stat_only", false)

	if err := validateRef(ref); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	if path != "" && !statOnly {
		rel, err := t.relPath(path)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		argv := []string{"git", "show", "--no-color", "--end-of-options", ref + ":" + rel}
		return t.run(ctx, "git_show", argv)
	}

	argv := []string{"git", "show", "--no-color"}
	if statOnly {
		argv = append(argv, "--stat")
	}
	argv = append(argv, "--end-of-options", ref)
	if path != "" {
		rel, err := t.relPath(path)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		argv = append(argv, "--", rel)
	}

	return t.run(ctx, "git_show", argv)
}

func (t *gitTools) gitBlame(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path, err := req.RequireString("path")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	ref := req.GetString("ref", "HEAD")
	lineStart := req.GetInt("line_start", 0)
	lineEnd := req.GetInt("line_end", 0)

	if err := validateRef(ref); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	rel, err := t.relPath(path)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	argv := []string{"git", "blame"}
	if lineStart > 0 && lineEnd > 0 {
		argv = append(argv, fmt.Sprintf("-L%d,%d", lineStart, lineEnd))
	}
	// git blame's revision parser mishandles "--end-of-options <ref> -- <path>"
	// together (it reports "bad revision" on the path), so the path is passed
	// directly after ref instead of behind a literal "--". relPath already
	// rejects any resolved path starting with "-", so this stays safe.
	argv = append(argv, "--end-of-options", ref, rel)

	return t.run(ctx, "git_blame", argv)
}

func (t *gitTools) gitBranches(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	all := req.GetBool("all", false)
	merged := req.GetBool("merged", false)

	argv := []string{"git", "branch", "--list", "--no-color"}
	if all {
		argv = append(argv, "-a")
	}
	if merged {
		argv = append(argv, "--merged")
	}

	return t.run(ctx, "git_branches", argv)
}

func (t *gitTools) gitTags(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	pattern := req.GetString("pattern", "")

	if pattern != "" {
		if err := validateRef(pattern); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
	}

	argv := []string{"git", "tag", "--list"}
	if pattern != "" {
		argv = append(argv, pattern)
	}

	return t.run(ctx, "git_tags", argv)
}

func (t *gitTools) gitRevParse(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ref, err := req.RequireString("ref")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	if err := validateRef(ref); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	argv := []string{"git", "rev-parse", "--verify", "--end-of-options", ref}

	return t.run(ctx, "git_rev_parse", argv)
}

func (t *gitTools) gitLsFiles(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path := req.GetString("path", "")
	untracked := req.GetBool("untracked", false)

	argv := []string{"git", "ls-files"}
	if untracked {
		argv = append(argv, "--others", "--exclude-standard")
	}
	if path != "" {
		rel, err := t.relPath(path)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		argv = append(argv, "--", rel)
	}

	return t.run(ctx, "git_ls_files", argv)
}

func (t *gitTools) gitStashList(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	argv := []string{"git", "stash", "list", "--no-color"}
	return t.run(ctx, "git_stash_list", argv)
}

func (t *gitTools) gitRemotes(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	argv := []string{"git", "remote", "-v"}
	return t.run(ctx, "git_remotes", argv)
}
