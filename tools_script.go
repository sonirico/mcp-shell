package main

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog"
)

type scriptTools struct {
	scripts  map[string][]string
	executor *CommandExecutor
	logger   zerolog.Logger
}

func newScriptTools(scripts map[string][]string, executor *CommandExecutor, logger zerolog.Logger) *scriptTools {
	return &scriptTools{
		scripts:  scripts,
		executor: executor,
		logger:   logger.With().Str("component", "script_tools").Logger(),
	}
}

func (t *scriptTools) register(s *server.MCPServer) {
	if len(t.scripts) == 0 {
		return
	}

	names := make([]string, 0, len(t.scripts))
	for name := range t.scripts {
		names = append(names, name)
	}
	sort.Strings(names)

	s.AddTool(
		mcp.NewTool(
			"run_script",
			mcp.WithDescription("Run an operator-defined script by name. Available: "+strings.Join(names, ", ")),
			mcp.WithString("name", mcp.Required(), mcp.Description("Name of the script to run")),
		),
		t.runScript,
	)
}

func (t *scriptTools) runScript(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name, err := req.RequireString("name")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	argv, ok := t.scripts[name]
	if !ok {
		names := make([]string, 0, len(t.scripts))
		for n := range t.scripts {
			names = append(names, n)
		}
		sort.Strings(names)
		return mcp.NewToolResultError(fmt.Sprintf("unknown script %q; available: %s", name, strings.Join(names, ", "))), nil
	}

	argvCopy := make([]string, len(argv))
	copy(argvCopy, argv)

	result, err := t.executor.run(ctx, argvCopy, false)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if result.ExitCode != 0 {
		return mcp.NewToolResultError(fmt.Sprintf("%s (exit %d): %s", "run_script", result.ExitCode, result.Stderr)), nil
	}
	return mcp.NewToolResultText(result.Stdout), nil
}
