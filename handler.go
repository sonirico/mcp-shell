package main

import (
	"context"
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/rs/zerolog"
)

type ShellHandler struct {
	executor *CommandExecutor
	logger   zerolog.Logger
}

func newShellHandler(
	executor *CommandExecutor,
	logger zerolog.Logger,
) *ShellHandler {
	return &ShellHandler{
		executor: executor,
		logger:   logger.With().Str("component", "handler").Logger(),
	}
}

func (h *ShellHandler) handle(
	ctx context.Context,
	request mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
	command, err := request.RequireString("command")
	if err != nil {
		h.logger.Error().Err(err).Msg("Missing command parameter")
		return mcp.NewToolResultError("Missing 'command' parameter"), nil
	}

	h.logger.Info().Str("command", command).Msg("Received shell command request")

	useBase64 := request.GetBool("base64", false)

	result, err := h.executor.runShell(ctx, command, useBase64)
	if err != nil {
		h.logger.Error().
			Err(err).
			Str("command", command).
			Msg("Command execution failed")
		return mcp.NewToolResultError(err.Error()), nil
	}

	response := map[string]interface{}{
		"status":         result.Status,
		"exit_code":      result.ExitCode,
		"stdout":         result.Stdout,
		"stderr":         result.Stderr,
		"command":        result.Command,
		"execution_time": result.ExecutionTime.String(),
	}

	jsonBytes, err := json.Marshal(response)
	if err != nil {
		h.logger.Error().Err(err).Msg("Failed to marshal response")
		return mcp.NewToolResultError("Failed to marshal result to JSON"), nil
	}

	h.logger.Debug().
		Str("command", command).
		Str("status", result.Status).
		Msg("Request handled successfully")

	return mcp.NewToolResultText(string(jsonBytes)), nil
}
