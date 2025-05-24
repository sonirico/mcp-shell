package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/rs/zerolog"
)

type ShellHandler struct {
	validator *SecurityValidator
	executor  *CommandExecutor
	logger    zerolog.Logger
}

func newShellHandler(
	validator *SecurityValidator,
	executor *CommandExecutor,
	logger zerolog.Logger,
) *ShellHandler {
	return &ShellHandler{
		validator: validator,
		executor:  executor,
		logger:    logger.With().Str("component", "handler").Logger(),
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

	if h.validator.isEnabled() {
		h.logger.Info().
			Str("command", command).
			Str("audit", "command_requested").
			Msg("Command execution requested")
	}

	if err := h.validator.validateCommand(command); err != nil {
		h.logger.Warn().
			Err(err).
			Str("command", command).
			Msg("Security validation failed")
		return mcp.NewToolResultError(fmt.Sprintf("Security violation: %s", err.Error())), nil
	}

	useBase64 := request.GetBool("base64", false)

	result, err := h.executor.execute(ctx, command, useBase64)
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

	if result.SecurityInfo != nil {
		response["security_info"] = result.SecurityInfo
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
