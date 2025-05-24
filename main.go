package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer(
		"mcp-shell 🐚",
		"0.2.0",
		server.WithToolCapabilities(false),
	)

	shellTool := mcp.NewTool(
		"shell_exec",
		mcp.WithDescription(
			"Execute shell commands with full system access. Returns structured JSON with stdout, stderr, exit code and execution status.",
		),
		mcp.WithString("command",
			mcp.Required(),
			mcp.Description("Shell command to execute"),
		),
		mcp.WithBoolean(
			"base64",
			mcp.DefaultBool(false),
			mcp.Description(
				"Return stdout/stderr as base64-encoded strings (useful for binary data)",
			),
		),
	)

	s.AddTool(shellTool, shellHandler)

	if err := server.ServeStdio(s); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}

type ShellResult struct {
	Status   string `json:"status"`
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	Command  string `json:"command"`
}

func shellHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	command, err := request.RequireString("command")
	if err != nil {
		return mcp.NewToolResultError("Missing 'command' parameter"), nil
	}

	useBase64 := request.GetBool("base64", false)

	// Execute command
	cmd := exec.CommandContext(ctx, "bash", "-c", command)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err = cmd.Run()

	// Determine exit code and status
	exitCode := 0
	status := "success"
	if err != nil {
		status = "error"
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = -1
		}
	}

	// Process output based on encoding preference
	var stdout, stderr string
	if useBase64 {
		stdout = base64.StdEncoding.EncodeToString(stdoutBuf.Bytes())
		stderr = base64.StdEncoding.EncodeToString(stderrBuf.Bytes())
	} else {
		stdout = strings.TrimRight(stdoutBuf.String(), "\n")
		stderr = strings.TrimRight(stderrBuf.String(), "\n")
	}

	result := ShellResult{
		Status:   status,
		ExitCode: exitCode,
		Stdout:   stdout,
		Stderr:   stderr,
		Command:  command,
	}

	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return mcp.NewToolResultError("Failed to marshal result to JSON"), nil
	}

	return mcp.NewToolResultText(string(jsonBytes)), nil
}
