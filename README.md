# mcp-shell 🐚

A robust Model Context Protocol (MCP) server that provides secure shell command execution capabilities to AI assistants and other MCP clients.

## What is this?

This tool creates a bridge between AI systems and your shell environment through the standardized MCP protocol. It allows AI assistants to execute shell commands and receive structured responses, enabling autonomous system interaction and real-world problem solving.

## Features

- **Full Shell Access**: Execute any shell command with complete system access
- **Structured Responses**: JSON-formatted output with stdout, stderr, exit codes, and status
- **Binary Data Support**: Optional base64 encoding for handling binary command output
- **Error Handling**: Proper exit code detection and error status reporting
- **Context Aware**: Supports command execution with proper context cancellation
- **Security Conscious**: Transparent about providing full system access

## Technical Implementation

- Built with Go using `os/exec` package for command execution
- Uses [mcp-go](https://github.com/mark3labs/mcp-go) for MCP protocol implementation
- Captures stdout, stderr, and exit codes separately
- Supports both text and base64-encoded output modes

## Quick Start

### Prerequisites

- Go 1.23 or later
- Unix-like system (Linux, macOS, WSL)
- Bash shell available in PATH

### Installation

```bash
git clone https://github.com/sonirico/mcp-shell
cd mcp-shell
make install
make build
```

### Usage

Start the MCP server:

```bash
make run
# or
./bin/mcp-shell
```

The server communicates via stdin/stdout using the MCP protocol.

## Tool Parameters

- `command` (string, required): Shell command to execute
- `base64` (boolean, optional): Return stdout/stderr as base64-encoded strings

## Response Format

```json
{
  "status": "success|error",
  "exit_code": 0,
  "stdout": "command output",
  "stderr": "error output", 
  "command": "executed command"
}
```

### With base64 encoding:

```json
{
  "status": "success",
  "exit_code": 0,
  "stdout": "SGVsbG8gV29ybGQK",
  "stderr": "",
  "command": "echo 'Hello World'"
}
```

## Development

```bash
# Install dependencies
make install

# Format code
make fmt

# Build binary
make build

# Run tests
make test

# Clean artifacts
make clean

# Install dev tools
make dev-tools

# See all commands
make help
```

## Integration Examples

### With Claude Desktop

Add to your MCP configuration:

```json
{
  "mcpServers": {
    "shell": {
      "command": "/path/to/mcp-shell/bin/mcp-shell"
    }
  }
}
```

### Programmatic Usage

The server expects MCP-formatted JSON messages via stdin and responds via stdout.

## Security Notice

⚠️ **SECURITY WARNING**: This tool provides unrestricted shell access to AI systems. Only use with trusted AI assistants and in controlled environments. Be aware that executed commands have the same privileges as the user running the server.

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions welcome! Please ensure code is properly formatted (`make fmt`) and follows Go best practices.
