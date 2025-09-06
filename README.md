# mcp-shell 🐚
[![Trust Score](https://archestra.ai/mcp-catalog/api/badge/quality/sonirico/mcp-shell)](https://archestra.ai/mcp-catalog/sonirico__mcp-shell)

A robust Model Context Protocol (MCP) server that provides secure shell command execution capabilities to AI assistants and other MCP clients. In other words: the brain thinks, this runs the commands.

> 🧠💥🖥️ *Think of `mcp-shell` as the command-line actuator for your LLM.*
> While language models reason about the world, `mcp-shell` is what lets them **touch it**.

## What is this?

This tool creates a bridge between AI systems and your shell environment through the standardized MCP protocol. It exposes the system shell as a structured tool, enabling autonomous workflows, tool-assisted reasoning, and real-world problem solving.

Built on top of the official MCP SDK for Go: [mark3labs/mcp-go](https://github.com/mark3labs/mcp-go).

It's written in Go, integrates directly with `mcp-go`, and provides a clean path from thought to execution. I'm aware similar projects exist — this one’s mine. It solves the problem the way I want it solved: minimal, composable, auditable.

Out of the box it runs isolated via Docker, but that's just a start. The roadmap includes support for optional jailing mechanisms like `chroot`, namespaces, and syscall-level confinement — without depending on Docker for everything.

## Features

- **🔒 Security First**: Configurable command allowlists, blocklists, and execution constraints
- **🐳 Docker Ready**: Lightweight Alpine-based container for secure isolation
- **📊 Structured Responses**: JSON-formatted output with stdout, stderr, exit codes, and execution metadata
- **🔄 Binary Data Support**: Optional base64 encoding for handling binary command output
- **⚡ Performance Monitoring**: Execution time tracking and resource limits
- **📋 Audit Logging**: Complete command execution audit trail with structured logging
- **🎯 Context Aware**: Supports command execution with proper context cancellation
- **⚙️ Environment Configuration**: Full configuration via environment variables

## Security Features

- **Command Validation**: Allowlist/blocklist with regex pattern matching
- **Execution Limits**: Configurable timeouts and output size limits
- **User Isolation**: Run commands as unprivileged users
- **Working Directory**: Restrict execution to specific directories
- **Audit Trail**: Complete logging of all command executions
- **Resource Limits**: Memory and CPU usage constraints

## Quick Start

### Prerequisites

- Go 1.23 or later
- Unix-like system (Linux, macOS, WSL)
- Docker (optional, for containerized deployment)

### Installation

```bash
git clone https://github.com/sonirico/mcp-shell
cd mcp-shell
make install
```

### Basic Usage

```bash
# Run with default configuration (if installed system-wide)
mcp-shell

# Or run locally
make run

# Run with security enabled (creates temporary config)
make run-secure

# Run with custom config file
MCP_SHELL_SEC_CONFIG_FILE=security.json mcp-shell

# Run with environment overrides
MCP_SHELL_LOG_LEVEL=debug mcp-shell
```

### Docker Deployment (Recommended)

```bash
# Build Docker image
make docker-build

# Run in secure container
make docker-run-secure

# Run with shell access for debugging
make docker-shell
```

## Configuration

### Environment Variables

Basic server and logging configuration via environment variables:

#### Server Configuration

- `MCP_SHELL_SERVER_NAME`: Server name (default: "mcp-shell 🐚")
- `MCP_SHELL_VERSION`: Server version (set at compile time)

#### Logging Configuration

- `MCP_SHELL_LOG_LEVEL`: Log level (debug, info, warn, error, fatal)
- `MCP_SHELL_LOG_FORMAT`: Log format (json, console)
- `MCP_SHELL_LOG_OUTPUT`: Log output (stdout, stderr, file)

#### Configuration File

- `MCP_SHELL_SEC_CONFIG_FILE`: Path to YAML configuration file

### Security Configuration (YAML Only)

Security settings are configured exclusively via YAML configuration file:

```bash
export MCP_SHELL_SEC_CONFIG_FILE=security.yaml
```

Example security configuration file:

```yaml
security:
  enabled: true
  allowed_commands:
    - ls
    - cat
    - grep
    - find
    - echo
  blocked_commands:
    - rm -rf
    - sudo
    - chmod
  blocked_patterns:
    - 'rm\s+.*-rf.*'
    - 'sudo\s+.*'
  max_execution_time: 30s
  working_directory: /tmp/mcp-workspace
  max_output_size: 1048576
  audit_log: true
```

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
  "command": "executed command",
  "execution_time": "100ms",
  "security_info": {
    "security_enabled": true,
    "working_dir": "/tmp/mcp-workspace",
    "timeout_applied": true
  }
}
```

## Integration Examples

### With Claude Desktop

```json
{
  "mcpServers": {
    "shell": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "mcp-shell:latest"],
      "env": {
        "MCP_SHELL_SECURITY_ENABLED": "true",
        "MCP_SHELL_LOG_LEVEL": "info"
      }
    }
  }
}
```

### Production Deployment

```bash
# Build and install
make build
sudo make install-bin

# Set environment variables for basic config
export MCP_SHELL_LOG_LEVEL=info
export MCP_SHELL_LOG_FORMAT=json
export MCP_SHELL_SEC_CONFIG_FILE=/etc/mcp-shell/config.json

# Security is configured in the JSON file only
# Run service
mcp-shell
```

## Development

```bash
# Install dependencies and dev tools
make install dev-tools

# Format code
make fmt

# Run tests
make test

# Run linter
make lint

# Build for release
make release

# Generate config example
make config-example
```

## Security Considerations

### ⚠️ Important Security Notes

1. **Default Mode**: Runs with **full system access** when security is disabled (which is, of course, a terrible idea — unless you're into that).
2. **Container Isolation**: Use Docker deployment for additional security layers
3. **User Privileges**: Run as non-root user in production
4. **Network Access**: Commands can access network unless explicitly restricted
5. **File System**: Can read/write files based on user permissions

### Recommended Production Setup

Create `security.yaml`:

```yaml
security:
  enabled: true
  allowed_commands:
    - ls
    - cat
    - head
    - tail
    - grep
    - find
    - wc
    - sort
    - uniq
  blocked_patterns:
    - 'rm\s+.*-rf.*'
    - 'sudo\s+.*'
    - 'chmod\s+(777|666)'
    - '>/dev/'
    - 'curl.*\|.*sh'
  max_execution_time: 10s
  working_directory: /tmp/mcp-workspace
  max_output_size: 524288
  audit_log: true
```

Set environment:
```bash
export MCP_SHELL_SEC_CONFIG_FILE=security.yaml
export MCP_SHELL_LOG_LEVEL=info
export MCP_SHELL_LOG_FORMAT=json
```

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

Ensure code is formatted (`make fmt`) and passes tests (`make test`).

## License

MIT License - See LICENSE file for details.
