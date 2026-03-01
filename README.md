# mcp-shell

[![Trust Score](https://archestra.ai/mcp-catalog/api/badge/quality/sonirico/mcp-shell)](https://archestra.ai/mcp-catalog/sonirico__mcp-shell)
[![glama](https://glama.ai/mcp/servers/@sonirico/mcp-shell/badge)](https://glama.ai/mcp/servers/@sonirico/mcp-shell)

MCP server that runs shell commands. Your LLM gets a tool; you get control over what runs and how.

Built on [mark3labs/mcp-go](https://github.com/mark3labs/mcp-go). Written in Go.

---

## Run it

**Docker** (easiest):

```bash
docker run -it --rm -v /tmp/mcp-workspace:/tmp/mcp-workspace sonirico/mcp-shell:latest
```

**From source**:

```bash
git clone https://github.com/sonirico/mcp-shell && cd mcp-shell
make install
mcp-shell
```

---

## Configure it

Security is off by default. To enable it, point to a YAML config:

```bash
export MCP_SHELL_SEC_CONFIG_FILE=/path/to/security.yaml
mcp-shell
```

**Secure mode** (recommended) — no shell interpretation, executable allowlist only:

```yaml
security:
  enabled: true
  use_shell_execution: false
  allowed_executables:
    - ls
    - cat
    - grep
    - find
    - echo
    - /usr/bin/git
  blocked_patterns:          # optional: restrict args on allowed commands
    - '(^|\s)remote\s+(-v|--verbose)(\s|$)'
  max_execution_time: 30s
  max_output_size: 1048576
  working_directory: /tmp/mcp-workspace
  audit_log: true
```

**Legacy mode** — shell execution, allowlist/blocklist by command string (vulnerable to injection if not careful):

```yaml
security:
  enabled: true
  use_shell_execution: true
  allowed_commands: [ls, cat, grep, echo]
  blocked_patterns: ['rm\s+-rf', 'sudo\s+']
  max_execution_time: 30s
  audit_log: true
```

---

## Wire it up

**Claude Desktop** — add to your MCP config:

```json
{
  "mcpServers": {
    "shell": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "sonirico/mcp-shell:latest"],
      "env": { "MCP_SHELL_LOG_LEVEL": "info" }
    }
  }
}
```

For custom config, mount the file and set the env:

```json
{
  "command": "docker",
  "args": ["run", "--rm", "-i", "-v", "/path/to/security.yaml:/etc/mcp-shell/security.yaml", "-e", "MCP_SHELL_SEC_CONFIG_FILE=/etc/mcp-shell/security.yaml", "sonirico/mcp-shell:latest"]
}
```

---

## Tool API

| Parameter | Type | Description |
|-----------|------|-------------|
| `command` | string | Shell command to run (required) |
| `base64` | boolean | Encode stdout/stderr as base64 (default: false) |

Response includes `status`, `exit_code`, `stdout`, `stderr`, `command`, `execution_time`, and optional `security_info`.

---

## Environment variables

| Variable | Description |
|----------|-------------|
| `MCP_SHELL_SEC_CONFIG_FILE` | Path to security YAML |
| `MCP_SHELL_SERVER_NAME` | Server name (default: "mcp-shell 🐚") |
| `MCP_SHELL_LOG_LEVEL` | debug, info, warn, error, fatal |
| `MCP_SHELL_LOG_FORMAT` | json, console |
| `MCP_SHELL_LOG_OUTPUT` | stdout, stderr, file |

---

## Development

```bash
make install dev-tools   # deps + goimports, golines
make fmt test lint
make docker-build       # build image locally
make release            # binary + docker image
```

---

## Security

- **Default**: No restrictions. Commands run with full access. Fine for local dev; dangerous otherwise.
- **Secure mode** (`use_shell_execution: false`): Executable allowlist, no shell parsing. Blocks injection.
- **Docker**: Runs as non-root, Alpine-based. Use it in production.

---

## Contributing

Fork, branch, `make fmt test`, open a PR.
