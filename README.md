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

**Secure mode is the default.** With no config file, `mcp-shell` boots in secure
mode restricted to a narrow allowlist of read-only utilities (`ls`, `cat`,
`grep`, `find`, `head`, `tail`, ...). You only need a config file to widen or
change that policy. To run fully unrestricted you must opt in explicitly:

```bash
MCP_SHELL_ALLOW_UNSAFE=true mcp-shell   # disables all validation - do not use in production
```

To customize the policy, point to a YAML config:

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
  # Allowlisting is necessary but not sufficient: an executable also has to be
  # classified as safe (a known data-only utility, or governed by an argument
  # policy like git/find/sort/uniq). Interpreters (bash, python, ...) and
  # command wrappers (env, timeout, nice, xargs, ...) are unclassified and get
  # rejected even if listed here; mcp-shell warns at startup about dead entries.
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
| `MCP_SHELL_SEC_CONFIG_FILE` | Path to security YAML (overrides built-in secure defaults) |
| `MCP_SHELL_ALLOW_UNSAFE` | Set `true` to disable all validation and run unrestricted (opt-in) |
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

- **Default**: Secure mode, restricted to a narrow allowlist of read-only utilities. No interpreters.
- **Secure mode** (`use_shell_execution: false`): the command is parsed into a shell AST and only a single, fully-literal simple command is accepted (no pipes, lists, substitution, redirection or globs); its executable must be on the allowlist **and** be classified as safe: either a known data-only utility (`ls`, `cat`, `grep`, ...) or governed by a deny-by-default argument policy (`git`, `find`, `sort`, `uniq`), where only explicitly safe flags are accepted (`git -c`/`config`, `find -exec`/`-fls`, `sort -o`/`--compress-program` are rejected). Anything unclassified - interpreters, command wrappers like `env`/`timeout`/`xargs`, `tar`, or any other binary - is rejected even when allowlisted. Git is limited to read-only subcommands, run with the diff and textconv drivers suppressed and a minimal environment. The child inherits no server or `.env` secrets. This is an early-reject layer, not a sandbox.
- **Unrestricted**: Only via `MCP_SHELL_ALLOW_UNSAFE=true`. Full access; fine for local dev, dangerous otherwise.
- **Docker**: Runs as non-root, Alpine-based. Use it in production. Best paired with an OS sandbox (read-only FS, dropped caps) as defense-in-depth.

Threat model, guarantees, and the scope for vulnerability reports live in [SECURITY.md](SECURITY.md). Read it before opening an advisory.

---

## Contributing

Fork, branch, `make fmt test`, open a PR.
