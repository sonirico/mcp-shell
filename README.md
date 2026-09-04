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
mode and registers only typed tools: file reads, `grep`/`glob`, git inspection,
and (opt-in) file/git writes and operator-defined scripts. There is no raw
shell command. You only need a config file to change the defaults below. To
run fully unrestricted you must opt in explicitly:

```bash
MCP_SHELL_ALLOW_UNSAFE=1 mcp-shell   # disables secure mode; the only tool is shell_exec
```

To customize the policy, point to a YAML config:

```bash
export MCP_SHELL_SEC_CONFIG_FILE=/path/to/security.yaml
mcp-shell
```

**Secure mode** (default) — typed tools only, every path confined to `working_directory`:

```yaml
security:
  enabled: true
  working_directory: /tmp/mcp-workspace
  max_execution_time: 30s
  max_output_size: 1048576
  run_as_user: ""
  audit_log: true

  # Expose file and git write tools (write_file, edit_file, mkdir, move,
  # delete, git_add, git_commit, git_switch, git_restore, git_stash). Off by
  # default.
  writes_enabled: false

  # Operator-defined scripts exposed through the run_script tool. The client
  # picks a name; the argv is yours and cannot be altered.
  # scripts:
  #   test: ["go", "test", "./..."]
  #   lint: ["golangci-lint", "run"]
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

## Tools

Secure mode (the default) registers these typed tools. `*` marks a required
parameter.

| Tool | Parameters | Available |
|------|------------|-----------|
| `read_file` | path*, offset, limit, tail | always |
| `list_dir` | path, depth, include_hidden | always |
| `glob` | pattern*, path, newer_than, max_results | always |
| `grep` | pattern*, path, glob, ignore_case, context, files_only, count, max_results | always |
| `stat` | path* | always |
| `diff_files` | path_a*, path_b* | always |
| `system_info` | | always |
| `git_status` | | always |
| `git_log` | max_count, ref, path, author, grep, since, until, oneline, follow | always |
| `git_diff` | ref, ref_to, staged, path, stat_only, name_only | always |
| `git_show` | ref, path, stat_only | always |
| `git_blame` | path*, ref, line_start, line_end | always |
| `git_branches` | all, merged | always |
| `git_tags` | pattern | always |
| `git_rev_parse` | ref* | always |
| `git_ls_files` | path, untracked | always |
| `git_stash_list` | | always |
| `git_remotes` | | always |
| `write_file` | path*, content*, append | writes_enabled |
| `edit_file` | path*, old_string*, new_string*, replace_all | writes_enabled |
| `mkdir` | path* | writes_enabled |
| `move` | from*, to* | writes_enabled |
| `delete` | path*, recursive | writes_enabled |
| `git_add` | paths, all | writes_enabled |
| `git_commit` | message*, all | writes_enabled |
| `git_switch` | branch*, create | writes_enabled |
| `git_restore` | paths*, staged | writes_enabled |
| `git_stash` | action*, message | writes_enabled |
| `run_script` | name* | scripts |

Every path parameter is resolved against `working_directory` (symlinks
followed); anything outside it is rejected. Git paths and refs are passed
positionally and validated: a ref starting with `-` is rejected. There are no
network tools; push, fetch and clone are not offered.

**Unrestricted mode**: `shell_exec` exists only with `MCP_SHELL_ALLOW_UNSAFE=1`, runs the command through `bash -c` with no validation, by design, and it is the only tool registered in that mode.

---

## Environment variables

| Variable | Description |
|----------|-------------|
| `MCP_SHELL_SEC_CONFIG_FILE` | Path to security YAML (overrides built-in secure defaults) |
| `MCP_SHELL_ALLOW_UNSAFE` | Set `1` (or `true`) to disable secure mode and expose `shell_exec` instead of the typed tools (opt-in) |
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

- **Default**: Secure mode. The server builds every command's argv itself; the
  client never supplies a shell string. Only typed tools are registered.
- **Path confinement**: every path parameter is resolved against
  `working_directory`, symlinks followed, and anything that resolves outside
  it is rejected.
- **Git hardening**: paths are passed after `--`, refs after
  `--end-of-options`, and a ref starting with `-` is rejected. Git runs with
  `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `core.fsmonitor`,
  `core.pager` and `core.hooksPath` neutralised, and `--no-ext-diff
  --no-textconv` on log/diff/show/blame.
- **Minimal environment**: child processes get only `PATH`, `HOME` and `LANG`,
  never the server's own environment or `.env` secrets.
- **Writes and scripts are opt-in**: `writes_enabled: true` exposes the
  file/git write tools; a non-empty `scripts` map exposes `run_script`. Both
  are off by default.
- **Unrestricted**: only via `MCP_SHELL_ALLOW_UNSAFE=1`. The only tool
  registered is `shell_exec`, which runs `bash -c` with no validation. Fine
  for local dev, dangerous otherwise.
- **Docker**: Runs as non-root, Alpine-based. Use it in production. Best paired with an OS sandbox (read-only FS, dropped caps) as defense-in-depth.

Threat model, guarantees, and the scope for vulnerability reports live in [SECURITY.md](SECURITY.md). Read it before opening an advisory.

---

## Migrating from 0.x

Secure mode no longer validates a `shell_exec` command string; it exposes
typed tools instead. A config file's `security:` block no longer accepts:

| Removed key | Replacement |
|-------------|-------------|
| `use_shell_execution` | not needed; typed tools never shell out |
| `allowed_executables` | not needed; each tool runs a fixed, server-built argv |
| `allowed_commands` | not needed; same as above |
| `blocked_commands` | not needed; same as above |
| `blocked_patterns` | not needed; same as above |

Loading a config file that still sets one of these fails at startup with an
error naming the key. There is no more "legacy mode" and no
`security-legacy.yaml` example. If you need raw shell access, set
`MCP_SHELL_ALLOW_UNSAFE=1` to get `shell_exec` back; it is no longer
constrained by the `security:` block at all.

---

## Contributing

Fork, branch, `make fmt test`, open a PR.
