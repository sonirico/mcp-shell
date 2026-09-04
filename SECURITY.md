# Security Policy

## Threat model

`mcp-shell` acts on behalf of an untrusted MCP client (typically an LLM that
may be prompt-injected). Secure mode (the default, `security.enabled: true`)
never lets the client supply a shell string: it registers only typed tools,
each of which builds its own fixed argv server-side from a small set of
declared parameters. There is no `shell_exec` in this mode.

What secure mode guarantees:

- **No shell interpretation.** Every tool invokes a specific program with a
  server-constructed argument list. There is no command string to parse,
  inject into, or escape from.
- **Path confinement.** Every path parameter (file tools and git tools alike)
  is resolved against `working_directory` with symlinks followed; a path that
  resolves outside it is rejected.
- **Git hardening.** Paths are passed to git after `--`, refs after
  `--end-of-options`, and a ref starting with `-` is rejected outright. Git
  runs with `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`,
  `-c core.fsmonitor=false -c core.pager=cat -c core.hooksPath=/dev/null`, and
  `--no-ext-diff --no-textconv` on `log`/`diff`/`show`/`blame`, so no
  operator- or attacker-controlled hook, pager, or external diff driver runs.
- **Minimal environment.** Child processes (git and `run_script` alike) get
  only `PATH`, `HOME` and `LANG` - never the server's own environment or any
  `.env` loaded at startup, so a tool cannot recover secrets held by the
  server or exported by the MCP client.
- **Writes are gated.** `write_file`, `edit_file`, `mkdir`, `move`, `delete`,
  and the git write tools (`git_add`, `git_commit`, `git_switch`,
  `git_restore`, `git_stash`) are only registered when the operator sets
  `writes_enabled: true`. They are absent from the tool list otherwise, not
  merely refused at call time.
- **Scripts are gated and operator-defined.** `run_script` is only registered
  when the operator's `scripts` map is non-empty. The client picks a script by
  name; it cannot alter or extend the argv the operator configured for it.
- **Output is capped.** Tool output is truncated to `max_output_size`.

What secure mode does **not** guarantee:

- It is not an OS sandbox. It does not confine filesystem, network or resource
  usage of a command once it runs. Real containment comes from the deployment:
  run the provided Docker image (non-root), ideally with a read-only rootfs,
  dropped capabilities and no network, or an equivalent OS-level sandbox.
- `run_script` executes the operator's own configured argv as-is. mcp-shell
  does not vet that argv; whatever the operator put there is what runs.
- `MCP_SHELL_ALLOW_UNSAFE=1` disables secure mode entirely by explicit opt-in
  and replaces the typed tools with a single `shell_exec` tool that runs
  `bash -c` on the client's command string with no validation at all.
- **git can still mutate refs within its own repository.** The git tools do
  not execute programs, write outside the repo, or reach the network, but with
  `writes_enabled: true`, `git_switch` (with `create`) and `git_stash` can
  still create branches or drop stashes in the repository git runs in. That is
  bounded to the repo (no arbitrary-path write, no execution) and is a known,
  lower-severity gap. If even repo-local mutation is unacceptable, run git
  under a read-only OS sandbox or leave `writes_enabled: false`.

## Scope for vulnerability reports

In scope is the default mode only: typed tools, path confinement, git
hardening, and config loading. Please report:

- A path parameter that escapes `working_directory` (a symlink or traversal
  that is not rejected).
- A git tool that reaches the network, executes an external program (hook,
  pager, diff/textconv driver), or accepts a ref/path that is not confined to
  the repository despite the `--`/`--end-of-options` and leading-`-`
  rejection described above.
- A way to reach `write_file`, `edit_file`, `mkdir`, `move`, `delete`, a git
  write tool, or `run_script` without the operator having set
  `writes_enabled: true` or a non-empty `scripts` map, respectively.
- A config file that is accepted despite setting a key that was removed in
  1.0.0 (see the migration notes in README.md).

Reports about `shell_exec` under `MCP_SHELL_ALLOW_UNSAFE=1` are out of scope
and will be closed: that mode is arbitrary command execution by design.

Out of scope (known limitations, not vulnerabilities):

- Anything requiring `MCP_SHELL_ALLOW_UNSAFE=1`.
- Resource exhaustion, information disclosure, or filesystem reads by
  `read_file`/`grep`/`glob`/`list_dir` within the working directory contract
  (reading a readable file is what those tools are for). Confinement to
  `working_directory` is the guarantee; containment of what's inside it is the
  sandbox's job.
- `run_script` running whatever argv the operator configured for it. The
  operator chose that argv; mcp-shell does not vet it.
- The repo-local ref mutation described above (`git_switch --create`,
  `git_stash`) when `writes_enabled: true`.

## Reporting

Use GitHub private vulnerability reporting on this repository. Include a
runnable proof of concept against the default configuration or a minimal
config diff. Reports matching the in-scope list are triaged and credited;
out-of-scope reports are closed with a pointer to this document.
