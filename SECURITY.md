# Security Policy

## Threat model

`mcp-shell` executes commands on behalf of an untrusted MCP client (typically
an LLM that may be prompt-injected). Secure mode is an **early-reject layer**:
it refuses commands it cannot affirmatively classify as safe. It is **not a
sandbox** and does not claim to contain a process once it runs.

What secure mode guarantees (with `use_shell_execution: false`):

- Only a single, fully-literal simple command is accepted. Pipes, lists,
  substitution, redirection, globs and any other shell structure are rejected
  at the AST level.
- The executable must be on the operator's allowlist **and** be classified as
  safe. Classified means one of:
  - a **data-only utility**: transforms or reports data, cannot execute other
    programs, cannot write to a caller-chosen path (`ls`, `cat`, `grep`, ...);
  - a **policy-governed binary**: `git`, `find`, `sort`, `uniq`, whose
    arguments are checked deny-by-default so only explicitly safe flags pass.
- Everything else is rejected, even when allowlisted. There is no denylist of
  "dangerous binaries" to bypass: interpreters (`bash`, `python`, ...),
  command wrappers (`env`, `timeout`, `nice`, `xargs`, `busybox`, ...) and any
  binary the classifier does not know are all denied by construction.
- The executable is run with a **minimal environment**, not the server's. The
  process environment and any `.env` loaded at startup are not inherited, so an
  allowlisted reader (`cat /proc/self/environ`, `env`) cannot read secrets held
  by the server or exported by the MCP client.
- A relative `argv[0]` containing a path separator (`./ls`, `sub/ls`) is
  rejected: only a bare name resolved via `PATH` or an absolute path is
  accepted, so validation and execution cannot resolve different files.

What secure mode does **not** guarantee:

- It is not an OS sandbox. It does not confine filesystem, network or resource
  usage of a command once accepted. Real containment comes from the deployment:
  run the provided Docker image (non-root), ideally with a read-only rootfs,
  dropped capabilities and no network, or an equivalent OS-level sandbox.
- Legacy mode (`use_shell_execution: true`) is best-effort string filtering,
  documented as vulnerable to injection. It exists for backwards compatibility
  and carries no bypass-resistance claim.
- `MCP_SHELL_ALLOW_UNSAFE=true` disables all checks by explicit opt-in.
- **git can still mutate refs within its own repository.** The allowed git
  subcommands do not execute programs, write outside the repo or reach the
  network - `core.fsmonitor`, `diff.external` and per-path `textconv` drivers
  are all suppressed, and system/global config is neutralised. But `branch`,
  `tag`, `symbolic-ref` and `reflog` can still delete or move refs in the
  repository git runs in. That is bounded to the repo (no arbitrary-path write,
  no execution) and is a known, lower-severity gap. If even repo-local mutation
  is unacceptable, run git under a read-only OS sandbox.

## Scope for vulnerability reports

In scope (please report):

- A command that executes a program, writes to a caller-chosen path, or
  reaches the network despite passing secure-mode validation with the
  **default configuration**.
- A data-only classified utility that can in fact execute programs or write to
  caller-chosen paths (a misclassification).
- An argument-policy escape: a governed binary (`git`, `find`, `sort`, `uniq`)
  accepting a flag or form that executes programs or writes to caller-chosen
  paths.
- Bypasses of the AST structural check (smuggling shell structure through the
  unfurler).

Out of scope (known limitations, not vulnerabilities):

- Anything requiring `use_shell_execution: true`, `enabled: false` or
  `MCP_SHELL_ALLOW_UNSAFE=true`.
- Resource exhaustion, information disclosure or filesystem reads by
  data-only utilities within the working directory contract (`cat` reading a
  readable file is what `cat` is for). Confinement is the sandbox's job.
- Reports that amount to "the operator can write an unsafe config" without a
  bypass of the classification described above.

## Reporting

Use GitHub private vulnerability reporting on this repository. Include a
runnable proof of concept against the default configuration or a minimal
config diff. Reports matching the in-scope list are triaged and credited;
out-of-scope reports are closed with a pointer to this document.
