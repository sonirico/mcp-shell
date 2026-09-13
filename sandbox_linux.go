//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	"github.com/landlock-lsm/go-landlock/landlock"
)

// sandboxArg is the internal subcommand that turns the server binary into a
// one-shot Landlock shim. main dispatches to runSandboxShim when it sees this
// as the first argument.
const sandboxArg = "__sandbox__"

// sandboxWrapArgv rewrites a child argv so it runs under the Landlock shim. The
// server re-execs itself as "<self> __sandbox__ <workspace> -- <argv...>"; the
// shim applies the ruleset and then execs the real target in the same process,
// so the target inherits a kernel-enforced domain it cannot escape. On any
// failure to locate the binary it returns argv unchanged, degrading to no
// sandbox rather than refusing to run.
func sandboxWrapArgv(workspace string, argv []string) []string {
	self, err := os.Executable()
	if err != nil {
		return argv
	}
	wrapped := make([]string, 0, len(argv)+4)
	wrapped = append(wrapped, self, sandboxArg, workspace, "--")
	wrapped = append(wrapped, argv...)
	return wrapped
}

// runSandboxShim applies the Landlock ruleset to the current process and execs
// the wrapped target. It never returns on success: syscall.Exec replaces the
// process image, and the Landlock domain established here is inherited across
// the exec and cannot be relaxed afterwards. The ruleset denies writes anywhere
// but the workspace and denies all TCP connect/bind, so a program the child
// manages to launch can do no more than the filesystem tools already allow and
// cannot reach the network. Reads stay broad because git legitimately reads
// system files; read confinement is left to run_as_user and containerisation.
func runSandboxShim() error {
	workspace, target, err := parseSandboxArgs(os.Args)
	if err != nil {
		return err
	}

	// The Landlock domain is inherited by whatever this thread execs, so keep
	// the goroutine pinned to the thread that was restricted.
	runtime.LockOSThread()

	rules := []landlock.Rule{
		landlock.RODirs("/"),
		landlock.RWDirs(workspace),
		landlock.RWFiles("/dev/null"),
	}
	if err := landlock.V5.BestEffort().Restrict(rules...); err != nil {
		return fmt.Errorf("apply landlock: %w", err)
	}

	bin, err := exec.LookPath(target[0])
	if err != nil {
		bin = target[0]
	}
	return syscall.Exec(bin, target, os.Environ())
}

// parseSandboxArgs pulls the workspace and target argv out of the shim's own
// os.Args, laid out as [self, __sandbox__, workspace, --, target...].
func parseSandboxArgs(args []string) (string, []string, error) {
	if len(args) < 5 || args[1] != sandboxArg || args[3] != "--" {
		return "", nil, fmt.Errorf("sandbox: malformed shim arguments")
	}
	workspace := args[2]
	target := args[4:]
	if len(target) == 0 {
		return "", nil, fmt.Errorf("sandbox: empty target command")
	}
	return workspace, target, nil
}
