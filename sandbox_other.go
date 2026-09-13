//go:build !linux

package main

import "fmt"

// sandboxArg mirrors the Linux constant so main can reference it on every
// platform; the shim itself exists only on Linux.
const sandboxArg = "__sandbox__"

// sandboxWrapArgv is a no-op off Linux: Landlock is a Linux LSM, so there is no
// kernel confinement to apply and the child runs directly.
func sandboxWrapArgv(_ string, argv []string) []string {
	return argv
}

// runSandboxShim never runs off Linux, because sandboxWrapArgv never produces
// the shim argv there. It exists so main compiles on every platform.
func runSandboxShim() error {
	return fmt.Errorf("sandbox: not supported on this platform")
}
