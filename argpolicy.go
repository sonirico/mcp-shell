package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

// argPolicy decides whether a resolved argv for one executable is permitted.
// argv[0] is the executable. Implementations are pure and stateless and exist
// to strip per-tool escape hatches (GTFOBins) that structural validation alone
// cannot see: an allowlisted binary may itself run arbitrary commands.
type argPolicy interface {
	name() string
	check(argv []string) error
}

// policySet maps an executable basename to its governing argPolicy. Absence of
// an entry means no extra per-argument restriction beyond structural + allowlist.
type policySet struct {
	byName map[string]argPolicy
}

func newPolicySet(policies ...argPolicy) *policySet {
	byName := make(map[string]argPolicy, len(policies))
	for _, p := range policies {
		byName[p.name()] = p
	}
	return &policySet{byName: byName}
}

func newDefaultPolicySet() *policySet {
	return newPolicySet(newGitArgPolicy(), newFindArgPolicy(), newTarArgPolicy())
}

// governs reports whether a policy exists for the executable's basename.
func (s *policySet) governs(executable string) bool {
	_, ok := s.byName[filepath.Base(executable)]
	return ok
}

func (s *policySet) check(argv []string) error {
	if len(argv) == 0 {
		return nil
	}
	if pol, ok := s.byName[filepath.Base(argv[0])]; ok {
		return pol.check(argv)
	}
	return nil
}

// gitArgPolicy blocks git's config-injection and alias-as-shell escape hatches.
type gitArgPolicy struct{}

func newGitArgPolicy() *gitArgPolicy { return &gitArgPolicy{} }

func (*gitArgPolicy) name() string { return "git" }

func (*gitArgPolicy) check(argv []string) error {
	for _, a := range argv[1:] {
		if a == "-c" || a == "--config-env" {
			return fmt.Errorf("git: -c/--config-env config injection is not allowed in secure mode")
		}
		if strings.HasPrefix(a, "--exec-path") ||
			strings.HasPrefix(a, "--upload-pack") ||
			strings.HasPrefix(a, "--receive-pack") {
			return fmt.Errorf("git: %q can execute arbitrary programs and is not allowed in secure mode", a)
		}
	}
	return nil
}

// findArgPolicy blocks find's action primaries that spawn processes or mutate.
type findArgPolicy struct{}

func newFindArgPolicy() *findArgPolicy { return &findArgPolicy{} }

func (*findArgPolicy) name() string { return "find" }

func (*findArgPolicy) check(argv []string) error {
	blocked := map[string]struct{}{
		"-exec": {}, "-execdir": {}, "-ok": {}, "-okdir": {},
		"-fprintf": {}, "-fprint": {}, "-fprint0": {}, "-delete": {},
	}
	for _, a := range argv[1:] {
		if _, bad := blocked[a]; bad {
			return fmt.Errorf("find: %q is not allowed in secure mode", a)
		}
	}
	return nil
}

// tarArgPolicy blocks tar options that run an external command.
type tarArgPolicy struct{}

func newTarArgPolicy() *tarArgPolicy { return &tarArgPolicy{} }

func (*tarArgPolicy) name() string { return "tar" }

func (*tarArgPolicy) check(argv []string) error {
	for _, a := range argv[1:] {
		if a == "-I" ||
			strings.HasPrefix(a, "--to-command") ||
			strings.HasPrefix(a, "--checkpoint-action") ||
			strings.HasPrefix(a, "--use-compress-program") ||
			strings.HasPrefix(a, "--rsh-command") {
			return fmt.Errorf("tar: %q can execute arbitrary programs and is not allowed in secure mode", a)
		}
	}
	return nil
}
