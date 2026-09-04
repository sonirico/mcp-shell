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
	return newPolicySet(
		newGitArgPolicy(), newFindArgPolicy(), newSortArgPolicy(),
		newUniqArgPolicy(),
	)
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

// stringSet is a membership set of exact tokens (long flags, whole-word primaries).
type stringSet map[string]struct{}

func newStringSet(items ...string) stringSet {
	s := make(stringSet, len(items))
	for _, it := range items {
		s[it] = struct{}{}
	}
	return s
}

func (s stringSet) has(k string) bool {
	_, ok := s[k]
	return ok
}

// byteSet is a membership set of single-letter short flags for cluster parsing.
type byteSet map[byte]struct{}

func newByteSet(letters string) byteSet {
	s := make(byteSet, len(letters))
	for i := 0; i < len(letters); i++ {
		s[letters[i]] = struct{}{}
	}
	return s
}

func (s byteSet) has(b byte) bool {
	_, ok := s[b]
	return ok
}

// isFlagToken reports whether argv token is a flag. "-" and "--" are bare
// tokens (stdin marker, end-of-options convention) and are not flags.
func isFlagToken(tok string) bool {
	return len(tok) > 0 && tok[0] == '-' && tok != "-" && tok != "--"
}

// longFlagName strips a "--name=value" token down to "--name".
func longFlagName(tok string) string {
	name, _, _ := strings.Cut(tok, "=")
	return name
}

// checkShortCluster walks a bundled short-flag token (e.g. "-nrk2") letter by
// letter. Every letter must be in allowed or the cluster is rejected via
// onReject. Hitting a letter in argTaking stops the scan: the remainder of
// the cluster is that flag's value, not further flags.
func checkShortCluster(tok string, allowed, argTaking byteSet, onReject func(c byte, tok string) error) error {
	letters := tok[1:]
	for i := 0; i < len(letters); i++ {
		c := letters[i]
		if !allowed.has(c) {
			return onReject(c, tok)
		}
		if argTaking.has(c) {
			return nil
		}
	}
	return nil
}

// gitArgPolicy is deny-by-default on both global flags and subcommands. Global
// flags before the subcommand must be allowlisted (that is where -c/--config-env
// and --exec-path live), and the subcommand itself must be one of a read-only
// set: git config writes are an RCE primitive (alias.*, diff.external, pagers),
// and mutating/network subcommands are outside this sandbox's contract. grep is
// deliberately excluded: git grep -O runs the pager string as a shell command
// and its short-flag form (-iO<cmd>) cannot be denied without false-positives on
// legitimate pattern values. The remaining always-dangerous flags are all long
// forms (git never bundles those), so gitDeniedFlag needs no cluster walk.
type gitArgPolicy struct{}

func newGitArgPolicy() *gitArgPolicy { return &gitArgPolicy{} }

func (*gitArgPolicy) name() string { return "git" }

var gitAllowedGlobal = newStringSet(
	"--no-pager", "--paginate", "--bare",
	"--literal-pathspecs", "--no-optional-locks",
)

// gitAllowedSubcommands neither execute programs, write outside the repository,
// nor reach the network. --git-dir/--work-tree are deliberately not allowed
// globals, so none can be retargeted at an arbitrary path. They are not all
// strictly read-only: branch, tag, symbolic-ref and reflog can still mutate refs
// within the repository. That is bounded to the repo (no arbitrary-path write,
// no execution) and is a lower-severity gap left open on purpose; the diff and
// textconv drivers, which do execute programs, are suppressed in the executor.
var gitAllowedSubcommands = newStringSet(
	"status", "log", "show", "diff", "branch", "tag", "describe",
	"rev-parse", "rev-list", "ls-files", "ls-tree", "cat-file", "blame",
	"shortlog", "reflog", "whatchanged", "symbolic-ref", "name-rev",
	"merge-base", "for-each-ref", "count-objects", "var", "show-ref",
	"show-branch",
)

// gitDeniedFlags are dangerous under any allowed subcommand: --output
// (diff/log/show write to an arbitrary file), --ext-diff (runs diff.external),
// --open-files-in-pager (runs the pager as a command), --contents (blame reads
// an arbitrary file into the output), and --textconv (cat-file/blame/log run a
// repo-configured textconv program). All are long forms, so git never bundles
// them; but parse-options accepts any unambiguous prefix of a long option
// (--cont is --contents), so gitDeniedFlag matches by prefix and fails closed
// on every prefix, ambiguous or not.
var gitDeniedFlags = []string{
	"--output", "--open-files-in-pager", "--ext-diff", "--contents", "--textconv",
}

func gitDeniedFlag(tok string) bool {
	name := longFlagName(tok)
	if !strings.HasPrefix(name, "--") || len(name) == 2 {
		return false
	}
	for _, denied := range gitDeniedFlags {
		if strings.HasPrefix(denied, name) {
			return true
		}
	}
	return false
}

func (*gitArgPolicy) check(argv []string) error {
	seenSubcommand := false
	for _, a := range argv[1:] {
		if !seenSubcommand {
			if !isFlagToken(a) {
				if !gitAllowedSubcommands.has(a) {
					return fmt.Errorf("git: subcommand %q is not allowed in secure mode", a)
				}
				seenSubcommand = true
				continue
			}
			if a == "-c" || strings.HasPrefix(a, "--config-env") {
				return fmt.Errorf("git: %q is a config injection vector and is not allowed in secure mode", a)
			}
			if strings.HasPrefix(a, "--exec-path") {
				return fmt.Errorf("git: %q can execute arbitrary programs via exec-path and is not allowed in secure mode", a)
			}
			if strings.HasPrefix(a, "--") && gitAllowedGlobal.has(longFlagName(a)) {
				continue
			}
			return fmt.Errorf("git: %q is not allowed in secure mode", a)
		}
		if isFlagToken(a) && gitDeniedFlag(a) {
			return fmt.Errorf("git: %q is not allowed in secure mode (matches a denied option or an abbreviation of one)", a)
		}
	}
	return nil
}

// findArgPolicy allowlists find's query/reporting primaries. Every action
// primary that spawns a process or mutates the filesystem is unlisted, so
// unknown or future primaries fail closed instead of slipping through.
type findArgPolicy struct{}

func newFindArgPolicy() *findArgPolicy { return &findArgPolicy{} }

func (*findArgPolicy) name() string { return "find" }

var findAllowed = newStringSet(
	"-name", "-iname", "-path", "-ipath", "-regex", "-iregex", "-type", "-maxdepth", "-mindepth", "-depth", "-d",
	"-print", "-print0", "-printf", "-ls", "-size", "-empty", "-perm", "-user", "-uid", "-group", "-gid", "-nouser", "-nogroup",
	"-mtime", "-atime", "-ctime", "-mmin", "-amin", "-cmin", "-newer", "-newermt", "-anewer", "-cnewer", "-used",
	"-not", "-a", "-and", "-o", "-or", "-true", "-false",
	"-prune", "-quit", "-follow", "-xdev", "-mount", "-samefile", "-inum", "-links", "-readable", "-writable", "-executable",
	"-lname", "-ilname", "-fstype", "-context", "-L", "-H", "-P",
)

func (*findArgPolicy) check(argv []string) error {
	for _, a := range argv[1:] {
		if !isFlagToken(a) {
			continue
		}
		if !findAllowed.has(a) {
			return fmt.Errorf("find: %q is not allowed in secure mode", a)
		}
	}
	return nil
}

// sortArgPolicy allowlists sort's ordering/formatting flags. -o/--output
// (arbitrary file write) and --compress-program (arbitrary execution) are the
// canonical escape hatches; everything else unlisted fails closed too.
type sortArgPolicy struct{}

func newSortArgPolicy() *sortArgPolicy { return &sortArgPolicy{} }

func (*sortArgPolicy) name() string { return "sort" }

var (
	// -T/--temporary-directory is arg-taking (so its value is consumed) but not
	// allowed: it plants a caller-controlled temp file in an attacker-chosen dir.
	sortAllowedShort = newByteSet("bdfgiMhnRrsuzcCktSV")
	sortArgTaking    = newByteSet("ktoST")
	sortAllowedLong  = newStringSet(
		"--ignore-leading-blanks", "--dictionary-order", "--ignore-case",
		"--general-numeric-sort", "--ignore-nonprinting", "--month-sort",
		"--human-numeric-sort", "--numeric-sort", "--random-sort", "--reverse",
		"--sort", "--stable", "--unique", "--zero-terminated", "--check",
		"--key", "--field-separator", "--buffer-size", "--version-sort",
		"--parallel", "--debug", "--help", "--version", "--random-source",
	)
)

func sortRejectLetter(c byte, tok string) error {
	if c == 'o' {
		return fmt.Errorf("sort: %q writes to an arbitrary file and is not allowed in secure mode", tok)
	}
	return fmt.Errorf("sort: %q is not allowed in secure mode", tok)
}

func (*sortArgPolicy) check(argv []string) error {
	for _, a := range argv[1:] {
		if !isFlagToken(a) {
			continue
		}
		if strings.HasPrefix(a, "--") {
			name := longFlagName(a)
			if sortAllowedLong.has(name) {
				continue
			}
			switch name {
			case "--output":
				return fmt.Errorf("sort: %q writes to an arbitrary file and is not allowed in secure mode", a)
			case "--compress-program":
				return fmt.Errorf("sort: %q can execute arbitrary programs and is not allowed in secure mode", a)
			default:
				return fmt.Errorf("sort: %q is not allowed in secure mode", a)
			}
		}
		if err := checkShortCluster(a, sortAllowedShort, sortArgTaking, sortRejectLetter); err != nil {
			return err
		}
	}
	return nil
}

// uniqArgPolicy allowlists uniq's comparison/formatting flags and denies a
// second positional operand: `uniq input output` writes to an arbitrary file,
// the same escape-hatch class as find -fls and sort -o. Separate-value flags
// (-f 2, --skip-fields 2) consume their value so it is not miscounted as an
// operand.
type uniqArgPolicy struct{}

func newUniqArgPolicy() *uniqArgPolicy { return &uniqArgPolicy{} }

func (*uniqArgPolicy) name() string { return "uniq" }

var (
	uniqAllowedShort = newByteSet("cdDiuzfsw")
	uniqArgTaking    = newByteSet("fsw")
	uniqAllowedLong  = newStringSet(
		"--count", "--repeated", "--all-repeated", "--ignore-case", "--unique",
		"--zero-terminated", "--group", "--skip-fields", "--skip-chars",
		"--check-chars", "--help", "--version",
	)
	// Long flags whose value may arrive as the next token instead of =value.
	uniqLongValueSeparate = newStringSet("--skip-fields", "--skip-chars", "--check-chars")
)

func uniqRejectLetter(_ byte, tok string) error {
	return fmt.Errorf("uniq: %q is not allowed in secure mode", tok)
}

func (*uniqArgPolicy) check(argv []string) error {
	operands := 0
	expectValue := false
	optionsEnded := false
	for _, a := range argv[1:] {
		if expectValue {
			expectValue = false
			continue
		}
		if !optionsEnded && a == "--" {
			optionsEnded = true
			continue
		}
		if !optionsEnded && isFlagToken(a) {
			if strings.HasPrefix(a, "--") {
				name := longFlagName(a)
				if !uniqAllowedLong.has(name) {
					return fmt.Errorf("uniq: %q is not allowed in secure mode", a)
				}
				// Bare form ("--skip-fields 2"): the next token is the value.
				expectValue = uniqLongValueSeparate.has(name) && name == a
				continue
			}
			if err := checkShortCluster(a, uniqAllowedShort, uniqArgTaking, uniqRejectLetter); err != nil {
				return err
			}
			// A cluster ending exactly on a value-taking letter ("-f") takes its
			// value from the next token; a glued value ("-f2") does not.
			expectValue = uniqArgTaking.has(a[len(a)-1])
			continue
		}
		operands++
		if operands > 1 {
			return fmt.Errorf("uniq: %q names an output file, which writes to an arbitrary path and is not allowed in secure mode", a)
		}
	}
	return nil
}
