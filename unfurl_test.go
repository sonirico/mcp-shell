package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommandUnfurler_unfurl(t *testing.T) {
	tests := []struct {
		name        string
		command     string
		wantAllowed bool
		wantArgv    []string
	}{
		{
			name:        "simple command",
			command:     "ls -la",
			wantAllowed: true,
			wantArgv:    []string{"ls", "-la"},
		},
		{
			name:        "multiple args",
			command:     "grep -n test file.txt",
			wantAllowed: true,
			wantArgv:    []string{"grep", "-n", "test", "file.txt"},
		},
		{
			name:        "surrounding whitespace trimmed",
			command:     "  echo hello world  ",
			wantAllowed: true,
			wantArgv:    []string{"echo", "hello", "world"},
		},
		{
			name:        "single command no args",
			command:     "pwd",
			wantAllowed: true,
			wantArgv:    []string{"pwd"},
		},
		{
			name:        "quoted metacharacter is an inert literal",
			command:     "echo ';'",
			wantAllowed: true,
			wantArgv:    []string{"echo", ";"},
		},
		{
			name:        "double-quoted argument keeps its space",
			command:     `echo "a b"`,
			wantAllowed: true,
			wantArgv:    []string{"echo", "a b"},
		},
		{
			name:        "glob inside double quotes is literal",
			command:     `echo "a*b"`,
			wantAllowed: true,
			wantArgv:    []string{"echo", "a*b"},
		},
		{
			name:        "empty command",
			command:     "",
			wantAllowed: false,
		},
		{
			name:        "whitespace only",
			command:     "   ",
			wantAllowed: false,
		},
		{
			name:        "pipeline",
			command:     "ls | grep test",
			wantAllowed: false,
		},
		{
			name:        "command list with semicolon",
			command:     "echo hello; rm file",
			wantAllowed: false,
		},
		{
			name:        "logical and",
			command:     "echo a && rm b",
			wantAllowed: false,
		},
		{
			name:        "command substitution",
			command:     "echo $(whoami)",
			wantAllowed: false,
		},
		{
			name:        "backtick substitution",
			command:     "echo `whoami`",
			wantAllowed: false,
		},
		{
			name:        "parameter expansion braces",
			command:     "echo ${HOME}",
			wantAllowed: false,
		},
		{
			name:        "parameter expansion bare",
			command:     "echo $HOME",
			wantAllowed: false,
		},
		{
			name:        "redirection",
			command:     "echo hello > file.txt",
			wantAllowed: false,
		},
		{
			name:        "background",
			command:     "sleep 10 &",
			wantAllowed: false,
		},
		{
			name:        "unquoted glob",
			command:     "cat *",
			wantAllowed: false,
		},
		{
			name:        "brace expansion",
			command:     "echo a{b,c}",
			wantAllowed: false,
		},
		{
			name:        "subshell",
			command:     "(ls)",
			wantAllowed: false,
		},
		{
			name:        "inline assignment",
			command:     "FOO=bar ls",
			wantAllowed: false,
		},
		{
			name:        "negation",
			command:     "! ls",
			wantAllowed: false,
		},
		{
			name:        "control flow",
			command:     "if true; then ls; fi",
			wantAllowed: false,
		},
		{
			name:        "ansi-c quoting is rejected",
			command:     `echo $'\143hmod'`,
			wantAllowed: false,
		},
		{
			// The parser silently drops NUL, so a smuggled NUL would make the
			// executed argv differ from the audited string. Reject up front.
			name:        "nul byte is rejected",
			command:     "cat /etc/pass\x00wd",
			wantAllowed: false,
		},
	}

	unfurler := newCommandUnfurler()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			res := unfurler.unfurl(tt.command)

			if tt.wantAllowed {
				require.True(t, res.Allowed, "expected allowed, got reason: %s", res.Reason)
				assert.Equal(t, tt.wantArgv, res.Argv)
			} else {
				require.False(t, res.Allowed)
				assert.NotEmpty(t, res.Reason)
			}
		})
	}
}
