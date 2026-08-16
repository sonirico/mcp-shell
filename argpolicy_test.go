package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicySet_check(t *testing.T) {
	tests := []struct {
		name          string
		argv          []string
		expectError   bool
		errorContains string
	}{
		{
			name:          "git -c config injection blocked",
			argv:          []string{"git", "-c", "alias.pwn=!id"},
			expectError:   true,
			errorContains: "config injection",
		},
		{
			name:          "git -c core.pager blocked",
			argv:          []string{"git", "-c", "core.pager=sh"},
			expectError:   true,
			errorContains: "config injection",
		},
		{
			name:          "git --exec-path blocked",
			argv:          []string{"git", "--exec-path=/tmp"},
			expectError:   true,
			errorContains: "exec-path",
		},
		{
			name:        "git status allowed",
			argv:        []string{"git", "status"},
			expectError: false,
		},
		{
			name:        "git log allowed",
			argv:        []string{"git", "log", "--oneline"},
			expectError: false,
		},
		{
			name:          "find -exec blocked",
			argv:          []string{"find", ".", "-exec", "rm", "{}", "+"},
			expectError:   true,
			errorContains: "-exec",
		},
		{
			name:          "find -delete blocked",
			argv:          []string{"find", ".", "-delete"},
			expectError:   true,
			errorContains: "-delete",
		},
		{
			name:          "find -fls blocked",
			argv:          []string{"find", "/etc/hostname", "-fls", "/tmp/pwned"},
			expectError:   true,
			errorContains: "-fls",
		},
		{
			name:          "git --config-env joined form blocked",
			argv:          []string{"git", "--config-env=core.pager=PAGER", "log"},
			expectError:   true,
			errorContains: "config injection",
		},
		{
			name:        "find name search allowed",
			argv:        []string{"find", ".", "-name", "x", "-type", "f"},
			expectError: false,
		},
		{
			name:          "sort --compress-program blocked",
			argv:          []string{"sort", "--compress-program=/bin/sh", "f"},
			expectError:   true,
			errorContains: "execute arbitrary",
		},
		{
			name:          "sort -o arbitrary write blocked",
			argv:          []string{"sort", "-o", "/etc/passwd", "f"},
			expectError:   true,
			errorContains: "arbitrary file",
		},
		{
			name:          "sort -oFILE glued blocked",
			argv:          []string{"sort", "-o/tmp/pwned", "f"},
			expectError:   true,
			errorContains: "arbitrary file",
		},
		{
			name:          "sort bundled -ro blocked",
			argv:          []string{"sort", "-ro", "/tmp/pwned", "f"},
			expectError:   true,
			errorContains: "arbitrary file",
		},
		{
			name:        "sort plain sort allowed",
			argv:        []string{"sort", "-n", "-r", "-k2", "f"},
			expectError: false,
		},
		{
			name:          "tar checkpoint-action blocked",
			argv:          []string{"tar", "-cf", "/dev/null", "x", "--checkpoint-action=exec=sh"},
			expectError:   true,
			errorContains: "checkpoint-action",
		},
		{
			name:          "tar to-command blocked",
			argv:          []string{"tar", "--to-command=sh", "-xf", "a.tar"},
			expectError:   true,
			errorContains: "to-command",
		},
		{
			name:        "tar list allowed",
			argv:        []string{"tar", "-tf", "a.tar"},
			expectError: false,
		},
		{
			name:        "ungoverned executable passes",
			argv:        []string{"ls", "-la"},
			expectError: false,
		},
		{
			name:        "empty argv passes",
			argv:        []string{},
			expectError: false,
		},
		{
			name:          "git unknown global flag blocked",
			argv:          []string{"git", "--upload-pack=/x", "log"},
			expectError:   true,
			errorContains: "not allowed",
		},
		{
			name:          "git -C path traversal blocked",
			argv:          []string{"git", "-C", "/etc", "status"},
			expectError:   true,
			errorContains: "not allowed",
		},
		{
			name:        "git safe global then subcommand allowed",
			argv:        []string{"git", "--no-pager", "log", "--oneline"},
			expectError: false,
		},
		{
			name:        "git subcommand-scoped -c allowed",
			argv:        []string{"git", "log", "-c"},
			expectError: false,
		},
		{
			name:          "find unknown primary blocked",
			argv:          []string{"find", ".", "-nonexistentprimary"},
			expectError:   true,
			errorContains: "not allowed",
		},
		{
			name:        "find complex query allowed",
			argv:        []string{"find", ".", "-name", "*.go", "-type", "f", "-maxdepth", "3", "-print"},
			expectError: false,
		},
		{
			name:          "sort unknown long flag blocked",
			argv:          []string{"sort", "--frobnicate", "f"},
			expectError:   true,
			errorContains: "not allowed",
		},
		{
			name:        "sort combined shorts allowed",
			argv:        []string{"sort", "-nru", "f"},
			expectError: false,
		},
		{
			name:        "sort -S buffer allowed",
			argv:        []string{"sort", "-S", "1G", "f"},
			expectError: false,
		},
		{
			name:          "tar unknown flag blocked",
			argv:          []string{"tar", "--frobnicate", "-xf", "a.tar"},
			expectError:   true,
			errorContains: "not allowed",
		},
		{
			name:          "tar -I compress program blocked",
			argv:          []string{"tar", "-I", "/bin/sh", "-xf", "a.tar"},
			expectError:   true,
			errorContains: "execute arbitrary",
		},
		{
			name:        "tar bundled -xzf allowed",
			argv:        []string{"tar", "-xzf", "a.tar"},
			expectError: false,
		},
		{
			name:          "git config write subcommand blocked",
			argv:          []string{"git", "config", "--global", "alias.x", "!id"},
			expectError:   true,
			errorContains: "subcommand",
		},
		{
			name:          "git mutating subcommand blocked",
			argv:          []string{"git", "checkout", "HEAD", "--", "f"},
			expectError:   true,
			errorContains: "subcommand",
		},
		{
			name:          "git grep open-files-in-pager blocked",
			argv:          []string{"git", "grep", "-O/bin/sh", "pattern"},
			expectError:   true,
			errorContains: "not allowed",
		},
		{
			name:          "git grep open-files-in-pager long blocked",
			argv:          []string{"git", "grep", "--open-files-in-pager=sh", "pattern"},
			expectError:   true,
			errorContains: "not allowed",
		},
		{
			name:          "git diff --output write blocked",
			argv:          []string{"git", "diff", "--output=/tmp/pwned", "HEAD"},
			expectError:   true,
			errorContains: "not allowed",
		},
		{
			name:          "git grep subcommand blocked",
			argv:          []string{"git", "grep", "-n", "pattern"},
			expectError:   true,
			errorContains: "subcommand",
		},
		{
			name:          "git grep bundled -O RCE blocked",
			argv:          []string{"git", "grep", "-iOtouch /tmp/pwned;true", "hi"},
			expectError:   true,
			errorContains: "subcommand",
		},
		{
			name:          "git blame --contents arbitrary read blocked",
			argv:          []string{"git", "blame", "--contents=/etc/passwd", "HEAD", "--", "f"},
			expectError:   true,
			errorContains: "not allowed",
		},
		{
			name:          "sort -T tempdir planting blocked",
			argv:          []string{"sort", "-T", "/etc/cron.d", "f"},
			expectError:   true,
			errorContains: "not allowed",
		},
		{
			name:          "sort --temporary-directory blocked",
			argv:          []string{"sort", "--temporary-directory=/etc/cron.d", "f"},
			expectError:   true,
			errorContains: "not allowed",
		},
		{
			name:        "sort -t separator allowed",
			argv:        []string{"sort", "-t", ":", "-k2", "f"},
			expectError: false,
		},
		{
			name:          "tar -C extraction escape blocked",
			argv:          []string{"tar", "-x", "-f", "a.tar", "-C", "/etc"},
			expectError:   true,
			errorContains: "sandbox",
		},
		{
			name:          "tar -p setuid restore blocked",
			argv:          []string{"tar", "-xpf", "a.tar"},
			expectError:   true,
			errorContains: "setuid",
		},
		{
			name:          "tar --directory long blocked",
			argv:          []string{"tar", "-xf", "a.tar", "--directory=/etc"},
			expectError:   true,
			errorContains: "sandbox",
		},
		{
			name:          "tar old-style bundled -C escape blocked",
			argv:          []string{"tar", "xfC", "a.tar", "/tmp/dest"},
			expectError:   true,
			errorContains: "sandbox",
		},
		{
			name:          "tar old-style bundled -p setuid blocked",
			argv:          []string{"tar", "xfp", "a.tar"},
			expectError:   true,
			errorContains: "setuid",
		},
		{
			name:          "tar old-style bundled -I exec blocked",
			argv:          []string{"tar", "cIf", "/bin/sh", "out.tar", "x"},
			expectError:   true,
			errorContains: "execute arbitrary",
		},
		{
			name:        "tar old-style xzf allowed",
			argv:        []string{"tar", "xzf", "a.tar.gz"},
			expectError: false,
		},
		{
			name:        "tar old-style tvf allowed",
			argv:        []string{"tar", "tvf", "a.tar"},
			expectError: false,
		},
	}

	policies := newDefaultPolicySet()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := policies.check(tt.argv)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestPolicySet_governs(t *testing.T) {
	policies := newDefaultPolicySet()

	t.Run("governed by basename", func(t *testing.T) {
		assert.True(t, policies.governs("git"))
		assert.True(t, policies.governs("/usr/bin/git"))
		assert.True(t, policies.governs("find"))
		assert.True(t, policies.governs("tar"))
	})

	t.Run("ungoverned", func(t *testing.T) {
		assert.False(t, policies.governs("ls"))
		assert.False(t, policies.governs("/bin/bash"))
	})
}
