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
			name:        "find name search allowed",
			argv:        []string{"find", ".", "-name", "x", "-type", "f"},
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
