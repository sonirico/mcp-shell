package main

import (
	"fmt"
	"strings"
	"sync"

	"mvdan.cc/sh/v3/syntax"
)

// unfurlResult is the outcome of structurally analysing one command string.
// Argv is valid only when Allowed is true; otherwise Reason explains the reject.
type unfurlResult struct {
	Argv    []string
	Allowed bool
	Reason  string
}

// commandUnfurler parses a command string into a shell AST and decides whether
// it is a single, fully-literal simple command, extracting its resolved argv.
// syntax.Parser is reusable but not safe for concurrent use, so parsers are
// pooled: each call borrows one and returns it, keeping allocations low without
// sharing state across goroutines.
type commandUnfurler struct {
	parsers sync.Pool
}

func newCommandUnfurler() *commandUnfurler {
	return &commandUnfurler{
		parsers: sync.Pool{
			New: func() any {
				return syntax.NewParser(syntax.Variant(syntax.LangBash))
			},
		},
	}
}

// unfurl reports unsafe input via unfurlResult.Allowed/Reason rather than an
// error. The structural whitelist is default-deny: only a single simple command
// whose every argument is a constant literal is allowed. The bash variant is
// used so the widest set of dynamic constructs is recognised and rejected.
//
// The resolved argv holds independent string copies (built via strings.Builder),
// so the borrowed parser is safe to return to the pool on return.
func (u *commandUnfurler) unfurl(command string) unfurlResult {
	if strings.TrimSpace(command) == "" {
		return unfurlResult{Reason: "empty command"}
	}

	parser := u.parsers.Get().(*syntax.Parser)
	defer u.parsers.Put(parser)

	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return unfurlResult{Reason: fmt.Sprintf("unparseable command: %v", err)}
	}
	if len(file.Stmts) != 1 {
		return unfurlResult{Reason: "command must be exactly one statement"}
	}

	stmt := file.Stmts[0]
	if stmt.Background || stmt.Coprocess || stmt.Negated || len(stmt.Redirs) > 0 {
		return unfurlResult{Reason: "background, coprocess, negation and redirection are not allowed"}
	}

	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok {
		return unfurlResult{Reason: "only a single simple command is allowed (no pipelines, lists, subshells or control flow)"}
	}
	if len(call.Assigns) > 0 {
		return unfurlResult{Reason: "inline environment assignments are not allowed"}
	}

	argv := make([]string, 0, len(call.Args))
	for _, word := range call.Args {
		// Surface brace expansion ({a,b}) as a dynamic BraceExp part so it is
		// rejected like any other expansion.
		syntax.SplitBraces(word)
		lit, ok := literalWord(word)
		if !ok {
			return unfurlResult{Reason: "arguments must be constant literals (no expansion, command substitution or glob)"}
		}
		argv = append(argv, lit)
	}
	if len(argv) == 0 {
		return unfurlResult{Reason: "empty command"}
	}

	return unfurlResult{Argv: argv, Allowed: true}
}

// literalWord returns the constant value of a word, or ok=false if any part is
// dynamic (parameter/command/process/arithmetic expansion, brace expansion,
// extended glob, ANSI-C quoting) or an unquoted glob.
func literalWord(word *syntax.Word) (string, bool) {
	return literalParts(word.Parts, false)
}

// literalParts concatenates constant word parts. When quoted is false, an
// unquoted literal containing a glob metacharacter (*, ?, [) is treated as
// dynamic; inside double quotes those characters are inert.
func literalParts(parts []syntax.WordPart, quoted bool) (string, bool) {
	var sb strings.Builder
	for _, part := range parts {
		switch p := part.(type) {
		case *syntax.Lit:
			if !quoted && strings.ContainsAny(p.Value, "*?[") {
				return "", false
			}
			sb.WriteString(p.Value)
		case *syntax.SglQuoted:
			// $'...' (ANSI-C) can encode arbitrary bytes via escapes; reject it
			// rather than guess at decoding the parser leaves untouched.
			if p.Dollar {
				return "", false
			}
			sb.WriteString(p.Value)
		case *syntax.DblQuoted:
			inner, ok := literalParts(p.Parts, true)
			if !ok {
				return "", false
			}
			sb.WriteString(inner)
		default:
			return "", false
		}
	}
	return sb.String(), true
}
