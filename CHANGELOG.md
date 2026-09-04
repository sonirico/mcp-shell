# Changelog

## [1.0.0](https://github.com/sonirico/mcp-shell/compare/v0.8.1...v1.0.0) (2026-09-04)


### ⚠ BREAKING CHANGES

* replace secure-mode shell_exec with typed tools

### Features

* **paths:** add workspace path confinement ([b398e0d](https://github.com/sonirico/mcp-shell/commit/b398e0d6833e695c360ffba54e4becd91158424f))
* replace secure-mode shell_exec with typed tools ([cda5814](https://github.com/sonirico/mcp-shell/commit/cda5814e83ccecb222ce9b1292a2dd556e7507e9))
* **tools:** add file and git write tools behind writes_enabled ([a5cd368](https://github.com/sonirico/mcp-shell/commit/a5cd3687245ea61e92a45c54c76c28d02b0869b5))
* **tools:** add run_script with operator-defined argv ([ecbbfc0](https://github.com/sonirico/mcp-shell/commit/ecbbfc079c554a02b9c4ae906de8b927a5b233e0))
* **tools:** add typed read-only filesystem tools ([0426796](https://github.com/sonirico/mcp-shell/commit/0426796284a0daa0774bb51f81ba6e040f3f92d4))
* **tools:** add typed read-only git tools ([3ab4aea](https://github.com/sonirico/mcp-shell/commit/3ab4aead7a57a2a9169b177f8ee768e02098483b))

## [0.8.1](https://github.com/sonirico/mcp-shell/compare/v0.8.0...v0.8.1) (2026-09-04)


### Bug Fixes

* **security:** deny abbreviated forms of denied git long options ([743791c](https://github.com/sonirico/mcp-shell/commit/743791c27351df9cc126271ded1916fb85021979))
* **security:** deny abbreviated forms of denied git long options ([d205560](https://github.com/sonirico/mcp-shell/commit/d2055602d78548c7634e3dddf22ee81e41e29193))

## [0.8.0](https://github.com/sonirico/mcp-shell/compare/v0.7.2...v0.8.0) (2026-08-27)


### Features

* **security:** close the allowlisted-binary-runs-anything class (GHSA-gg85-6grh-63fp) with deny-by-default executable classification, minimal child environment, git repo-config neutralisation, write-time output cap, and rejection of relative argv[0] and NUL bytes ([#28](https://github.com/sonirico/mcp-shell/pull/28))

## [0.7.2](https://github.com/sonirico/mcp-shell/compare/v0.7.1...v0.7.2) (2026-08-27)


### Bug Fixes

* **security:** fail closed on privilege-drop and working-dir setup errors ([7fe9e88](https://github.com/sonirico/mcp-shell/commit/7fe9e88eaab59675895cf124d2994a81d770776a))

## [0.7.1](https://github.com/sonirico/mcp-shell/compare/v0.7.0...v0.7.1) (2026-08-16)


### Bug Fixes

* **security:** deny-by-default argument allowlist for governed binaries ([ac4af99](https://github.com/sonirico/mcp-shell/commit/ac4af997ae1d1eb2adf0d0878b10a9fecf01ea1d))
* **security:** deny-by-default argument allowlist for governed binaries ([120aec2](https://github.com/sonirico/mcp-shell/commit/120aec2eed1fe750d9821e3943039597b855da1c))

## [0.7.0](https://github.com/sonirico/mcp-shell/compare/v0.6.0...v0.7.0) (2026-06-14)


### Features

* AST-based command unfurling for secure mode ([6ef72cd](https://github.com/sonirico/mcp-shell/commit/6ef72cdeb757a77778da3678bbe5d704752d0d5b))
* AST-based command unfurling for secure mode ([9654784](https://github.com/sonirico/mcp-shell/commit/9654784876fe42669c02fd6d1e5f5d3dbb3a4da6))
