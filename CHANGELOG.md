# Changelog

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
