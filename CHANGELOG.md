# Changelog

## [0.8.0](https://github.com/shigechika/mcp-stdio/compare/v0.7.0...v0.8.0) (2026-04-20)


### Features

* honour Retry-After on HTTP 429 (typescript-sdk[#1892](https://github.com/shigechika/mcp-stdio/issues/1892)) ([#45](https://github.com/shigechika/mcp-stdio/issues/45)) ([fb5ac14](https://github.com/shigechika/mcp-stdio/commit/fb5ac148ecde6cd0252de956db934241a1941b99))

## [0.7.0](https://github.com/shigechika/mcp-stdio/compare/v0.6.0...v0.7.0) (2026-04-20)


### Features

* cancel-aware response filter (drops late responses for cancelled ids) ([#40](https://github.com/shigechika/mcp-stdio/issues/40)) ([8d4d4aa](https://github.com/shigechika/mcp-stdio/commit/8d4d4aa350a8a58017fd45c78d7df4a1ec4beabe))

## [0.6.0](https://github.com/shigechika/mcp-stdio/compare/v0.5.2...v0.6.0) (2026-04-18)


### Features

* **sse:** inject TCP keepalive socket options on httpx transport ([#34](https://github.com/shigechika/mcp-stdio/issues/34)) ([463b037](https://github.com/shigechika/mcp-stdio/commit/463b0376ba579d533a692cf4ce811d05db488349))

## [0.5.2](https://github.com/shigechika/mcp-stdio/compare/v0.5.1...v0.5.2) (2026-04-18)


### Bug Fixes

* **sse:** add --sse-read-timeout to surface half-open TCP as reconnect ([#32](https://github.com/shigechika/mcp-stdio/issues/32)) ([0ff7bb8](https://github.com/shigechika/mcp-stdio/commit/0ff7bb835778ae2faceeb6c07a91174fadd7a07e))

## [0.5.1](https://github.com/shigechika/mcp-stdio/compare/v0.5.0...v0.5.1) (2026-04-18)


### Bug Fixes

* **oauth:** compare OAuth state in constant time via secrets.compare_digest ([#27](https://github.com/shigechika/mcp-stdio/issues/27)) ([bc90557](https://github.com/shigechika/mcp-stdio/commit/bc9055790c52281eee6fdaf4729a02a0a6f943e9))

## [0.5.0](https://github.com/shigechika/mcp-stdio/compare/v0.4.9...v0.5.0) (2026-04-18)


### Features

* **sse:** wire scope_upgrader into run_sse for 403 step-up symmetry ([#21](https://github.com/shigechika/mcp-stdio/issues/21)) ([dd04550](https://github.com/shigechika/mcp-stdio/commit/dd04550119fe0710a1e81f605ba4d5ebb6d2e2da))


### Bug Fixes

* **check:** stop logging response body on non-200 in --check ([#18](https://github.com/shigechika/mcp-stdio/issues/18)) ([d2514bc](https://github.com/shigechika/mcp-stdio/commit/d2514bcea58d6beaf97f391dec9a5b5301f9670e))
* **cli:** reject CRLF / NUL in -H values and non-token header names ([#20](https://github.com/shigechika/mcp-stdio/issues/20)) ([dcf74ca](https://github.com/shigechika/mcp-stdio/commit/dcf74ca6c93b5c3bfe31fab905f8bc882ab52808))
* **oauth:** reject non-/callback paths on the OAuth callback server ([#19](https://github.com/shigechika/mcp-stdio/issues/19)) ([7a0a968](https://github.com/shigechika/mcp-stdio/commit/7a0a9687f7b4946dbe6062f810a69d67f7586214))
* **oauth:** validate PRM authorization_servers against SSRF / plaintext leaks ([#22](https://github.com/shigechika/mcp-stdio/issues/22)) ([e50f8cf](https://github.com/shigechika/mcp-stdio/commit/e50f8cffa4b03f878f81ceabefc03ed7815e40ca))
* **relay:** emit JSON-RPC error on unhandled 4xx/5xx instead of silent drop ([#12](https://github.com/shigechika/mcp-stdio/issues/12)) ([c142deb](https://github.com/shigechika/mcp-stdio/commit/c142debbfe6571430d5da94e49f1adedb693b4ea))
