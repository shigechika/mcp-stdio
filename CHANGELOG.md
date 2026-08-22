# Changelog

## [0.43.2](https://github.com/shigechika/mcp-stdio/compare/v0.43.1...v0.43.2) (2026-08-22)


### Bug Fixes

* reap dead-child sessions even when --session-idle-ttl is unset ([#425](https://github.com/shigechika/mcp-stdio/issues/425)) ([3ffda18](https://github.com/shigechika/mcp-stdio/commit/3ffda188d9af957907a05e0ed828012f132057a4))

## [0.43.1](https://github.com/shigechika/mcp-stdio/compare/v0.43.0...v0.43.1) (2026-08-22)


### Bug Fixes

* give PR docs validation its own concurrency group ([#423](https://github.com/shigechika/mcp-stdio/issues/423)) ([264f166](https://github.com/shigechika/mcp-stdio/commit/264f166b807f9ce590f7945a514c51ca9e12fbd3))

## [0.43.0](https://github.com/shigechika/mcp-stdio/compare/v0.42.2...v0.43.0) (2026-08-22)


### Features

* add --max-message-size to bound relay/serve response reads ([#417](https://github.com/shigechika/mcp-stdio/issues/417)) ([49272b0](https://github.com/shigechika/mcp-stdio/commit/49272b01ce2820f6363c2c01809a2fff765d1a9d))
* add bounded gzip/deflate decompression for --max-message-size ([#421](https://github.com/shigechika/mcp-stdio/issues/421)) ([d0a33ad](https://github.com/shigechika/mcp-stdio/commit/d0a33ad6657a2b205d81dedf0069463a051b3d9a))
* extend --max-message-size to cover OAuth HTTP traffic ([#422](https://github.com/shigechika/mcp-stdio/issues/422)) ([d9f2ce0](https://github.com/shigechika/mcp-stdio/commit/d9f2ce0a8195c456e45eb61d32f26ff74aa032e0))

## [0.42.2](https://github.com/shigechika/mcp-stdio/compare/v0.42.1...v0.42.2) (2026-08-13)


### Bug Fixes

* make the poison-cancel tests independent of interpreter stack size ([#412](https://github.com/shigechika/mcp-stdio/issues/412)) ([032c662](https://github.com/shigechika/mcp-stdio/commit/032c6625ea5baa7d68b5b8d16d5a41ee9ef6cd46))

## [0.42.1](https://github.com/shigechika/mcp-stdio/compare/v0.42.0...v0.42.1) (2026-08-11)


### Bug Fixes

* add explicit workflow permissions to test.yml and release.yml ([#407](https://github.com/shigechika/mcp-stdio/issues/407)) ([bcad3b4](https://github.com/shigechika/mcp-stdio/commit/bcad3b464603172f300dee9202b558ea53600d61))

## [0.42.0](https://github.com/shigechika/mcp-stdio/compare/v0.41.0...v0.42.0) (2026-08-09)


### Features

* add --token-store-firestore for OAuth state persistence with no local disk ([#404](https://github.com/shigechika/mcp-stdio/issues/404)) ([bddc291](https://github.com/shigechika/mcp-stdio/commit/bddc291f260384722b379a1033667762bd841338))

## [0.41.0](https://github.com/shigechika/mcp-stdio/compare/v0.40.0...v0.41.0) (2026-08-08)


### Features

* add pr-gate.yml admission control caller ([#402](https://github.com/shigechika/mcp-stdio/issues/402)) ([eb860a2](https://github.com/shigechika/mcp-stdio/commit/eb860a216ae913a6a10520b3f56a88b472fd9dc0))

## [0.40.0](https://github.com/shigechika/mcp-stdio/compare/v0.39.1...v0.40.0) (2026-08-07)


### Features

* add --user-env to inject the authenticated principal into spawned children ([#400](https://github.com/shigechika/mcp-stdio/issues/400)) ([bbff675](https://github.com/shigechika/mcp-stdio/commit/bbff675143c85fdb1fb7114f2feffa5c7934e49a))

## [0.39.1](https://github.com/shigechika/mcp-stdio/compare/v0.39.0...v0.39.1) (2026-08-02)


### Bug Fixes

* eliminate two flaky/false signals — test init timeout leak, ledger cap notice ([#392](https://github.com/shigechika/mcp-stdio/issues/392)) ([4eb9701](https://github.com/shigechika/mcp-stdio/commit/4eb970174a6d434f5dcd4e0622148a9852dbb8bd))

## [0.39.0](https://github.com/shigechika/mcp-stdio/compare/v0.38.0...v0.39.0) (2026-08-02)


### Features

* reverse MRTR envelope, per-child txn table, concurrency invariant ([#375](https://github.com/shigechika/mcp-stdio/issues/375) PR 1) ([#389](https://github.com/shigechika/mcp-stdio/issues/389)) ([cc30eb4](https://github.com/shigechika/mcp-stdio/commit/cc30eb42e4fa263dc00db6e1eee6f32a3cf15703))
* serve-side resourceSubscriptions ([#381](https://github.com/shigechika/mcp-stdio/issues/381)) ([#388](https://github.com/shigechika/mcp-stdio/issues/388)) ([299938c](https://github.com/shigechika/mcp-stdio/commit/299938cc7bc3fe68fb48bd2a2cf3df1359bc5c37))
* the reverse MRTR bridge — translation, minting, retry correlation, D4 valve removal ([#375](https://github.com/shigechika/mcp-stdio/issues/375)) ([#390](https://github.com/shigechika/mcp-stdio/issues/390)) ([297861b](https://github.com/shigechika/mcp-stdio/commit/297861b76ebd9823972e41d9b4f1805702dd6c35))


### Bug Fixes

* keep close_connection true on the legacy GET SSE path ([#383](https://github.com/shigechika/mcp-stdio/issues/383)) ([#384](https://github.com/shigechika/mcp-stdio/issues/384)) ([48a0b0a](https://github.com/shigechika/mcp-stdio/commit/48a0b0a521ae2548f93386194f4d7d457988ae12))

## [0.38.0](https://github.com/shigechika/mcp-stdio/compare/v0.37.0...v0.38.0) (2026-08-01)


### Features

* idle reaper, checkout refcount and --modern-only for the modern pool ([#376](https://github.com/shigechika/mcp-stdio/issues/376)) ([#379](https://github.com/shigechika/mcp-stdio/issues/379)) ([478d985](https://github.com/shigechika/mcp-stdio/commit/478d985773fd06cd52600b7235e568c8cc741bdf))
* serve-side subscriptions/listen — the listChanged trio ([#374](https://github.com/shigechika/mcp-stdio/issues/374)) ([#382](https://github.com/shigechika/mcp-stdio/issues/382)) ([6a5c4ca](https://github.com/shigechika/mcp-stdio/commit/6a5c4ca7373ef203458ea496f2f277fff48b4b77))

## [0.37.0](https://github.com/shigechika/mcp-stdio/compare/v0.36.0...v0.37.0) (2026-08-01)


### Features

* modern dispatch for serve — discover, dual-era, result stamping ([#270](https://github.com/shigechika/mcp-stdio/issues/270) Phase 3 P3-B) ([#373](https://github.com/shigechika/mcp-stdio/issues/373)) ([3686ec3](https://github.com/shigechika/mcp-stdio/commit/3686ec3bca4ebd3fe6ce15064fde7f9589ffe072))
* modern request-plane validation ladder for serve ([#270](https://github.com/shigechika/mcp-stdio/issues/270) Phase 3 P3-A) ([#371](https://github.com/shigechika/mcp-stdio/issues/371)) ([f8f916d](https://github.com/shigechika/mcp-stdio/commit/f8f916d03fb5eeca63183118572b567e401ae964))

## [0.36.0](https://github.com/shigechika/mcp-stdio/compare/v0.35.0...v0.36.0) (2026-07-31)


### Features

* integration harness against python-sdk v2.0.0 as the 2026-07-28 reference peer ([#367](https://github.com/shigechika/mcp-stdio/issues/367)) ([#368](https://github.com/shigechika/mcp-stdio/issues/368)) ([8838f23](https://github.com/shigechika/mcp-stdio/commit/8838f232ad4b44289619a826a557b51459b0e59c))

## [0.35.0](https://github.com/shigechika/mcp-stdio/compare/v0.34.1...v0.35.0) (2026-07-31)


### Features

* stdin handoff + true cancel abort on the modern era ([#270](https://github.com/shigechika/mcp-stdio/issues/270) Phase 2 PR D) ([#362](https://github.com/shigechika/mcp-stdio/issues/362)) ([203b9c2](https://github.com/shigechika/mcp-stdio/commit/203b9c273cff546b35a9a2109a9f838113f9a5ed))

## [0.34.1](https://github.com/shigechika/mcp-stdio/compare/v0.34.0...v0.34.1) (2026-07-31)


### Bug Fixes

* **ci:** close the supplement bypass and size the ledger cap by measurement ([#363](https://github.com/shigechika/mcp-stdio/issues/363)) ([7feccf4](https://github.com/shigechika/mcp-stdio/commit/7feccf454724e9f1ebf3ec173a0845c98d78410f))

## [0.34.0](https://github.com/shigechika/mcp-stdio/compare/v0.33.0...v0.34.0) (2026-07-31)


### Features

* intercept resources/subscribe with dedicated resource listen stream ([#270](https://github.com/shigechika/mcp-stdio/issues/270) Phase 2 PR B) ([#358](https://github.com/shigechika/mcp-stdio/issues/358)) ([8a0947b](https://github.com/shigechika/mcp-stdio/commit/8a0947b886288d44f9df544fe0634bb273c41d08))


### Bug Fixes

* **ci:** close five correctness gaps in the ai-review ledger machinery ([#360](https://github.com/shigechika/mcp-stdio/issues/360)) ([e7b9239](https://github.com/shigechika/mcp-stdio/commit/e7b9239d7d5c988a10c63110d637ccbb1d65f4f3))

## [0.33.0](https://github.com/shigechika/mcp-stdio/compare/v0.32.0...v0.33.0) (2026-07-31)


### Features

* MRTR bridge on the modern era ([#270](https://github.com/shigechika/mcp-stdio/issues/270) Phase 2 PR C) ([#356](https://github.com/shigechika/mcp-stdio/issues/356)) ([3c1c5d7](https://github.com/shigechika/mcp-stdio/commit/3c1c5d76c8f2b001f3d4afdc07d9fa211728527f))

## [0.32.0](https://github.com/shigechika/mcp-stdio/compare/v0.31.0...v0.32.0) (2026-07-30)


### Features

* subscriptions/listen stream on the modern era ([#270](https://github.com/shigechika/mcp-stdio/issues/270) Phase 2 PR A) ([#352](https://github.com/shigechika/mcp-stdio/issues/352)) ([b28fe63](https://github.com/shigechika/mcp-stdio/commit/b28fe6369633fe45fd88f4cd2f12669ae0ade0d6))


### Bug Fixes

* **ci:** verifier diff parity and case-insensitive DROP id matching ([#355](https://github.com/shigechika/mcp-stdio/issues/355)) ([9eb7cb4](https://github.com/shigechika/mcp-stdio/commit/9eb7cb41f661b4c9405fae7ad660a1034fab8032))

## [0.31.0](https://github.com/shigechika/mcp-stdio/compare/v0.30.1...v0.31.0) (2026-07-30)


### Features

* dual-mode Streamable HTTP era detection for MCP 2026-07-28 (Phase 1, [#270](https://github.com/shigechika/mcp-stdio/issues/270)) ([#350](https://github.com/shigechika/mcp-stdio/issues/350)) ([5580f98](https://github.com/shigechika/mcp-stdio/commit/5580f98ef6bcf6a40c2d93d4dc315ca37adea759))

## [0.30.1](https://github.com/shigechika/mcp-stdio/compare/v0.30.0...v0.30.1) (2026-07-28)


### Bug Fixes

* **oauth:** do not reuse client credentials across authorization servers ([#347](https://github.com/shigechika/mcp-stdio/issues/347)) ([5309a58](https://github.com/shigechika/mcp-stdio/commit/5309a58bb3482d186bfa3a52ec2aa7d285ab53ad))
* **oauth:** validate iss before acting on an error response, compare exactly ([#344](https://github.com/shigechika/mcp-stdio/issues/344)) ([f97865a](https://github.com/shigechika/mcp-stdio/commit/f97865af6d18f2cf4aa276ecba19edf1b93fe9a6))

## [0.30.0](https://github.com/shigechika/mcp-stdio/compare/v0.29.1...v0.30.0) (2026-07-27)


### Features

* **serve:** log conflicting id and methods on duplicate-id 409 ([#337](https://github.com/shigechika/mcp-stdio/issues/337)) ([bd5a1fe](https://github.com/shigechika/mcp-stdio/commit/bd5a1fe6e8a154a480598d0bf316fcfd07ee4d95))


### Bug Fixes

* **ci:** read AI-review guidance from the base revision, drop the checkout ([#343](https://github.com/shigechika/mcp-stdio/issues/343)) ([af37ceb](https://github.com/shigechika/mcp-stdio/commit/af37cebaad31d9b9a4476c4ab847260742659953))

## [0.29.1](https://github.com/shigechika/mcp-stdio/compare/v0.29.0...v0.29.1) (2026-07-24)


### Bug Fixes

* piggyback same-payload duplicate in-flight requests instead of 409 ([#332](https://github.com/shigechika/mcp-stdio/issues/332)) ([a8a7a09](https://github.com/shigechika/mcp-stdio/commit/a8a7a099fc0b113a82421110a987ea9deb3d0406))

## [0.29.0](https://github.com/shigechika/mcp-stdio/compare/v0.28.1...v0.29.0) (2026-07-23)


### Features

* **serve:** --max-sessions-per-owner for ghost session reclamation ([#329](https://github.com/shigechika/mcp-stdio/issues/329)) ([f16ce0b](https://github.com/shigechika/mcp-stdio/commit/f16ce0b56838f891dcb3cbed741c0b2bb37f637a))

## [0.28.1](https://github.com/shigechika/mcp-stdio/compare/v0.28.0...v0.28.1) (2026-07-20)


### Bug Fixes

* make scrub_secrets regex linear (polynomial-ReDoS) ([#325](https://github.com/shigechika/mcp-stdio/issues/325)) ([20f6e25](https://github.com/shigechika/mcp-stdio/commit/20f6e256441ebeff2cdc7b78a6c871f31116e4d0))
* redact credentials from upstream URL before logging ([#322](https://github.com/shigechika/mcp-stdio/issues/322)) ([bf181fa](https://github.com/shigechika/mcp-stdio/commit/bf181fac9fc73c013d0b1c2dc37831134991ea4a))
* scrub URL userinfo at the log() sink (covers exception paths) ([#324](https://github.com/shigechika/mcp-stdio/issues/324)) ([6488aee](https://github.com/shigechika/mcp-stdio/commit/6488aee64064863a5f38a64f83202d4c5e7ca6d9))

## [0.28.0](https://github.com/shigechika/mcp-stdio/compare/v0.27.0...v0.28.0) (2026-07-12)


### Features

* **oauth:** log the scope granted by the authorization server ([#316](https://github.com/shigechika/mcp-stdio/issues/316)) ([9866721](https://github.com/shigechika/mcp-stdio/commit/9866721b0e1d00f8fed2f911f2cda1e55a3472c9))

## [0.27.0](https://github.com/shigechika/mcp-stdio/compare/v0.26.2...v0.27.0) (2026-07-12)


### Features

* **oauth:** add --oauth-resource to send a custom RFC 8707 resource value ([#310](https://github.com/shigechika/mcp-stdio/issues/310)) ([7b4d66e](https://github.com/shigechika/mcp-stdio/commit/7b4d66ee2f1b2391eb7b71243111e886d051497d))

## [0.26.2](https://github.com/shigechika/mcp-stdio/compare/v0.26.1...v0.26.2) (2026-07-11)


### Bug Fixes

* **serve:** reject a JSON-RPC id already in flight on the same session ([#307](https://github.com/shigechika/mcp-stdio/issues/307)) ([fa4e937](https://github.com/shigechika/mcp-stdio/commit/fa4e937128d0984cc5ab33639fc838df74c64990))

## [0.26.1](https://github.com/shigechika/mcp-stdio/compare/v0.26.0...v0.26.1) (2026-07-09)


### Bug Fixes

* synchronize POST thread in flaky SSE notification test ([#301](https://github.com/shigechika/mcp-stdio/issues/301)) ([527308d](https://github.com/shigechika/mcp-stdio/commit/527308d47c858fc2871a502dd65018f9fc071fd9))

## [0.26.0](https://github.com/shigechika/mcp-stdio/compare/v0.25.1...v0.26.0) (2026-07-04)


### Features

* **serve:** log the rejected redirect_uri on invalid_redirect_uri ([#287](https://github.com/shigechika/mcp-stdio/issues/287)) ([cc9b0bb](https://github.com/shigechika/mcp-stdio/commit/cc9b0bbb6936839225906345b07d01277adab7d1))

## [0.25.1](https://github.com/shigechika/mcp-stdio/compare/v0.25.0...v0.25.1) (2026-07-02)


### Bug Fixes

* **run_sse:** synthesize errors for requests in flight when the SSE stream drops ([#282](https://github.com/shigechika/mcp-stdio/issues/282)) ([f7de3be](https://github.com/shigechika/mcp-stdio/commit/f7de3be64aaab42c1b0d5d628d549ca55764e2be))

## [0.25.0](https://github.com/shigechika/mcp-stdio/compare/v0.24.1...v0.25.0) (2026-07-02)


### Features

* **serve:** --token-store persists AS-issued tokens across restarts ([#279](https://github.com/shigechika/mcp-stdio/issues/279)) ([e8ca6b9](https://github.com/shigechika/mcp-stdio/commit/e8ca6b98c4e160df31dd399c342137c48fab214b))

## [0.24.1](https://github.com/shigechika/mcp-stdio/compare/v0.24.0...v0.24.1) (2026-07-02)


### Bug Fixes

* anchor WWW-Authenticate auth-param parsing at token boundaries ([#275](https://github.com/shigechika/mcp-stdio/issues/275)) ([a8c2178](https://github.com/shigechika/mcp-stdio/commit/a8c217826c72d13385bf5098595589e6e3dcf928))

## [0.24.0](https://github.com/shigechika/mcp-stdio/compare/v0.23.0...v0.24.0) (2026-07-01)


### Features

* **serve:** --allow-redirect-uri exact-match allowlist for remote HTTPS clients ([#268](https://github.com/shigechika/mcp-stdio/issues/268)) ([a426de1](https://github.com/shigechika/mcp-stdio/commit/a426de12ce9723a0620d5d236420995c39a5b5d8))

## [0.23.0](https://github.com/shigechika/mcp-stdio/compare/v0.22.0...v0.23.0) (2026-06-30)


### Features

* **oauth:** support Client ID Metadata Documents (MCP 2025-11-25 / [#60](https://github.com/shigechika/mcp-stdio/issues/60)) ([#265](https://github.com/shigechika/mcp-stdio/issues/265)) ([80de50a](https://github.com/shigechika/mcp-stdio/commit/80de50a104c9fe80eaf610ff397fd961f89f58f0))

## [0.22.0](https://github.com/shigechika/mcp-stdio/compare/v0.21.0...v0.22.0) (2026-06-30)


### Features

* **serve:** bind OAuth sessions to the authenticated user ([#263](https://github.com/shigechika/mcp-stdio/issues/263)) ([9fcd8d3](https://github.com/shigechika/mcp-stdio/commit/9fcd8d33d2a492f1e156a53f9b3116c1261d36c7))
* **serve:** per-session backend child for concurrent-client isolation ([#258](https://github.com/shigechika/mcp-stdio/issues/258)) ([624581f](https://github.com/shigechika/mcp-stdio/commit/624581fdf05ada70ac897d8db7d025f9bc327d27))
* **serve:** session resource governance — max-sessions, idle eviction ([#261](https://github.com/shigechika/mcp-stdio/issues/261)) ([78c8e88](https://github.com/shigechika/mcp-stdio/commit/78c8e88e5e274d193e379137b98f2972a323be97))

## [0.21.0](https://github.com/shigechika/mcp-stdio/compare/v0.20.0...v0.21.0) (2026-06-29)


### Features

* **oauth:** --oauth-eager cold-start (local initialize + background OAuth) ([#256](https://github.com/shigechika/mcp-stdio/issues/256)) ([3b30c8e](https://github.com/shigechika/mcp-stdio/commit/3b30c8efa7859027a8ac7cb0a3082729f64e8f32))
* **oauth:** --oauth-use-id-token to present the OIDC id_token as Bearer ([#59](https://github.com/shigechika/mcp-stdio/issues/59)) ([#254](https://github.com/shigechika/mcp-stdio/issues/254)) ([863ee66](https://github.com/shigechika/mcp-stdio/commit/863ee6669c7deaa2a4a1a15a12b59faf0222317a))

## [0.20.0](https://github.com/shigechika/mcp-stdio/compare/v0.19.0...v0.20.0) (2026-06-29)


### Features

* **oauth:** send application_type "native" in DCR (SEP-837 / RFC 8252) ([#252](https://github.com/shigechika/mcp-stdio/issues/252)) ([8201d57](https://github.com/shigechika/mcp-stdio/commit/8201d57c8c7089b3f15b6156172fc7f1ef22e977))

## [0.19.0](https://github.com/shigechika/mcp-stdio/compare/v0.18.0...v0.19.0) (2026-06-29)


### Features

* **oauth:** OpenID Connect Discovery 1.0 fallback for AS metadata ([#248](https://github.com/shigechika/mcp-stdio/issues/248)) ([9b60eb9](https://github.com/shigechika/mcp-stdio/commit/9b60eb9b25901ea5533a8f5c5a27c371130e0d58))
* **serve:** RFC 9207 iss, RFC 7591 invalid_redirect_uri + DCR no-store ([#249](https://github.com/shigechika/mcp-stdio/issues/249)) ([be7de4f](https://github.com/shigechika/mcp-stdio/commit/be7de4fb71e7fe8cd51f7afd4fc05e168c97b402))
* **serve:** RS audience binding, invalid_token, replay revocation ([#250](https://github.com/shigechika/mcp-stdio/issues/250)) ([dc0d8bf](https://github.com/shigechika/mcp-stdio/commit/dc0d8bfa8aa5ed9d5c2d1e031f6a5b5bc43f7a3d))

## [0.18.0](https://github.com/shigechika/mcp-stdio/compare/v0.17.0...v0.18.0) (2026-06-29)


### Features

* **serve:** path-scoped issuer for --enable-oauth ([#245](https://github.com/shigechika/mcp-stdio/issues/245)) ([#246](https://github.com/shigechika/mcp-stdio/issues/246)) ([59e4027](https://github.com/shigechika/mcp-stdio/commit/59e40277f145f7b8529e8f9d1cc830df04017867))

## [0.17.0](https://github.com/shigechika/mcp-stdio/compare/v0.16.0...v0.17.0) (2026-06-28)


### Features

* proactive OAuth token refresh timer for HTTP-200 expiry gateways ([#243](https://github.com/shigechika/mcp-stdio/issues/243)) ([a479527](https://github.com/shigechika/mcp-stdio/commit/a479527ef76e45381ea6c35f33f02fdb63c8a82f))

## [0.16.0](https://github.com/shigechika/mcp-stdio/compare/v0.15.0...v0.16.0) (2026-06-03)


### Features

* add `serve` reverse-gateway mode (HTTP -&gt; stdio, no-auth) ([#236](https://github.com/shigechika/mcp-stdio/issues/236)) ([a7eda89](https://github.com/shigechika/mcp-stdio/commit/a7eda897cd0c942dc0309ca2ec7f4013326108fb))
* embedded OAuth 2.1 Authorization Server for serve mode ([#239](https://github.com/shigechika/mcp-stdio/issues/239)) ([f992350](https://github.com/shigechika/mcp-stdio/commit/f9923506262e4381d9f11c78a2cd1f1d36dabef8))
* serve mode optional static-token auth + RFC 9728 metadata ([#238](https://github.com/shigechika/mcp-stdio/issues/238)) ([0c0ca27](https://github.com/shigechika/mcp-stdio/commit/0c0ca2796924e992787ddda0ddbdc2d84b9f8d59))

## [0.15.0](https://github.com/shigechika/mcp-stdio/compare/v0.14.0...v0.15.0) (2026-06-01)


### Features

* **cli:** add --oauth-timeout for the interactive flow; fix README RFC 8414 sections ([#181](https://github.com/shigechika/mcp-stdio/issues/181)) ([b4cd7a9](https://github.com/shigechika/mcp-stdio/commit/b4cd7a966226f3eae21d5b4c11a7727b125cfdf4))
* **oauth:** enforce RFC 9207 missing-iss rejection; validate fallback endpoints ([#159](https://github.com/shigechika/mcp-stdio/issues/159)) ([cde5e6a](https://github.com/shigechika/mcp-stdio/commit/cde5e6aba7802e628c03c6751e738a15bf71193d))
* **relay:** honour Retry-After on 503 like 429; document SSE refresh timing ([#148](https://github.com/shigechika/mcp-stdio/issues/148)) ([5f05226](https://github.com/shigechika/mcp-stdio/commit/5f05226c2cce85da22949d3f864dd31a879d5428))


### Bug Fixes

* **cli:** apply the CR/LF/NUL header ban to OAuth-acquired access tokens ([#166](https://github.com/shigechika/mcp-stdio/issues/166)) ([bc65324](https://github.com/shigechika/mcp-stdio/commit/bc653240eb3526b3519925f4d55d3b73eff69335))
* **cli:** catch refresher() exceptions; treat empty leeway env var as unset ([#115](https://github.com/shigechika/mcp-stdio/issues/115)) ([ee69a7e](https://github.com/shigechika/mcp-stdio/commit/ee69a7e2a94b4607144dc5919767510ae456e503))
* **cli:** de-dup a case-variant -H authorization against the OAuth token ([#103](https://github.com/shigechika/mcp-stdio/issues/103)) ([99e4721](https://github.com/shigechika/mcp-stdio/commit/99e472125334f5844e0a0aaa3dc6b8b1379ae4df))
* **cli:** empty --bearer-token conflicts with --oauth; warn on overridden -H Authorization ([#122](https://github.com/shigechika/mcp-stdio/issues/122)) ([d620ac9](https://github.com/shigechika/mcp-stdio/commit/d620ac9aa37663c822cdd7997c6accc55a5962d5))
* **cli:** env bearer token must not block --oauth; -H overrides case-insensitively ([#81](https://github.com/shigechika/mcp-stdio/issues/81)) ([578a62e](https://github.com/shigechika/mcp-stdio/commit/578a62ef341eabd01b2668f8410f1e4a623c480b))
* **cli:** env MCP_OAUTH_CLIENT_ID no longer warns; validate bearer token CR/LF/NUL ([#108](https://github.com/shigechika/mcp-stdio/issues/108)) ([9aab96a](https://github.com/shigechika/mcp-stdio/commit/9aab96a67f2cbba8deeaf8174c6f4b271a59c167))
* **cli:** exit cleanly on Ctrl-C during the pre-relay OAuth flow ([#214](https://github.com/shigechika/mcp-stdio/issues/214)) ([ad33c72](https://github.com/shigechika/mcp-stdio/commit/ad33c72f734c24f8463b69885267ce004eee1495))
* **cli:** float --sse-read-timeout default; cover OAuth-token header-injection guard ([#174](https://github.com/shigechika/mcp-stdio/issues/174)) ([53d3779](https://github.com/shigechika/mcp-stdio/commit/53d377924ecc83660c578809032136611a51a1e0))
* **cli:** float timeout defaults; sync CLAUDE.md OAuth description ([#157](https://github.com/shigechika/mcp-stdio/issues/157)) ([c6d67e7](https://github.com/shigechika/mcp-stdio/commit/c6d67e7460df100737c3bccb2ab1c9d2af880a29))
* **cli:** freeze base headers in OAuth callbacks instead of aliasing the live dict ([#227](https://github.com/shigechika/mcp-stdio/issues/227)) ([210fd57](https://github.com/shigechika/mcp-stdio/commit/210fd57f72e36911633727ce894d839e2da13314))
* **cli:** make --check honour --transport sse ([#111](https://github.com/shigechika/mcp-stdio/issues/111)) ([36b3d49](https://github.com/shigechika/mcp-stdio/commit/36b3d491870183be652f0ac5b7a7fa372c4d42a8))
* **cli:** pin follow_redirects=False on the OAuth credential-bearing client ([#95](https://github.com/shigechika/mcp-stdio/issues/95)) ([a5ad280](https://github.com/shigechika/mcp-stdio/commit/a5ad280463cd303296648fa33eb2c83f8046b04a))
* **cli:** presence-based OAuth-only warning for --client-id; note leeway is OAuth-only ([#170](https://github.com/shigechika/mcp-stdio/issues/170)) ([b12c356](https://github.com/shigechika/mcp-stdio/commit/b12c356f4e40dace745f8c97769638f584c4efe8))
* **cli:** propagate --oauth-timeout to the mid-session step-up flow ([#184](https://github.com/shigechika/mcp-stdio/issues/184)) ([db62258](https://github.com/shigechika/mcp-stdio/commit/db622584080c968f3afb37f02600366f4b399a0e))
* **cli:** reject negative --timeout-connect/--timeout-read/--sse-read-timeout ([#85](https://github.com/shigechika/mcp-stdio/issues/85)) ([c6eb080](https://github.com/shigechika/mcp-stdio/commit/c6eb0803b8b43c11a0c86460f212b326a5554495))
* **cli:** reject non-finite (nan/inf) values in the float validators ([#190](https://github.com/shigechika/mcp-stdio/issues/190)) ([9748809](https://github.com/shigechika/mcp-stdio/commit/9748809d530403a1dfccb01d461782053fa4b1f0))
* **cli:** reject zero --timeout-connect / --timeout-read ([#130](https://github.com/shigechika/mcp-stdio/issues/130)) ([fbb61e2](https://github.com/shigechika/mcp-stdio/commit/fbb61e294ae1f0d3be538702aab63015dd461eec))
* **cli:** warn on an empty --bearer-token; route bearer via _bearer_header_value ([#192](https://github.com/shigechika/mcp-stdio/issues/192)) ([6e2f9ab](https://github.com/shigechika/mcp-stdio/commit/6e2f9ab28d345b762a74a2ef6da649d20318c6a5))
* **cli:** warn when -H 'Authorization' overrides an explicit --bearer-token ([#197](https://github.com/shigechika/mcp-stdio/issues/197)) ([5be66b6](https://github.com/shigechika/mcp-stdio/commit/5be66b63617bcab1ebe0876d859e86a05da85ec9))
* **cli:** warn when OAuth-only flags are set without an OAuth flow ([#106](https://github.com/shigechika/mcp-stdio/issues/106)) ([84c733a](https://github.com/shigechika/mcp-stdio/commit/84c733a50444be7b886912d517ce3ea21bba50ab))
* **oauth:** bound callback serve loop; always show device user_code; cover XSS+absent-state ([#156](https://github.com/shigechika/mcp-stdio/issues/156)) ([0a538d2](https://github.com/shigechika/mcp-stdio/commit/0a538d236fbe94237b8bbe1f0a5fc1dfe703c0ce))
* **oauth:** clear error on non-JSON token body; ignore non-positive expires_in ([#168](https://github.com/shigechika/mcp-stdio/issues/168)) ([73c731b](https://github.com/shigechika/mcp-stdio/commit/73c731bc1c0f246a631a7c26682d7653ab4589e4))
* **oauth:** close localhost callback server when DCR fails ([#110](https://github.com/shigechika/mcp-stdio/issues/110)) ([fb47a12](https://github.com/shigechika/mcp-stdio/commit/fb47a12f11bbabbfc3fe5a72daed2f55a2d19153))
* **oauth:** compare PRM resource against the userinfo-stripped identifier ([#232](https://github.com/shigechika/mcp-stdio/issues/232)) ([810267c](https://github.com/shigechika/mcp-stdio/commit/810267c5474f6a663ba8392ff0e38f6f32d191e4))
* **oauth:** fast-fail the device-flow poll on a non-compliant status ([#217](https://github.com/shigechika/mcp-stdio/issues/217)) ([6fd0182](https://github.com/shigechika/mcp-stdio/commit/6fd0182dd9f6b6cf51f283d3a86b2774c72acbd9))
* **oauth:** harden AS-supplied JSON against non-standard / non-object values ([#223](https://github.com/shigechika/mcp-stdio/issues/223)) ([c296995](https://github.com/shigechika/mcp-stdio/commit/c296995ff6bd4453439cfd4dfe47e6cb418bb8bb))
* **oauth:** harden the OAuth callback handler and reject non-finite expires_in ([#231](https://github.com/shigechika/mcp-stdio/issues/231)) ([7ecbb04](https://github.com/shigechika/mcp-stdio/commit/7ecbb0446f33078b27510db3b1cea2add9d0d523))
* **oauth:** honour --oauth-timeout for the device-code wait ([#226](https://github.com/shigechika/mcp-stdio/issues/226)) ([78d9d48](https://github.com/shigechika/mcp-stdio/commit/78d9d48c8f99482891a7545a831ce8a7519dcfce))
* **oauth:** honour AS-assigned token_endpoint_auth_method from DCR response ([#225](https://github.com/shigechika/mcp-stdio/issues/225)) ([7da4bf1](https://github.com/shigechika/mcp-stdio/commit/7da4bf1d9d3965f798c10fe1057a73b8b36aef24))
* **oauth:** in-body error on form-urlencoded, validate verification_uri, clearer errors ([#84](https://github.com/shigechika/mcp-stdio/issues/84)) ([f48d60d](https://github.com/shigechika/mcp-stdio/commit/f48d60dc81f1f20291bb3f22fa498acd29092a5c))
* **oauth:** make RFC 9207 iss comparison trailing-slash tolerant ([#180](https://github.com/shigechika/mcp-stdio/issues/180)) ([cfe89c3](https://github.com/shigechika/mcp-stdio/commit/cfe89c32b973816e007f5e43eca331bbfda2e7ea))
* **oauth:** neutral callback page for a bare hit; correct RFC 9728 §3.3 comment ([#164](https://github.com/shigechika/mcp-stdio/issues/164)) ([6cbf339](https://github.com/shigechika/mcp-stdio/commit/6cbf3396a9303f8f278010c0cd2a4243065d7684))
* **oauth:** persist AS issuer for RFC 9207; strip userinfo from default endpoints; cap device-flow lifetime ([#117](https://github.com/shigechika/mcp-stdio/issues/117)) ([43bad90](https://github.com/shigechika/mcp-stdio/commit/43bad9060fa512648ed8e10dd0633b69e28ada15))
* **oauth:** persist RFC 9207 iss-support so step-up keeps the missing-iss reject ([#162](https://github.com/shigechika/mcp-stdio/issues/162)) ([3b39e7c](https://github.com/shigechika/mcp-stdio/commit/3b39e7c8a5ef5579e93ec90767a0f8f38ff6edfa))
* **oauth:** phase-3 defaults target the discovered AS origin; precise RFC 8414 citation ([#140](https://github.com/shigechika/mcp-stdio/issues/140)) ([1acf71b](https://github.com/shigechika/mcp-stdio/commit/1acf71b7d75a84d470810e931f67624663bd7544))
* **oauth:** preserve cached refresh_token across a step-up re-authorization ([#229](https://github.com/shigechika/mcp-stdio/issues/229)) ([0e891dc](https://github.com/shigechika/mcp-stdio/commit/0e891dc1006237db1b9103d8fdcb7338e075e9b0))
* **oauth:** preserve granted scope across refresh; 5 defense-in-depth fixes ([#119](https://github.com/shigechika/mcp-stdio/issues/119)) ([1c3fe87](https://github.com/shigechika/mcp-stdio/commit/1c3fe87febe887059a0ec01b987a073da9fef063))
* **oauth:** preserve requested scope on device flow; cover non-JSON poll error ([#146](https://github.com/shigechika/mcp-stdio/issues/146)) ([a711d99](https://github.com/shigechika/mcp-stdio/commit/a711d99278c24542e0d27fee7c68741cb9387c81))
* **oauth:** preserve scope on step-up; strip/reject userinfo in discovery ([#124](https://github.com/shigechika/mcp-stdio/issues/124)) ([df672d7](https://github.com/shigechika/mcp-stdio/commit/df672d7e038d7a3b5ce4c6ce4a7ffaf9b2586995))
* **oauth:** probe WWW-Authenticate on step-up re-discovery ([#151](https://github.com/shigechika/mcp-stdio/issues/151)) ([49a57dd](https://github.com/shigechika/mcp-stdio/commit/49a57dde8abf53cb5250baa54d1ca14fe457159c))
* **oauth:** reject cross-origin issuer; sanitize refresh-failure log ([#185](https://github.com/shigechika/mcp-stdio/issues/185)) ([e190aa0](https://github.com/shigechika/mcp-stdio/commit/e190aa0673bf3687955129c25edd243d771c5524))
* **oauth:** reject endpoint URLs with embedded userinfo; test client_secret_post device flow ([#105](https://github.com/shigechika/mcp-stdio/issues/105)) ([a60396a](https://github.com/shigechika/mcp-stdio/commit/a60396a80515c038cb5d7d0122fea2ff8d075893))
* **oauth:** reject malformed-port URLs instead of crashing the discovery walk ([#201](https://github.com/shigechika/mcp-stdio/issues/201)) ([7a6cda3](https://github.com/shigechika/mcp-stdio/commit/7a6cda347400f89e551e52b4031c2591fc723cc3))
* **oauth:** reject schemeless/hostless server URL in _authorization_base_url ([#133](https://github.com/shigechika/mcp-stdio/issues/133)) ([435a7d7](https://github.com/shigechika/mcp-stdio/commit/435a7d70bfa7d413be68e8d90b1da206249d870f))
* **oauth:** reject userinfo in PRM hint; close callback server on any auth-flow failure ([#135](https://github.com/shigechika/mcp-stdio/issues/135)) ([03f65d6](https://github.com/shigechika/mcp-stdio/commit/03f65d6e3d9c7d70d41c17828272fe3f04429e5b))
* **oauth:** return None on access_token-less refresh; strip resource userinfo ([#220](https://github.com/shigechika/mcp-stdio/issues/220)) ([2887f7d](https://github.com/shigechika/mcp-stdio/commit/2887f7d3b7b234ec7ceec6d2a2c458be440bdcc2))
* **oauth:** sanitize AS-supplied error strings; cover explicit-client-id device flow ([#143](https://github.com/shigechika/mcp-stdio/issues/143)) ([b171056](https://github.com/shigechika/mcp-stdio/commit/b17105698135c0f63fada27587e0f0b9c2218bfb))
* **oauth:** sanitize device-flow poll error log; cover untested poll/cache edges ([#193](https://github.com/shigechika/mcp-stdio/issues/193)) ([57bc2d5](https://github.com/shigechika/mcp-stdio/commit/57bc2d58a746dbd564ae0ae0e4060e52ab2ab475))
* **oauth:** set no-store / no-referrer on the OAuth callback page ([#206](https://github.com/shigechika/mcp-stdio/issues/206)) ([c573e0b](https://github.com/shigechika/mcp-stdio/commit/c573e0bdfea54f06fbacb283a054aa736b33cf9b))
* **oauth:** single-shot callback capture; don't abandon discovery on a useless PRM ([#128](https://github.com/shigechika/mcp-stdio/issues/128)) ([c5b63d2](https://github.com/shigechika/mcp-stdio/commit/c5b63d2e48a2c5bc8e42561ea67a85b1561b18a5))
* **oauth:** strip query from AS base before issuer comparison; cover edge branches ([#175](https://github.com/shigechika/mcp-stdio/issues/175)) ([ad53cd9](https://github.com/shigechika/mcp-stdio/commit/ad53cd9112c56e378f58044e8bc50b794265dee0))
* **oauth:** surface RFC 6749 §5.2 token-error bodies; validate DCR credentials ([#210](https://github.com/shigechika/mcp-stdio/issues/210)) ([ed87b0e](https://github.com/shigechika/mcp-stdio/commit/ed87b0e8aaa98765a36b307393daf563cbdf9ac7))
* **oauth:** tolerate null token_type and non-numeric device-flow ints; exact iss ([#101](https://github.com/shigechika/mcp-stdio/issues/101)) ([b4dc399](https://github.com/shigechika/mcp-stdio/commit/b4dc39902a3fecb9f23f9586e93d7df727e2d5e2))
* **oauth:** validate AS-metadata endpoints, coerce expires_in, Google device fallback ([#79](https://github.com/shigechika/mcp-stdio/issues/79)) ([cbf49f2](https://github.com/shigechika/mcp-stdio/commit/cbf49f2122589f9a806db70fdec55e26a6be94cf))
* **oauth:** validate CSRF state before acting on an error callback ([#213](https://github.com/shigechika/mcp-stdio/issues/213)) ([3623731](https://github.com/shigechika/mcp-stdio/commit/36237311dfaa6954e20348482ab86164b0ed24e0))
* **oauth:** validate RFC 9207 iss; drop double-slash in default endpoints ([#98](https://github.com/shigechika/mcp-stdio/issues/98)) ([4e5c663](https://github.com/shigechika/mcp-stdio/commit/4e5c6635c9c6eb0f84d867e97abb49786d1c028a))
* **oauth:** warn on non-Bearer token_type, cap device poll interval, AS issuer query ([#91](https://github.com/shigechika/mcp-stdio/issues/91)) ([5062339](https://github.com/shigechika/mcp-stdio/commit/5062339185ecee3fd0ea636bc6b2441180ebee65))
* **relay:** adopt rotated session id across chained recovery; honour fresh SSE endpoint on retry ([#132](https://github.com/shigechika/mcp-stdio/issues/132)) ([cb33fa5](https://github.com/shigechika/mcp-stdio/commit/cb33fa5f6d0a3c1af391e5e0fb39859f16fc079c))
* **relay:** adopt session-id before recovery retry; reader join on shutdown; coverage ([#89](https://github.com/shigechika/mcp-stdio/issues/89)) ([f6ce174](https://github.com/shigechika/mcp-stdio/commit/f6ce17403258382a0157e05be14c77f328d448b3))
* **relay:** cancel filter — consume-on-match + untrack reused ids; SSE polish ([#97](https://github.com/shigechika/mcp-stdio/issues/97)) ([1e1b1d0](https://github.com/shigechika/mcp-stdio/commit/1e1b1d03da4f26c14ada4711538632e32b16d9b0))
* **relay:** catch DecodingError in the POST cores so a bad body can't crash the gateway ([#145](https://github.com/shigechika/mcp-stdio/issues/145)) ([48b1fe1](https://github.com/shigechika/mcp-stdio/commit/48b1fe1354b1bc72c08d55ce7789fd02ad59e76b))
* **relay:** dedup MCP-Protocol-Version / Mcp-Session-Id in _prepare_headers ([#189](https://github.com/shigechika/mcp-stdio/issues/189)) ([4e0077e](https://github.com/shigechika/mcp-stdio/commit/4e0077e3545f55ff90c39dc70620eca8f8de35e6))
* **relay:** deliver interleaved server-initiated messages on the pagination path ([#172](https://github.com/shigechika/mcp-stdio/issues/172)) ([409dbe5](https://github.com/shigechika/mcp-stdio/commit/409dbe528ffba9cf2a9371091a1133507974075c))
* **relay:** don't adopt a 202-to-request's session id (gate parity) ([#207](https://github.com/shigechika/mcp-stdio/issues/207)) ([c3acaac](https://github.com/shigechika/mcp-stdio/commit/c3acaac5b78b379acc4b2d2615d7d1bee3e7c6f5))
* **relay:** don't adopt a session id echoed on a rejected response; strengthen cancel-tracker test ([#158](https://github.com/shigechika/mcp-stdio/issues/158)) ([1a98e72](https://github.com/shigechika/mcp-stdio/commit/1a98e7232394581f09f2ee392b082de9583c6764))
* **relay:** don't dispatch an empty-data SSE event (WHATWG) ([#141](https://github.com/shigechika/mcp-stdio/issues/141)) ([a975e9a](https://github.com/shigechika/mcp-stdio/commit/a975e9a84e070a0f75e28399e747401907207825))
* **relay:** gate 403 session-id adoption on a parseable scope challenge ([#182](https://github.com/shigechika/mcp-stdio/issues/182)) ([b8f5c7c](https://github.com/shigechika/mcp-stdio/commit/b8f5c7cdbc7c149853a5f9975da205eef026cac4))
* **relay:** gate inline 401-retry session-id adoption on a parseable scope ([#191](https://github.com/shigechika/mcp-stdio/issues/191)) ([5b7410f](https://github.com/shigechika/mcp-stdio/commit/5b7410faaaa221813d770bfed55385055b59358f))
* **relay:** gate inline 401/403 retry session-id adoption on a recoverable status ([#176](https://github.com/shigechika/mcp-stdio/issues/176)) ([fb3654f](https://github.com/shigechika/mcp-stdio/commit/fb3654f50661a63ef50e83de1320f17c7d919119))
* **relay:** gate MCP-Protocol-Version strip on a parse-authoritative initialize check ([#155](https://github.com/shigechika/mcp-stdio/issues/155)) ([5526a0b](https://github.com/shigechika/mcp-stdio/commit/5526a0b668fd5c91741bd698373531312a2bef4c))
* **relay:** gate notification error-synthesis in POST helpers; don't downgrade protocol on session recovery ([#113](https://github.com/shigechika/mcp-stdio/issues/113)) ([6a271d2](https://github.com/shigechika/mcp-stdio/commit/6a271d26202d2620dfb0ebbf89766a6830fbcf3b))
* **relay:** gate protocol-version capture on parse-authoritative initialize check ([#230](https://github.com/shigechika/mcp-stdio/issues/230)) ([0bbcadb](https://github.com/shigechika/mcp-stdio/commit/0bbcadbd7488323e1b45180520ea3d8c19f32eae))
* **relay:** keep reading the --check SSE stream past interleaved frames ([#216](https://github.com/shigechika/mcp-stdio/issues/216)) ([8f27103](https://github.com/shigechika/mcp-stdio/commit/8f271039e9b93a36789377e09bcb286159aa8fc9))
* **relay:** make "never crash the gateway" structural; soften 503 idempotency note ([#152](https://github.com/shigechika/mcp-stdio/issues/152)) ([cce0b17](https://github.com/shigechika/mcp-stdio/commit/cce0b17a19b94cfe861f3e1eb46ad0ad6489b69e))
* **relay:** make the outer handler's recovery write survive a broken pipe ([#202](https://github.com/shigechika/mcp-stdio/issues/202)) ([d041f33](https://github.com/shigechika/mcp-stdio/commit/d041f33097f3ea32d56c26d0f5886c6a6fbb1747))
* **relay:** never synthesize a response for a notification; cover 401→404 cascade ([#109](https://github.com/shigechika/mcp-stdio/issues/109)) ([02fba4b](https://github.com/shigechika/mcp-stdio/commit/02fba4b8f49c487996348ba6f6a262414b69efe9))
* **relay:** no duplicate response on page-2+ pagination failure; cover recovery branches ([#118](https://github.com/shigechika/mcp-stdio/issues/118)) ([9a87bc1](https://github.com/shigechika/mcp-stdio/commit/9a87bc1997cfedf5e1cf70594a26208cee091489))
* **relay:** pagination ignores interleaved SSE messages; strip protocol header on re-init ([#126](https://github.com/shigechika/mcp-stdio/issues/126)) ([47edee7](https://github.com/shigechika/mcp-stdio/commit/47edee780076b00519fc03c7b6a5a4c7d3a20d11))
* **relay:** preserve negotiated protocol_version on an interrupted initialize; default empty SSE event type ([#178](https://github.com/shigechika/mcp-stdio/issues/178)) ([3c0ca50](https://github.com/shigechika/mcp-stdio/commit/3c0ca5071f74b89ba19d15e3b1f0141100fdea26))
* **relay:** preserve session on transient blip; resumable pagination; reconnect on non-200; empty-body error ([#127](https://github.com/shigechika/mcp-stdio/issues/127)) ([9c75cbd](https://github.com/shigechika/mcp-stdio/commit/9c75cbd8c15ccda10cf53b1357c60b9cc0f1af88))
* **relay:** re-capture protocol version on re-initialize; merge late fields; cover SSE gaps ([#123](https://github.com/shigechika/mcp-stdio/issues/123)) ([98ba4c6](https://github.com/shigechika/mcp-stdio/commit/98ba4c61aa77098050d9ab25567c4f2ab4a9c88f))
* **relay:** recover SSE reader on unexpected error; error on 202-to-request ([#149](https://github.com/shigechika/mcp-stdio/issues/149)) ([1a7136e](https://github.com/shigechika/mcp-stdio/commit/1a7136ee5fc629ddda9d703087790a2d6c7748ca))
* **relay:** retry all transient transport errors; guard cross-origin SSE endpoint ([#100](https://github.com/shigechika/mcp-stdio/issues/100)) ([5d79b8d](https://github.com/shigechika/mcp-stdio/commit/5d79b8dbb25253ffda351b555f022662c7d0b749))
* **relay:** scope cancel filter to pure responses; cover pagination recovery ([#199](https://github.com/shigechika/mcp-stdio/issues/199)) ([ea611d1](https://github.com/shigechika/mcp-stdio/commit/ea611d101198abc3fa921b3fb79d418a9f7338fa))
* **relay:** split inbound SSE on CR/LF/CRLF only to stop U+2028/U+2029/U+0085 corruption ([#87](https://github.com/shigechika/mcp-stdio/issues/87)) ([7f75767](https://github.com/shigechika/mcp-stdio/commit/7f757672530c8dee640bc2a6f6e74251303593c9))
* **relay:** strip a leading U+FEFF BOM in the SSE decoder (WHATWG) ([#134](https://github.com/shigechika/mcp-stdio/issues/134)) ([ef2322e](https://github.com/shigechika/mcp-stdio/commit/ef2322e5edef5833a2a0001e4071ec432aa396f4))
* **relay:** surface 429 Retry-After in error.data; single-parse hot path; cover notif recovery ([#142](https://github.com/shigechika/mcp-stdio/issues/142)) ([d486918](https://github.com/shigechika/mcp-stdio/commit/d48691816b57f0d621b831ded833b5686557bdf1))
* **relay:** uniform session reset, re-capture renegotiated version, lock-symmetric SSE POST ([#83](https://github.com/shigechika/mcp-stdio/issues/83)) ([52e167d](https://github.com/shigechika/mcp-stdio/commit/52e167d14f9b1fbea38714c1926e94bb7bd448d2))
* **relay:** validate server protocolVersion before injecting it as a header ([#219](https://github.com/shigechika/mcp-stdio/issues/219)) ([ea0e2f1](https://github.com/shigechika/mcp-stdio/commit/ea0e2f1e080507f0b882e4a9991c30edb3c700ba))
* **relay:** WHATWG-correct SSE parsing, at-most-once streaming retry, SSE header race ([#77](https://github.com/shigechika/mcp-stdio/issues/77)) ([70e8734](https://github.com/shigechika/mcp-stdio/commit/70e8734fd9c9b70bfdcbd1a0b31b8b112465a544))
* round-44 review — notification pagination, store resilience, fd leak ([#233](https://github.com/shigechika/mcp-stdio/issues/233)) ([c62dce6](https://github.com/shigechika/mcp-stdio/commit/c62dce6bec7bf89a6760ff103d5ee35286ab8ad4))
* **token_store:** add O_NONBLOCK to the lock-file open so a FIFO can't hang it ([#204](https://github.com/shigechika/mcp-stdio/issues/204)) ([049aff1](https://github.com/shigechika/mcp-stdio/commit/049aff12d880999b549efbce0f1fa93e31bceef4))
* **token_store:** advisory lock, migration hardening, dir mode, key normalization ([#80](https://github.com/shigechika/mcp-stdio/issues/80)) ([79fe6d0](https://github.com/shigechika/mcp-stdio/commit/79fe6d05df8da08744aa6e5113564c96c8ed79fe))
* **token_store:** create store-dir ancestors at 0o700 (no umask/chmod window) ([#218](https://github.com/shigechika/mcp-stdio/issues/218)) ([23959ee](https://github.com/shigechika/mcp-stdio/commit/23959ee5ff55ca91062636b0418e760ecb1659a0))
* **token_store:** don't delete legacy tokens when the XDG store is empty/unreadable ([#139](https://github.com/shigechika/mcp-stdio/issues/139)) ([08b8ee8](https://github.com/shigechika/mcp-stdio/commit/08b8ee8a640367b07cc8862f1f54d366dc56ea7f))
* **token_store:** fail soft when the store write fails in save/delete ([#165](https://github.com/shigechika/mcp-stdio/issues/165)) ([a5a0916](https://github.com/shigechika/mcp-stdio/commit/a5a0916c463a627cb95357f7dc5ec7592fd20622))
* **token_store:** fsync the parent directory after os.replace for crash-durability ([#102](https://github.com/shigechika/mcp-stdio/issues/102)) ([c31e090](https://github.com/shigechika/mcp-stdio/commit/c31e0903111748d16006429049acd3e1e3d174e8))
* **token_store:** give each write a unique temp-file name ([#129](https://github.com/shigechika/mcp-stdio/issues/129)) ([895bd04](https://github.com/shigechika/mcp-stdio/commit/895bd04d888207083102774ebd83de8b3e062767))
* **token_store:** guard legacy unlink in migration; isolate post-rename chmod ([#114](https://github.com/shigechika/mcp-stdio/issues/114)) ([ebe402b](https://github.com/shigechika/mcp-stdio/commit/ebe402b40620bad6e61544dcdb5b3c6e80412120))
* **token_store:** guard the migration copy-through write against load_token crash ([#147](https://github.com/shigechika/mcp-stdio/issues/147)) ([e57273a](https://github.com/shigechika/mcp-stdio/commit/e57273ac8a2fec5d6d2e5f53b10526ef2ff3c3ca))
* **token_store:** never clobber an unreadable store on save/delete ([#125](https://github.com/shigechika/mcp-stdio/issues/125)) ([0daccf1](https://github.com/shigechika/mcp-stdio/commit/0daccf1596faf3cb44faff7ccf98d75b6b0a798e))
* **token_store:** O_NOFOLLOW on credential writes; symlink-safe read chmod; docs ([#99](https://github.com/shigechika/mcp-stdio/issues/99)) ([40c4e49](https://github.com/shigechika/mcp-stdio/commit/40c4e493477e821a5d4dfcd69005d84f03131e7a))
* **token_store:** re-tighten a pre-existing lock file to 0o600 ([#160](https://github.com/shigechika/mcp-stdio/issues/160)) ([8ddeb9d](https://github.com/shigechika/mcp-stdio/commit/8ddeb9dea10752e3a52b725522ca974c5761d28d))
* **token_store:** reconcile empty XDG placeholder; harden legacy dir perms ([#150](https://github.com/shigechika/mcp-stdio/issues/150)) ([b72ec5d](https://github.com/shigechika/mcp-stdio/commit/b72ec5d5d6049d85526ccc0193f5c59894f13ce5))
* **token_store:** refuse to migrate a symlinked/non-regular legacy store ([#188](https://github.com/shigechika/mcp-stdio/issues/188)) ([d78bff5](https://github.com/shigechika/mcp-stdio/commit/d78bff500bc839d1a989a1e88de35c36863419f0))
* **token_store:** stop concurrent-migration clobber; harden _normalize_key ([#88](https://github.com/shigechika/mcp-stdio/issues/88)) ([c1a6160](https://github.com/shigechika/mcp-stdio/commit/c1a6160ef31364b88c320e461a2975c03659531e))
* **token_store:** tighten a pre-existing loose tokens.json mode on read ([#94](https://github.com/shigechika/mcp-stdio/issues/94)) ([60093ee](https://github.com/shigechika/mcp-stdio/commit/60093ee28d0fcc38e1b9815f51fb40ff169384b4))
* **token_store:** tighten newly-created parent dirs to 0o700 ([#196](https://github.com/shigechika/mcp-stdio/issues/196)) ([024f134](https://github.com/shigechika/mcp-stdio/commit/024f1343e9743830551cf2fa151b4835e5391c33))
* **token_store:** treat an empty-dict XDG store as no-data during legacy migration ([#224](https://github.com/shigechika/mcp-stdio/issues/224)) ([980f722](https://github.com/shigechika/mcp-stdio/commit/980f722a06e55e127eab8fae48503686164f3128))
* **token_store:** validate iss_parameter_supported on load; document temp orphans ([#169](https://github.com/shigechika/mcp-stdio/issues/169)) ([188fde0](https://github.com/shigechika/mcp-stdio/commit/188fde099c061f98e2941a5098a9bc875bea2546))
* **token_store:** validate string fields on load; O_NOFOLLOW legacy read; O_EXCL temp write ([#136](https://github.com/shigechika/mcp-stdio/issues/136)) ([42c80b2](https://github.com/shigechika/mcp-stdio/commit/42c80b2429ea3f1d1864b4fdbdf29785684967a3))
* **token_store:** validate value types on load; O_NOFOLLOW read; document migration lock gap ([#120](https://github.com/shigechika/mcp-stdio/issues/120)) ([00506a5](https://github.com/shigechika/mcp-stdio/commit/00506a54504c9dfa8e51f0b867dd05caa14521e3))
* **token_store:** warn on a valid-but-non-object JSON store, matching corrupt-JSON ([#228](https://github.com/shigechika/mcp-stdio/issues/228)) ([3f2a1e7](https://github.com/shigechika/mcp-stdio/commit/3f2a1e7cbcadb7ac52c45f1096509b190bc0749f))
* **token_store:** warn on userinfo key collision; sort output; ENOENT is absent ([#153](https://github.com/shigechika/mcp-stdio/issues/153)) ([d17f49a](https://github.com/shigechika/mcp-stdio/commit/d17f49a23d5f02a02db973498559e8045417d171))
* **token_store:** warn when a corrupt store is replaced on save ([#221](https://github.com/shigechika/mcp-stdio/issues/221)) ([2f6f248](https://github.com/shigechika/mcp-stdio/commit/2f6f2485e2f2072141ea7ac79505db72f0659395))
* **token_store:** widen legacy-migration copy-through soft-fail to non-OSError ([#194](https://github.com/shigechika/mcp-stdio/issues/194)) ([9c31249](https://github.com/shigechika/mcp-stdio/commit/9c3124969d00d065d7d535dda841cf7c120ec011))
* **token_store:** widen save soft-fail to non-OSError; warn on lock symlink ([#183](https://github.com/shigechika/mcp-stdio/issues/183)) ([90b831d](https://github.com/shigechika/mcp-stdio/commit/90b831d3d494214f8cdac241fd7eab5daee02ce1))
* **token_store:** write standards-compliant JSON (allow_nan=False) ([#203](https://github.com/shigechika/mcp-stdio/issues/203)) ([de96e0d](https://github.com/shigechika/mcp-stdio/commit/de96e0d779e06cfa4d1c456621d4930ed72b44e8))


### Performance

* **cli:** skip building relay recovery callbacks on the --check probe ([#137](https://github.com/shigechika/mcp-stdio/issues/137)) ([ec71095](https://github.com/shigechika/mcp-stdio/commit/ec71095a7370423b574bfff6fd472bb7a4725473))


### Refactoring

* **relay:** drop dead _has_id; cover nextCursor/_same_origin/HTTP-date edges ([#205](https://github.com/shigechika/mcp-stdio/issues/205)) ([e405ba1](https://github.com/shigechika/mcp-stdio/commit/e405ba1378104a2f85a54e824e2fb03ef97a58ab))

## [0.14.0](https://github.com/shigechika/mcp-stdio/compare/v0.13.1...v0.14.0) (2026-05-28)


### Features

* **relay:** escape raw U+2028/U+2029 in stdout to prevent client mis-framing ([#73](https://github.com/shigechika/mcp-stdio/issues/73)) ([91840d1](https://github.com/shigechika/mcp-stdio/commit/91840d1f00bd302e756c5bbd4b0affcc4aedf450))
* **relay:** inject MCP-Protocol-Version header on subsequent requests ([#70](https://github.com/shigechika/mcp-stdio/issues/70)) ([b4eb111](https://github.com/shigechika/mcp-stdio/commit/b4eb11127b63596e1459b73ec0d1c7ce6b1c2daf))
* **relay:** normalize tools/call arguments:null to {} for strict servers ([#75](https://github.com/shigechika/mcp-stdio/issues/75)) ([899a707](https://github.com/shigechika/mcp-stdio/commit/899a70731fa2a1fe0d3610c6363778ae234822c7))

## [0.13.1](https://github.com/shigechika/mcp-stdio/compare/v0.13.0...v0.13.1) (2026-05-28)


### Bug Fixes

* **relay:** serialize stdout writes to prevent NDJSON line interleaving ([#67](https://github.com/shigechika/mcp-stdio/issues/67)) ([ce91459](https://github.com/shigechika/mcp-stdio/commit/ce914593152efc4d0a64d0fd05105f637b6a6a86))

## [0.13.0](https://github.com/shigechika/mcp-stdio/compare/v0.12.0...v0.13.0) (2026-05-07)


### Features

* **oauth:** add --no-resource-indicator for AS that reject RFC 8707 resource parameter ([#65](https://github.com/shigechika/mcp-stdio/issues/65)) ([7a07deb](https://github.com/shigechika/mcp-stdio/commit/7a07deb9e53d0167c3ff0f62cdcfbf1dc79c675a))

## [0.12.0](https://github.com/shigechika/mcp-stdio/compare/v0.11.0...v0.12.0) (2026-05-07)


### Features

* **oauth:** select token_endpoint_auth_method from AS metadata (RFC 8414) ([#62](https://github.com/shigechika/mcp-stdio/issues/62)) ([9e6feff](https://github.com/shigechika/mcp-stdio/commit/9e6feff050db056e039716f3bbc2ea076833dba9))


### Bug Fixes

* **test:** add missing path-aware PRM mock in TestDiscoverMetadataAuthMethods ([df06108](https://github.com/shigechika/mcp-stdio/commit/df06108a21beb468d6e38c74b24cbfc2c3b10c4b))

## [0.11.0](https://github.com/shigechika/mcp-stdio/compare/v0.10.1...v0.11.0) (2026-05-07)


### Features

* **oauth:** make proactive token refresh window configurable (--oauth-refresh-leeway) ([#57](https://github.com/shigechika/mcp-stdio/issues/57)) ([10737ca](https://github.com/shigechika/mcp-stdio/commit/10737ca46f2572f352eb3f0d7ab5f3ab47c35fdd))

## [0.10.1](https://github.com/shigechika/mcp-stdio/compare/v0.10.0...v0.10.1) (2026-05-02)


### Bug Fixes

* **oauth:** support path-scoped issuers in RFC 8414 discovery (Keycloak, Cognito) ([#54](https://github.com/shigechika/mcp-stdio/issues/54)) ([1916ec0](https://github.com/shigechika/mcp-stdio/commit/1916ec040cfc90fc1bcc20011f36344f0ab37a68))

## [0.10.0](https://github.com/shigechika/mcp-stdio/compare/v0.9.0...v0.10.0) (2026-05-02)


### Features

* **oauth:** add Device Authorization Grant (RFC 8628) via --oauth-device ([#51](https://github.com/shigechika/mcp-stdio/issues/51)) ([4df5021](https://github.com/shigechika/mcp-stdio/commit/4df5021d9c9a1a731031233ab2dde9c8ed6e60f5))

## [0.9.0](https://github.com/shigechika/mcp-stdio/compare/v0.8.0...v0.9.0) (2026-05-01)


### Features

* **oauth:** use WWW-Authenticate resource_metadata hint for PRM discovery (RFC 9728 §5.1) ([#49](https://github.com/shigechika/mcp-stdio/issues/49)) ([05239be](https://github.com/shigechika/mcp-stdio/commit/05239be9e977d24768e7310f60fed9a21b7576d7))

## [0.8.0](https://github.com/shigechika/mcp-stdio/compare/v0.7.0...v0.8.0) (2026-04-20)


### Features

* honour Retry-After on HTTP 429 (typescript-sdk[#1892](https://github.com/modelcontextprotocol/typescript-sdk/issues/1892)) ([#45](https://github.com/shigechika/mcp-stdio/issues/45)) ([fb5ac14](https://github.com/shigechika/mcp-stdio/commit/fb5ac148ecde6cd0252de956db934241a1941b99))

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
