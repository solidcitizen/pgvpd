# Changelog

All notable changes to pgvpd are documented here.

## [Unreleased]

### Fixed
- Admin API bound `0.0.0.0` unconditionally, exposing the unauthenticated
  `/status` and `/metrics` endpoints — which reveal pool topology (every
  `database`, `role`, and bucket count) — on every interface. On a multi-homed
  host this leaked the tenant/role namespace to anything that could route to the
  port. The admin API now binds `127.0.0.1` by default; set `admin_host`
  (config), `--admin-host` (CLI), or `PGVPD_ADMIN_HOST` (env) to expose it
  deliberately. Pre-existing since the admin API (0.5). (#13)
- Handshake-phase read loops ignored EOF. `read_buf` returns `Ok(0)` when the
  peer closes its socket; that is not an error, but the startup, upstream-auth
  (cleartext/MD5/SCRAM), post-auth, pooled reset (`DISCARD ALL`), context
  injection, pool-connection-create, and checkin-reset loops all treated `Ok(0)`
  as "no data yet" and looped again. A client (or upstream) that closed mid-
  handshake therefore returned `Ok(0)` immediately and forever, spinning the
  connection task at ~100% CPU until the handshake timeout (30s) or reset timeout
  (5s) fired. A connect-and-close storm pinned one spinning core per event and
  logged a spurious per-connection "handshake timeout". Measured: 15 events with
  a 1s handshake timeout burned ~8 CPU-seconds on 1.0.5, ~0 after the fix. Every
  such loop now reads through a single `stream::read_or_eof` helper that maps
  `Ok(0)` to a prompt `UnexpectedEof`, mirroring the steady-state pipe (which
  already handled EOF since #11). Availability/CPU class, bounded by the loopback
  trust model. Pre-existing (all versions). (#24)

## [1.0.5] — 2026-09-18

### Fixed
- Logging was on the connection data path: pgvpd logged to stdout via
  `tracing_subscriber::fmt`, and a per-connection `info!` wrote directly on the
  connection task. When a parent process closed BOTH pgvpd's stdout and stderr
  while pgvpd kept running (e.g. a launcher that exited right after spawn, or a
  supervisor that stopped draining), the stdout write failed, tracing's error
  fallback `eprintln!`'d to the now-closed stderr, and `eprintln!` panicked on
  the write error — killing the per-connection task before it decremented
  `connections_active` or completed checkout. Every later connection was then
  accepted and dropped (`Connection terminated unexpectedly`),
  `connections_active` climbed and never fell, and checkouts froze: a permanent
  wedge (TCP still accepting, process alive) cleared only by restart. Logging
  now goes through a non-blocking writer (`tracing_appender::non_blocking`, a
  bounded channel drained by a worker thread, dropping lines when full), so a
  slow or closed consumer can neither block nor panic a connection task. The
  startup banner and the fatal-error line use non-panicking writes.
  Pre-existing (1.0.0–1.0.4). (#21)

## [1.0.4] — 2026-09-14

### Fixed
- Pool mode: a checkout that reserved a slot (`bucket.total += 1`) and was then
  cancelled — the per-connection handshake timeout dropping the future while
  `create_connection` was still awaiting a slow/unresponsive upstream — never
  released that slot. Each cancelled checkout leaked one phantom slot; enough
  leaks pinned `total` at `pool_size` with zero real connections, permanently
  wedging the bucket (every later checkout failed `pool checkout timeout` until
  restart). The reserved slot is now held by an RAII guard
  (`SlotReservation`) that releases it on every exit — error or cancellation —
  and is disarmed only once the connection exists. Pre-existing since pooling
  (0.3); present in 1.0.0–1.0.3. (#20)

## [1.0.3] — 2026-09-13

### Fixed
- Pool mode: a client that disconnected while a query was still in flight left
  its unread response on the shared upstream connection. The checkin reset
  consumed the wrong `ReadyForQuery`, so the next holder of that connection
  received a stale `CommandComplete` (node-postgres: "Received unexpected
  commandComplete message from backend") or had its first query resolved with
  an empty, shifted result and no error. The pooled pipe now counts request
  sync points (`Query`, `Sync`, `FunctionCall`) against `ReadyForQuery`
  received, and checkin drains anything outstanding before `ROLLBACK` /
  `DISCARD ALL`. A connection whose protocol state cannot be verified — drain
  timeout, EOF, framing mismatch — is closed instead of reused. (#11)
- Pool mode: any error or handshake timeout after checkout (upstream gone,
  client gone, injection failure) dropped the upstream connection without
  releasing its slot, so a bucket's `total` drifted above the connections that
  existed until every checkout timed out. Checked-out slots are now held by a
  lease that is released on every exit path.
- Pool mode: bytes upstream sent after the injection's `ReadyForQuery`
  (asynchronous notices) were silently dropped instead of forwarded.

### Added
- `pgvpd_pool_drains_total` metric and an info-level log line
  (`pool: client left with responses outstanding — draining before reset`)
  so operators can see how often clients abandon queries in flight.
- Integration tests 2.5/2.6 (psql sessions killed mid-query) and 7P.4
  (`tests/drizzle/pool-desync.mjs`: node-postgres churn with mid-query socket
  drops, asserting no protocol error and no shifted or empty result); unit
  tests for the backend frame tracker.

## [1.0.2] — 2026-03-03

Commit `0ce3be6`. This version shipped as the running binary on the NexusPlus
production host and is the baseline against which the #11 fix was verified
(red on 1.0.2, green on 1.0.3). It was not tagged or published at the time;
the git tag `baseline/1.0.2` marks the commit for that red-then-green record.

### Changed
- Allow empty context segments in multi-variable usernames: an omitted
  dimension (e.g. `app_user.val_a:` with an empty second segment) is injected
  as `SET var = ''`, which is fail-closed for RLS, instead of a fatal auth
  error. (#10)

## [1.0.0] — 2026-02-26

### Released
- First stable release
- Published to crates.io and as prebuilt binaries (Linux x86_64/aarch64, macOS x86_64/aarch64)
- 89 unit tests, 33 integration tests, CI on every push

## [0.9.0] — 2026-02-26

### Added
- Unit tests for `protocol.rs` (28 tests: startup parsing, backend message framing, SQL escaping)
- Unit tests for `config.rs` (31 tests: file parsing, validation, env var overrides)
- Unit tests for `auth.rs` (19 tests: MD5 hash, SCRAM parsing, key derivation)
- Connection throughput benchmark (`benches/throughput.rs`)

### Changed
- Unit test count: 17 → 89
- README: updated test counts, added install-from-release instructions
- Fixed all pre-existing clippy warnings across the codebase

## [0.8.0] — 2026-02-25

### Added
- GitHub Actions CI (cargo check, test, clippy, fmt, integration tests)
- GitHub Actions release workflow (cross-compiled binaries, crates.io publish)
- Dockerfile (multi-stage build)
- LICENSE file (MIT)
- This changelog

### Changed
- Cargo.toml: added crates.io metadata (repository, homepage, keywords, categories, readme)
- PLAN.md: replaced vague v1.0 milestone with concrete v0.8/v0.9 plan

## [0.7.0] — 2025-06-01

### Added
- SQL helper functions: `pgvpd_context()`, `pgvpd_context_array()`, `pgvpd_context_uuid_array()`, `pgvpd_context_contains()`, `pgvpd_context_text_contains()`
- `pgvpd_protect_acl()` for multi-path RLS policies (ownership + ACL grants + team membership + org roles)
- `sql/helpers.sql` installable script
- 10 new integration tests for SQL helpers

## [0.6.0] — 2025-05-01

### Added
- Tenant allow/deny lists (`tenant_allow`, `tenant_deny`)
- Per-tenant connection limits (`tenant_max_connections`)
- Per-tenant rate limiting (`tenant_rate_limit`) — fixed-window 1-second rate limiter
- Query/idle timeout (`tenant_query_timeout`)
- `TenantRegistry` — shared per-tenant state with lazy creation
- Metrics: `pgvpd_tenant_rejected_total{reason=deny|limit|rate}`, `pgvpd_tenant_timeouts_total`
- Configurable `set_role` target (override SET ROLE username)
- 5 integration tests for tenant isolation

## [0.5.0] — 2025-04-01

### Added
- Admin HTTP API on configurable `admin_port` (axum)
  - `GET /health` — 200 OK for load balancer health checks
  - `GET /metrics` — Prometheus exposition format
  - `GET /status` — JSON pool and resolver state
- Shared metrics (`Arc<Metrics>`) with `AtomicU64` counters
- Connection, pool, and resolver metrics
- 4 integration tests for admin API

## [0.4.0] — 2025-03-01

### Added
- Context resolver engine: `[[resolver]]` config blocks — SQL queries that run post-auth to derive session variables from database state
- Dependency ordering: resolvers chain via bind parameters
- Context caching with configurable TTL
- Fail-closed semantics: resolver error → connection terminated
- Resolver-only mode: all context derived from database, not username
- 13 end-to-end integration tests (passthrough, pool, resolver)

## [0.3.0] — 2025-02-01

### Added
- Session connection pooling (`pool_mode = session`)
- Pgvpd-side client authentication (cleartext)
- Upstream authentication (cleartext, MD5, SCRAM-SHA-256)
- Pool checkout/checkin with `DISCARD ALL` reset
- Idle connection reaper
- Superuser bypass (never pooled)

## [0.2.0] — 2025-01-15

### Added
- TLS termination (client → pgvpd)
- TLS origination (pgvpd → upstream Postgres)
- Handshake timeout enforcement

## [0.1.0] — 2025-01-01

### Added
- Initial release: TCP proxy with tenant extraction from username
- Auth relay (passthrough)
- Context injection (`SET` commands after auth)
- Transparent bidirectional pipe (`tokio::io::copy_bidirectional`)
- Single static binary, zero runtime dependencies
