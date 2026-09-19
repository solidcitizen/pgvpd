# pgvpd Adversarial Test Plan

pgvpd sits in the trust path of every tenant of every application that uses
it. Its correctness proofs are owned by this project; consumers (Nexusplus
first) verify each release candidate independently with a hostile round
before it promotes. This document maps the invariants a verifier will attack
to the tests that defend them, names the gaps, and states the release gate.

Issue register: GitHub issues on `solidcitizen/pgvpd`, one per defect, with
root cause and status. Chaos scenarios live in `tests/run.sh` against a real
Postgres in Docker. Every fix carries a test that fails without it.

## Release gate

A version is SHIP only when all of the following hold:

1. `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check` are green.
2. `./tests/run.sh` is green on the release binary
   (`PGVPD_BIN=./target/release/pgvpd ./tests/run.sh`).
3. Every regression test added for the release is shown red on the previous
   version (`PGVPD_BIN=<old binary> ./tests/run.sh`) or on a named mutant,
   with the command and output recorded in the issue.
4. The changelog names the defect, the root cause, and the tests.
5. The consumer's hostile round finds nothing that can corrupt or leak.

## Invariants → tests

Status legend: **have** = covered today, **partial** = covered for some
inputs, **gap** = not covered. Test ids refer to `tests/run.sh`; `7P.4` and
the harnesses under `tests/drizzle/` run node-postgres against the proxy.

### 1. Context correctness

Every query on a handed-out session runs under exactly the context derived
from that client's username: never a prior holder's, never none.

| Coverage | Tests | Mutant that must turn it red |
|---|---|---|
| have — single-shot per mode | 1.1, 1.2, 1.5, 2.1, 7.x, 7P.1–7P.3, 8.1–8.3 | skip `SET` on a reused pooled connection |
| have — randomized concurrent churn, per-query tenant assertion | 7P.4 (`pool-desync.mjs poison`), every query asserts `current_setting('app.current_tenant_id')` and row count | inject context only on `pool_creates`, not on reuse |
| gap — long run, more tenants, resolver mode | add 7P.5: `pool-desync.mjs clean` with `TENANT_POOLS=8 ROUNDS=1000`; add resolver-mode variant (Suite 3 conf) | resolver cache keyed on the wrong input |

### 2. Hand-off integrity

A session reaches idle only at a message boundary with no outstanding
backend messages; no fresh holder ever sees a shifted or empty response.
Fix: 1.0.3 (issue #11) — the pooled pipe counts `Query`/`Sync`/`FunctionCall`
against `ReadyForQuery`; checkin drains what is outstanding before reset;
anything unaccountable is discarded.

The client-visible poison had (at least) three manifestations, all of which
`tests/drizzle/pool-desync.mjs` (7P.4) must catch: (1) a stray
`CommandComplete` raised as a pg client `'error'` event; (2) a silent shifted
or empty result with no error at all; (3) a stray `RowDescription` arriving on
a client whose `activeQuery` is `null`, which makes pg's
`Client._handleRowDescription` **throw uncaught** rather than emit `'error'`,
so an app-side checkout `'error'` guard never sees it. A verifier confirmed
manifestation 3 on 1.0.2. The harness traps it with a process-level
`uncaughtException`/`unhandledRejection` handler that records a `crash` and
exits non-zero, so a RowDescription-shift is asserted rather than aborting the
run opaquely; all three are gone on 1.0.3.

| Scenario | Coverage | Tests | Mutant |
|---|---|---|---|
| abrupt disconnect mid simple query | have | 2.5, 2.6, 7P.4 | remove the drain step (1.0.2 behaviour) |
| mid transaction (`BEGIN` + query, drop) | partial (drain + `ROLLBACK`) | add 2.7: drop inside `BEGIN`; next holder sees `txid_current()` fresh and no open transaction | skip `ROLLBACK` |
| mid `COPY FROM STDIN` | gap — expected: server waits for CopyData, drain times out, slot discarded | add chaos test: `COPY ... FROM STDIN` then kill; assert `pgvpd_pool_discards_total` +1 and next holder clean | shorten nothing; test asserts discard, not drain |
| extended protocol without `Sync` (Parse/Bind/Execute, drop) | gap — expected: no `ReadyForQuery` owed; stray `CommandComplete` skipped by reset drain; on error `ErrorResponse` discards | add `tests/drizzle/raw-frames.mjs`: hand-built frames, with and without a Parse error | count `Sync` twice / treat `CommandComplete` as boundary |
| unparseable client frame | have (code path) / gap (test) | add raw-frames case: length < 4 → `framing_lost` → discard | forward without flagging |
| upstream error or EOF mid drain | have (code path) / gap (test) | add: `pg_terminate_backend()` of the abandoned session during drain → discard | treat EOF as clean |
| drain timeout | gap | covered by the COPY case above | raise timeout to infinity |
| unit | have | `BackendFrameTracker` tests (split headers, split bodies, 'Z' inside a body, malformed length) | — |

**Dead end — do not retry.** A single-client harness cannot force the poison
deterministically. With `pool_size = 1` and one client that sends
`SELECT pg_sleep(...)` then drops its socket, the old (1.0.2) checkin reads
the stray `DISCARD ALL` reply into its own scratch buffer and drops it when
checkin returns, so the socket ends up clean and the broken build looks
correct. The defect is concurrency-dependent: it takes interleaved reads
across the shared pool to strand a response on the wire, which is why 7P.4
uses a concurrent storm. The deterministic red side must therefore come from
either the mutant (revert the drain block in `Pool::checkin`) or the planned
`raw-frames.mjs` with a proxy-side hook that hands back a slot with a known
number of responses still outstanding — not from a client-only script.

### 3. Reset completeness

A new holder never sees the previous holder's state. `ROLLBACK` then
`DISCARD ALL` (which itself runs `SET SESSION AUTHORIZATION DEFAULT`,
`RESET ALL`, `DEALLOCATE ALL`, `CLOSE ALL`, `UNLISTEN *`,
`SELECT pg_advisory_unlock_all()`, `DISCARD PLANS/TEMP/SEQUENCES`).

| Coverage | Tests | Mutant |
|---|---|---|
| gap — nothing asserts state is gone | add Suite 2R with `pool_size = 1` so reuse is forced: holder A creates a temp table, `PREPARE`s, sets `search_path`, takes `pg_advisory_lock(42)`, `LISTEN`s, opens a `WITH HOLD` cursor, `SET ROLE`s; holder B asserts each is gone and `pg_try_advisory_lock(42)` succeeds | drop `DISCARD ALL` from checkin; drop `DISCARD ALL` from checkout |

Advisory locks matter to Nexusplus (per-list drain ownership); the test must
prove `pg_advisory_unlock_all` ran, not assume it.

### 4. Fail closed

Any doubt closes the upstream, decrements accounting, logs with `conn_id`,
increments a metric. Never a reuse on doubt.

| Coverage | Tests | Mutant |
|---|---|---|
| have (code paths in `Pool::checkin`, `PoolLease::drop`) | partial: 2.6 checks the drain log line | add assertions to every chaos test above: `pgvpd_pool_discards_total` delta and `pgvpd_pool_connections_total` gauge after the event | return the connection to idle on drain failure |

### 5. Pool accounting

No slot leaks on any error path; totals converge after upstream restart;
exhaustion returns a clean error within bounded time; no busy loops.

| Scenario | Coverage | Tests | Mutant |
|---|---|---|---|
| leak after checkout on error (fixed 1.0.3 via `PoolLease`) | gap (test) | add 2.8: `set_role = does_not_exist` conf → every connection fails after checkout; assert gauge returns to 0 and a later good checkout succeeds | disarm the lease early |
| upstream restart | **fixed 1.0.6** (#15) — Suite 13 (`tests/drizzle/upstream-restart.mjs`) warms the pool, kills pgvpd's upstream backends via `pg_terminate_backend`, and asserts reused checkouts recover on a fresh connection. Checkout discards a connection that fails its reset and retries (bounded). | remove the discard-and-retry loop |
| exhaustion | partial (5.3 is per-tenant, not pool) | add 2.9: `pool_size = 1`, hold one, second client gets `53300` within `pool_checkout_timeout` + 1 s | remove the deadline |
| busy loop — full pool | known: checkout polls every 50 ms while full | improvement: `tokio::sync::Notify` on checkin (issue to open) | — |
| busy loop — EOF spin (issue #24) | **finding** — see 5a | new suite (5a) | — |

#### 5a. EOF-blindness in handshake-phase read loops (issue #24 + family)

`read_buf()` returns `Ok(0)` on EOF; it is not an error. The steady-state pipe
(`pipe_pooled`, `drain_outstanding`) treats `Ok(0)` as "peer closed" and stops.
The handshake / reset / auth / resolve / checkin-reset loops instead use
`.await?` (error-only) or `.is_err()` and re-loop on `Ok(0)`, busy-spinning a
core until a timeout fires. Nine confirmed instances: connection.rs 362, 557,
575, 585, 700, 761, 869; pool.rs 405 (bounded by handshake_timeout, ~30 s) and
357 (`send_and_drain`, bounded by reset_timeout, 5 s); `auth.rs`/`resolver.rs`
read loops share the pattern and need auditing. Root cause and severity in
`docs/architecture-review-lifecycle.md` (Gap 1).

| Scenario | Coverage | Tests | Mutant |
|---|---|---|---|
| client connects then FINs mid-startup | gap | add 5a.1 `tests/eof-storm.sh`: open+immediately close N sockets to the proxy; assert per-event CPU/time bounded and no core-spin (measure wall-time to task exit ≪ handshake_timeout after fix) | current code: task spins to handshake_timeout |
| upstream FINs mid-handshake (reset/inject) | gap | add 5a.2: black-hole→FIN upstream during DISCARD ALL; assert client gets a prompt error, not a 30 s hang | treat `Ok(0)` as "loop again" |
| upstream FINs during checkin reset | gap | add 5a.3: kill upstream after client Terminate; assert checkin discards within ≪ 5 s, not a 5 s spin | — |

Fix shape: one shared `read_or_eof` helper mapping `Ok(0)` to a distinct
"peer closed during handshake" error; route every loop above through it.

#### 5b. `connections_active` panic-safety (finding, unfiled)

`connections_active` is inc'd/dec'd as bare statements around the `.await` on
`handle_connection` (proxy.rs 212/233, 257/271), not via RAII. A panic anywhere
in the connection path is caught by `tokio::spawn` and skips the dec, leaking the
gauge permanently — the exact mechanism by which #21 read as a "wedge" to the
consumer's monitoring. The #21 fix removed one panic source; the structural
vulnerability remains and the gauge is load-bearing for wedge detection.

| Scenario | Coverage | Tests | Mutant |
|---|---|---|---|
| panic in a connection task | gap | add 5b.1: a mutant that `panic!`s after inc; assert `connections_active` still returns to 0 (RED until a `ConnectionGuard` drops the count) | inc/dec as statements (current) |

Fix shape: a `ConnectionGuard` that inc's on construction, dec's on `Drop`
(mirrors the working `TenantGuard`).

### 6. Cancel semantics

**Fixed 1.0.6 (#12, #14).** Each client is handed pgvpd's own minted
`BackendKeyData`; a registry maps that key to the client's current upstream
connection, so a `CancelRequest` is routed only to the issuing client's query.
A client that abandons an in-flight query has it cancelled upstream at checkin
(#14). Previously CancelRequest was dropped and every client shared the bucket's
cached key, so a forwarded cancel could have hit another tenant.

| Coverage | Tests | Mutant |
|---|---|---|
| have — routing + isolation | Suite 14 (`tests/drizzle/cancel-isolation.mjs`): two tenants, cancel one → only its query aborts (57014), the other completes. Unit tests in `cancel.rs` and `protocol.rs` (key round-trips, unknown key = no-op). | forward with the cached key / drop the registry |
| have — orphan cancel | Suite 15 (`tests/drizzle/orphan-cancel.mjs`): client drops mid-query → the orphan is cancelled upstream, not left active. | skip the checkin cancel |
| gap — forged key refused explicitly | isolation already implies a random cancel key disturbs nothing; add an explicit case | — |

### 7. Trust boundary

Anyone with the pool password can claim any tenant; the application is the
trusted party. The boundary must therefore be the network.

| Item | Status |
|---|---|
| proxy listener defaults to `127.0.0.1` (`listen_host`) | have |
| admin API binds `0.0.0.0:<admin_port>`, unauthenticated | **fixed 1.0.6** (#13) — now binds `127.0.0.1` by default; `admin_host`/`PGVPD_ADMIN_HOST` opts into wider exposure. Suite 12 (`tests/admin-bind.mjs`) asserts default is loopback-only and opt-in works. A bearer token is still open. |
| threat model document | have — `docs/threat-model.md` (trusted app, pool password scope, what the username encodes, what the admin port reveals, out-of-scope attackers) |

### 8. Observability

| Item | Status |
|---|---|
| `pgvpd_pool_drains_total`, `pgvpd_pool_discards_total`, checkouts/reuses/creates/checkins/timeouts, per-bucket total/idle | have (1.0.3 adds drains) |
| checkout latency histogram | gap — add `pgvpd_pool_checkout_seconds` buckets |
| structured logs with `conn_id` and bucket on every pool event | partial — drain/discard lines carry `conn_id`; add bucket key |
| version | have (`--version`); add to `/status` JSON and a `pgvpd_build_info` gauge |

### 9. Compatibility matrix

| Item | Status |
|---|---|
| Postgres 17 | have (CI service) |
| Postgres 15, 16 | gap — CI matrix on the integration job |
| node-pg simple and extended protocol | have via drizzle (extended) and psql (simple); 7P.4 uses `pool.query` (extended) |
| drizzle batching/transactions | partial (7.4); add pool-mode transaction test |
| SSL to upstream | gap in CI — add a self-signed cert Postgres service and `upstream_tls = true` conf |
| `COPY`, large results | gap — add `COPY TO STDOUT` of `generate_series(1, 2e6)` through the pool; assert byte-exact against direct |
| explicit out-of-scope | document: `LISTEN/NOTIFY` in pool mode (reset unlistens; notifications not delivered across hand-offs), replication protocol. `CancelRequest` is supported as of 1.0.6 (#12). |

### 10. Chaos

| Scenario | Status |
|---|---|
| upstream Postgres restart | gap (see 5) |
| half-open sockets | gap — Linux CI only: drop packets with `iptables` to a held client; assert the slot is reclaimed by `tenant_query_timeout` and discarded |
| slow client while the server streams | gap — client reads 1 byte/s from a large result; assert other tenants unaffected and no unbounded buffering |
| slow client dribbling a large request (D4) | gap — client announces a large frontend message length and dribbles bytes; the sliding idle deadline (connection.rs:273) resets on every read, so `tenant_query_timeout` never fires and the slot pins with per-conn buffer growth to the ~2 GB protocol max; fix: cap in-flight message size and/or use an absolute per-request deadline |
| no max connection lifetime (D3) | gap — `checkin` resets `created_at` to now (pool.rs:305), so pooled upstreams age out only by idle time, never total age; fix: preserve real `created_at`, add optional `pool_max_lifetime` |
| `SIGTERM` of pgvpd mid-query | gap — clients get a clean connection error; restart shows zero poisoned slots (trivially true: the pool dies with the process) |
| orphan handling | consumer side (Nexusplus `startPgvpd()` kills orphans on its port) |

## Order of work

Shipped: 1.0.3 (#11), 1.0.4 (#20), 1.0.5 (#21). The 1.0.6 sequencing below is
driven by `docs/architecture-review-lifecycle.md`, which maps the open register
to one class (abnormal transitions handled in the pipe, not the handshake).

1. **Gap 1 / #24** — shared `read_or_eof` helper; retires #24 and hardens the
   eight sibling loops (5a). Lowest risk, highest breadth. First.
2. **D1 / #12 / #14** — per-client cancel-key machinery. The only
   correctness/isolation-class item: today all clients on a bucket share the
   cached `BackendKeyData`, so a naive cancel would hit the wrong tenant. #14
   (cancel the orphaned query instead of waiting out the drain) rides this.
3. **Gap 2 / #15** — discard-and-retry on a dead-upstream checkout, so an
   upstream bounce victimizes zero clients instead of one-per-stale-conn.
4. **Gap 3 (5b)** — `ConnectionGuard` for `connections_active` (panic-safe gauge).
5. **D2 / #13** — admin bind to `listen_host` by default, add `admin_host`.
6. **Tail** — D3 max-lifetime, D4 absolute request deadline, #16 cleanup,
   CI matrix (PG 15/16/17, upstream TLS), large results, upstream-restart chaos.

Prior backlog (still valid, folds into the above): Suite 2R reset completeness,
2.7 mid-transaction, 2.8 lease release, 2.9 exhaustion, `raw-frames.mjs`
(extended protocol, COPY, malformed frames), discard/gauge assertions on every
chaos test, checkout latency histogram, version in `/status`.
