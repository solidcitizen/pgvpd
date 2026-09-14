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
| upstream restart | gap | add chaos: `docker compose restart postgres` mid-run; assert checkouts recover and gauge equals live connections | skip `decrement_total` on upstream EOF |
| exhaustion | partial (5.3 is per-tenant, not pool) | add 2.9: `pool_size = 1`, hold one, second client gets `53300` within `pool_checkout_timeout` + 1 s | remove the deadline |
| busy loop | known: checkout polls every 50 ms while full | improvement: `tokio::sync::Notify` on checkin (issue to open) | — |

### 6. Cancel semantics

Issue #12. Today `CancelRequest` is closed unforwarded and every client gets
the bucket's cached `BackendKeyData`, so cancel is a no-op — safe, but wrong.

| Coverage | Tests | Mutant |
|---|---|---|
| gap | after #12: cancel from holder A must cancel A's backend only; a forged key must be refused; cancel of an idle slot is a no-op | forward with the cached key |

### 7. Trust boundary

Anyone with the pool password can claim any tenant; the application is the
trusted party. The boundary must therefore be the network.

| Item | Status |
|---|---|
| proxy listener defaults to `127.0.0.1` (`listen_host`) | have |
| admin API binds `0.0.0.0:<admin_port>`, unauthenticated | **finding** — issue #13; fix: bind to `listen_host` by default, add `admin_host` for deliberate exposure; consider a bearer token |
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
| explicit out-of-scope | document: `LISTEN/NOTIFY` in pool mode (reset unlistens; notifications not delivered across hand-offs), replication protocol, `CancelRequest` until #12 |

### 10. Chaos

| Scenario | Status |
|---|---|
| upstream Postgres restart | gap (see 5) |
| half-open sockets | gap — Linux CI only: drop packets with `iptables` to a held client; assert the slot is reclaimed by `tenant_query_timeout` and discarded |
| slow client while the server streams | gap — client reads 1 byte/s from a large result; assert other tenants unaffected and no unbounded buffering |
| `SIGTERM` of pgvpd mid-query | gap — clients get a clean connection error; restart shows zero poisoned slots (trivially true: the pool dies with the process) |
| orphan handling | consumer side (Nexusplus `startPgvpd()` kills orphans on its port) |

## Order of work

1. 1.0.3 — issue #11 fix with 2.5, 2.6, 7P.4 and tracker unit tests (this branch).
2. Suite 2R reset completeness, 2.7 mid-transaction, 2.8 lease release, 2.9 exhaustion, `raw-frames.mjs` (extended protocol, COPY, malformed frames), discard/gauge assertions on every chaos test.
3. #13 admin bind, `docs/threat-model.md`, checkout latency histogram, version in `/status`.
4. #12 cancel semantics.
5. CI matrix (PG 15/16/17, upstream TLS), large results, upstream restart chaos.
