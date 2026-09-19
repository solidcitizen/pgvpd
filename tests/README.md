# pgvpd Integration Tests

End-to-end tests that exercise pgvpd against a real Postgres instance.

## Prerequisites

- **Docker** — for the Postgres 17 container
- **psql** — Postgres client (`brew install libpq` or `brew install postgresql`)
- **cargo** — Rust toolchain

## Running

From the project root:

```bash
./tests/run.sh
```

The script handles everything: starts Postgres in Docker, loads fixtures, builds pgvpd, runs all tests, and cleans up on exit.

## What's tested

| # | Mode | Test | Verifies |
|---|------|------|----------|
| 1.1 | Passthrough | Tenant A isolation | RLS + context injection |
| 1.2 | Passthrough | Tenant B isolation | Cross-tenant boundary |
| 1.3 | Passthrough | Superuser bypass | Bypass skips injection |
| 1.4 | Passthrough | Bad username | Error handling for missing separator |
| 1.5 | Passthrough | Context variable | SET injection produces correct value |
| 2.1 | Pool | Auth + isolation | Pool auth + RLS context |
| 2.2 | Pool | Bad password | Client auth rejection |
| 2.3 | Pool | Superuser bypass | Superuser never pooled |
| 2.4 | Pool | Connection reuse | Pool checkout/checkin cycle |
| 2.5 | Pool | Client killed mid-query | Next holder of the connection sees only its own result (issue #11) |
| 2.6 | Pool | Drain on checkin | Abandoned responses are drained before reset (log) |
| 3.1 | Resolver | Context resolved | Resolver SQL populates session vars |
| 3.2 | Resolver | No rows | Empty context on unknown user (fail-closed) |
| 3.3 | Resolver | Cache hit | Resolver result caching |
| 7P.4 | Pool | node-pg churn + socket drops | `tests/drizzle/pool-desync.mjs` on `pgvpd-pool-desync-test.conf`: no protocol error, no shifted/empty result (issue #11) |
| 9.1 | Pool | Cancelled checkout (black-hole upstream) | Reserved slot released; bucket total returns to 0 (issue #20) |
| 9.2 | Pool | Not wedged after cancels | Fresh checkout is not blocked by leaked slots (issue #20) |
| 10.1 | Logging | Parent closes both stdio pipes | Connections survive; logging never panics a task (issue #21) |
| 11.1 | Handshake | Client connects and closes during handshake | Task ends promptly, no busy-spin to the handshake timeout (issue #24) |
| 12.1 | Admin API | Default vs. opt-in bind host | Admin API defaults to 127.0.0.1, not reachable off-host; PGVPD_ADMIN_HOST opts in (issue #13) |
| 13.1 | Pool | Upstream backends killed under the pool | Dead pooled connection discarded and checkout retried on a fresh one; client not victimized (issue #15) |

## Diagnostics

### `same-slot-probe.sh` — #14 drain-pin measurement

`./tests/same-slot-probe.sh` measures how long an abandoned in-flight query
pins a pooled slot before the next client can reuse it (issue #14). It runs
pgvpd on a single-connection pool (`pgvpd-pool-size1.conf`) so the next
checkout must reuse the abandoned slot, and reports the pin in milliseconds.

```bash
./tests/same-slot-probe.sh                    # measure (SLEEP_S=3)
SLEEP_S=8 ./tests/same-slot-probe.sh          # longer abandoned query (hits the 5s cap)
THRESHOLD_MS=200 ./tests/same-slot-probe.sh   # red-then-green pin: RED until #14 cancels the query
PGVPD_BIN=/path/to/pgvpd ./tests/same-slot-probe.sh
```

On 1.0.3 the pin is ~the abandoned query's remaining runtime, capped at the
5s reset timeout (then the slot is discarded and recreated); results are always
correct. It is a measurement, not part of `run.sh`; `THRESHOLD_MS` turns it into
a pass/fail assertion for verifying the #14 fix.

## Architecture

- **`docker-compose.yml`** — Postgres 17 on port 15432 (avoids conflicts with local Postgres or Supabase)
- **`fixtures.sql`** — Runs `sql/setup.sql`, then creates test tables and sample data
- **`pgvpd-test.conf`** — Passthrough mode config (port 16432 → 15432)
- **`pgvpd-pool-test.conf`** — Session pool mode config
- **`pgvpd-resolver-test.conf`** — Resolver mode config
- **`resolvers-test.toml`** — Single org_membership resolver for testing
- **`run.sh`** — Test runner: starts services, runs tests, reports results
