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

## Architecture

- **`docker-compose.yml`** — Postgres 17 on port 15432 (avoids conflicts with local Postgres or Supabase)
- **`fixtures.sql`** — Runs `sql/setup.sql`, then creates test tables and sample data
- **`pgvpd-test.conf`** — Passthrough mode config (port 16432 → 15432)
- **`pgvpd-pool-test.conf`** — Session pool mode config
- **`pgvpd-resolver-test.conf`** — Resolver mode config
- **`resolvers-test.toml`** — Single org_membership resolver for testing
- **`run.sh`** — Test runner: starts services, runs tests, reports results
