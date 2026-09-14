# Pgvpd

[![CI](https://github.com/solidcitizen/pgvpd/actions/workflows/ci.yml/badge.svg)](https://github.com/solidcitizen/pgvpd/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/pgvpd.svg)](https://crates.io/crates/pgvpd)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Virtual Private Database for PostgreSQL**

Pgvpd extends the Postgres wire protocol with tenant identity — the way
Oracle VPD does — so your ORM stays completely unaware of multi-tenancy.
It sits between your application and PostgreSQL, speaking the same binary
API that every Postgres client already uses. No HTTP gateway, no REST
layer, no SDK. Your application connects to pgvpd exactly like it
connects to Postgres, because it *is* the Postgres API — with tenant
context built into the connection handshake. Beyond simple identity
extraction, pgvpd resolves additional context (org membership, roles,
ACLs) from database state at connect time — the application provides a
user ID and the database derives the full security context.

```
Your App ──→ Pgvpd ──→ PostgreSQL (RLS enforced)
              ↕                 ↕
        Extracts identity   Policies enforce
        Resolves context    row-level security
        Injects SET vars    per connection
```

## The Problem

Postgres RLS can enforce tenant isolation, but someone has to call
`SET app.current_tenant_id` on every connection. If they forget, queries
run as a superuser and return **all tenants' data**. Every team hand-rolls
the same middleware, connection-pinning, and AsyncLocalStorage plumbing.
The application becomes the security boundary — and applications make mistakes.

ORMs make this worse. They treat database connections as fungible resources
and assume a single privileged role — exactly the opposite of what RLS
requires. The moment you use Drizzle, Prisma, or TypeORM with a standard
connection pool, every query runs in the same security context. Setting
per-request session variables requires manual connection pinning that the
ORM wasn't designed for, and a single missed code path fails open.

Platforms like Supabase (via PostgREST) and Hasura work around this by
routing queries through a REST or GraphQL gateway that sets RLS context
per request. But this means giving up the ORM entirely — you query
through the gateway's API, not SQL. You lose joins, transactions,
migrations, and the full expressiveness of Postgres. You also inherit the
gateway's limitations: response size caps, restricted query patterns, and
another service in the critical path. The database has a policy engine;
you shouldn't need a middleware layer to use it.

## The Solution

Encode the tenant in the username. Pgvpd handles the rest.

```bash
# Instead of connecting as:
psql -U app_user -d mydb

# Connect as:
psql -h localhost -p 6432 -U app_user.acme -d mydb
```

Pgvpd extracts `acme` as the tenant ID, rewrites the username to
`app_user`, and after authentication injects:

```sql
SET app.current_tenant_id = 'acme';
SET ROLE app_user;
```

Every subsequent query is scoped by RLS. The ORM never knows.

## Quick Start

### 1. Install

**From release binaries** (recommended):

```bash
# Linux x86_64
curl -sSL https://github.com/solidcitizen/pgvpd/releases/latest/download/pgvpd-linux-x86_64.tar.gz | tar xz
sudo mv pgvpd /usr/local/bin/

# macOS Apple Silicon
curl -sSL https://github.com/solidcitizen/pgvpd/releases/latest/download/pgvpd-macos-aarch64.tar.gz | tar xz
sudo mv pgvpd /usr/local/bin/
```

**From crates.io**:

```bash
cargo install pgvpd
```

**From source**:

```bash
git clone https://github.com/solidcitizen/pgvpd.git
cd pgvpd
cargo build --release
```

The binary is at `target/release/pgvpd`.

**Docker**:

```bash
docker run -p 6432:6432 ghcr.io/solidcitizen/pgvpd --upstream-host host.docker.internal
```

### 2. Set up Postgres

```bash
psql -U postgres -d your_database -f sql/setup.sql
```

This creates:
- `app_user` role with `NOSUPERUSER NOBYPASSRLS`
- `current_tenant_id()` function (fail-closed: returns NULL if unset)
- `pgvpd_protect()` helper to enable RLS on your tables
- `pgvpd_status()` to verify protection

### 3. Protect your tables

```sql
SELECT pgvpd_protect('contacts', 'tenant_id');
SELECT pgvpd_protect('invoices', 'org_id');
SELECT pgvpd_protect('orders', 'tenant_id');

-- Verify
SELECT * FROM pgvpd_status();
```

### 4. Start Pgvpd

```bash
# Point at your Postgres instance
./target/release/pgvpd --upstream-port 5432

# Or with a config file
cp pgvpd.conf.example pgvpd.conf
./target/release/pgvpd --config pgvpd.conf
```

### 5. Connect through Pgvpd

```bash
# From psql
psql -h localhost -p 6432 -U app_user.acme mydb

# From your application — just change the connection string
DATABASE_URL=postgresql://app_user.acme:password@localhost:6432/mydb
```

Your ORM (Drizzle, Prisma, TypeORM, etc.) connects to Pgvpd instead of
Postgres directly. No code changes. No middleware. No connection pinning.

## How It Works

**Passthrough mode** (default):

1. **Client connects** with username `app_user.acme`
2. **Pgvpd parses** the tenant ID (`acme`) from the username
3. **Username is rewritten** to `app_user` for upstream Postgres
4. **Auth is proxied** transparently (supports cleartext, MD5, SCRAM-SHA-256)
5. **Context resolvers** run (if configured) — SQL queries that derive additional session variables from database state
6. **After auth**, Pgvpd injects `SET app.current_tenant_id = 'acme'` (plus any resolver-derived variables)
7. **All traffic** is then piped transparently — zero overhead (`tokio::io::copy_bidirectional`)
8. **RLS policies** on every tenant-scoped table enforce isolation

**Pool mode** (`pool_mode = session`):

Steps 1–2 are the same, but Pgvpd authenticates the client itself (cleartext), checks out a pooled upstream connection, resets it (`DISCARD ALL`), resolves + injects context, and uses a message-aware pipe (`pipe_pooled`) that intercepts Terminate messages so the upstream connection can be returned to the pool. On disconnect, the connection is cleaned up with `ROLLBACK` → `DISCARD ALL` and returned to the idle pool.

### Fail-Closed Guarantee

- `app_user` has `NOSUPERUSER NOBYPASSRLS` — cannot bypass RLS
- `FORCE ROW LEVEL SECURITY` is on — even table owners are filtered
- `current_tenant_id()` returns `NULL` if the variable isn't set
- RLS policies match `tenant_id = current_tenant_id()` — NULL matches nothing
- **No context = no data. Never fail-open.**

## Context Resolvers

Resolvers are SQL queries that run after authentication to derive additional
session variables from database state — the Postgres equivalent of Oracle's
Real Application Security. The application provides identity (a user UUID);
the database resolves the full security context (org membership, team grants,
ACLs).

```toml
# resolvers.toml
[[resolver]]
name = "org_membership"
query = "SELECT org_id, role FROM org_members WHERE user_id = $1"
params = ["app.current_user_id"]
inject = { "app.org_id" = "org_id", "app.org_role" = "role" }
cache_ttl = 300
```

Configure with `resolvers = resolvers.toml` in your config file. Resolvers
execute in dependency order, chain results via bind parameters, and cache
results with configurable TTL. Failed required resolvers terminate the
connection (fail-closed).

### Using Existing Roles (`set_role`)

Managed Postgres platforms (Supabase, Neon, etc.) ship with NOLOGIN roles
that already have RLS policies and table grants attached:

```
authenticated  ← NOLOGIN, has all RLS policies and grants
service_role   ← NOLOGIN, bypasses RLS
anon           ← NOLOGIN, public access
```

These roles can't authenticate over the wire — the platform activates them
internally with `SET ROLE` after JWT validation. Without `set_role`, pgvpd
would authenticate as `app_user` and then `SET ROLE app_user`, which has
none of the existing policies. You'd have to duplicate every policy for the
new role.

`set_role` eliminates this. Pgvpd authenticates as `app_user` (LOGIN) but
switches to the platform's existing role:

```ini
# pgvpd.conf
set_role = authenticated
```

```sql
-- One-time setup: allow app_user to assume the role
GRANT authenticated TO app_user;
```

Now pgvpd injects:

```sql
SET app.current_tenant_id = 'acme';
SET ROLE authenticated;   -- not app_user
```

Every existing policy, grant, and RLS check works unchanged. `app_user`
exists only to get through the TCP handshake. When `set_role` is not
configured, pgvpd uses the rewritten username as before.

### Superuser Bypass

Admin connections (e.g., `postgres`) are passed through without tenant
extraction. Configure bypass usernames in `pgvpd.conf`:

```
superuser_bypass = postgres
```

## Configuration

| Option | Default | Env Var | Description |
|--------|---------|---------|-------------|
| `port` | 6432 | `PGVPD_PORT` | Listen port |
| `listen_host` | 127.0.0.1 | `PGVPD_HOST` | Bind address |
| `upstream_host` | 127.0.0.1 | `PGVPD_UPSTREAM_HOST` | Postgres host |
| `upstream_port` | 5432 | `PGVPD_UPSTREAM_PORT` | Postgres port |
| `tenant_separator` | `.` | `PGVPD_TENANT_SEPARATOR` | Separator in username |
| `context_variables` | `app.current_tenant_id` | `PGVPD_CONTEXT_VARIABLES` | Comma-separated session variables |
| `value_separator` | `:` | `PGVPD_VALUE_SEPARATOR` | Separator for multiple values |
| `superuser_bypass` | `postgres` | `PGVPD_SUPERUSER_BYPASS` | Bypass usernames (comma-separated) |
| `log_level` | `info` | `PGVPD_LOG_LEVEL` | debug/info/warn/error |
| `handshake_timeout` | 30 | `PGVPD_HANDSHAKE_TIMEOUT` | Max seconds for startup + auth + injection |
| `tls_port` | *(disabled)* | `PGVPD_TLS_PORT` | TLS listen port (requires tls_cert + tls_key) |
| `tls_cert` | — | `PGVPD_TLS_CERT` | Path to PEM certificate for TLS termination |
| `tls_key` | — | `PGVPD_TLS_KEY` | Path to PEM private key for TLS termination |
| `upstream_tls` | false | `PGVPD_UPSTREAM_TLS` | Connect to upstream Postgres over TLS |
| `upstream_tls_verify` | true | `PGVPD_UPSTREAM_TLS_VERIFY` | Verify upstream TLS certificate |
| `upstream_tls_ca` | — | `PGVPD_UPSTREAM_TLS_CA` | Custom CA cert for upstream TLS |
| `pool_mode` | none | `PGVPD_POOL_MODE` | `none` (passthrough) or `session` (pooling) |
| `pool_size` | 20 | `PGVPD_POOL_SIZE` | Max upstream connections per (database, role) |
| `pool_password` | — | `PGVPD_POOL_PASSWORD` | Password clients must provide in pool mode |
| `upstream_password` | — | `PGVPD_UPSTREAM_PASSWORD` | Password pgvpd uses to authenticate upstream |
| `pool_idle_timeout` | 300 | `PGVPD_POOL_IDLE_TIMEOUT` | Seconds idle before pooled connection is closed |
| `pool_checkout_timeout` | 5 | `PGVPD_POOL_CHECKOUT_TIMEOUT` | Seconds to wait when pool is full |
| `resolvers` | — | `PGVPD_RESOLVERS` | Path to context resolver TOML file |
| `set_role` | *(login user)* | `PGVPD_SET_ROLE` | Override SET ROLE target (e.g., `authenticated`) |
| `tenant_allow` | *(none)* | `PGVPD_TENANT_ALLOW` | Comma-separated allow list (only these tenants) |
| `tenant_deny` | *(none)* | `PGVPD_TENANT_DENY` | Comma-separated deny list (block these tenants) |
| `tenant_max_connections` | *(none)* | `PGVPD_TENANT_MAX_CONNECTIONS` | Max concurrent connections per tenant |
| `tenant_rate_limit` | *(none)* | `PGVPD_TENANT_RATE_LIMIT` | Max new connections per tenant per second |
| `tenant_query_timeout` | *(none)* | `PGVPD_TENANT_QUERY_TIMEOUT` | Seconds of inactivity before connection terminated |
| `admin_port` | *(disabled)* | `PGVPD_ADMIN_PORT` | HTTP port for admin API (health, metrics, status) |

Configuration is loaded in priority order: defaults → config file → environment variables → CLI flags.

### Multiple Context Variables

For apps that need more than one dimension of identity (e.g., tenant + user):

```
# pgvpd.conf
context_variables = app.current_list_id,app.current_user_id
value_separator = :
```

Username: `app_user.list123:user456` — Pgvpd injects both:

```sql
SET app.current_list_id = 'list123';
SET app.current_user_id = 'user456';
SET ROLE app_user;
```

## Connection Pooling

With `pool_mode = session`, Pgvpd maintains a pool of upstream Postgres
connections keyed by `(database, role)`. Clients authenticate to Pgvpd
directly (cleartext), and Pgvpd checks out a pooled upstream connection,
resets it, injects context, and pipes traffic using a message-aware
forwarder that intercepts Terminate messages to preserve the upstream
connection.

```ini
# pgvpd.conf
pool_mode = session
pool_size = 20
pool_password = secret
upstream_password = upstream_secret
pool_idle_timeout = 300
pool_checkout_timeout = 5
```

On disconnect, connections are cleaned up (`ROLLBACK` → `DISCARD ALL`) and
returned to the idle pool. An idle reaper closes connections that have been
unused longer than `pool_idle_timeout`. Superuser bypass connections are
never pooled.

If a client disconnects while a query is still in flight, pgvpd first drains
the responses that client never read (bounded by the 5-second reset timeout)
and only then resets and returns the connection. A connection that cannot be
brought to a known state is closed rather than reused, so a later client never
sees another session's messages. `pgvpd_pool_drains_total` on the admin
`/metrics` endpoint counts these events.

## TLS

**TLS termination** (client → Pgvpd): clients connect over TLS to
`tls_port`. Requires `tls_cert` and `tls_key` pointing to PEM files. The
plain listener continues on `port`.

**TLS origination** (Pgvpd → upstream): set `upstream_tls = true` to connect
to Postgres over TLS. Use `upstream_tls_verify = false` for self-signed
certs, or `upstream_tls_ca` for a custom CA.

## SQL Helpers

Pgvpd ships convenience SQL functions (`sql/helpers.sql`) that make RLS
policies readable and composable. Install them alongside `sql/setup.sql`:

```bash
psql -U postgres -d your_database -f sql/helpers.sql
```

### Context access

Replace verbose `current_setting()` + `NULLIF()` boilerplate:

```sql
-- Before
NULLIF(current_setting('app.user_id', true), '')
-- After
pgvpd_context('app.user_id')
```

| Function | Returns | Description |
|----------|---------|-------------|
| `pgvpd_context(var)` | `TEXT` | Read session variable (NULL if unset — fail-closed) |
| `pgvpd_context_array(var)` | `TEXT[]` | Parse comma-separated variable into text array |
| `pgvpd_context_uuid_array(var)` | `UUID[]` | Parse comma-separated variable into UUID array |
| `pgvpd_context_contains(var, uuid)` | `BOOLEAN` | Check if UUID is in a comma-separated variable |
| `pgvpd_context_text_contains(var, text)` | `BOOLEAN` | Check if text value is in a comma-separated variable |

### Multi-path RLS policies

`pgvpd_protect_acl()` builds complex RBAC policies from a JSON config:

```sql
SELECT pgvpd_protect_acl('cases', '[
  {"column": "creator_id", "var": "app.user_id", "type": "uuid"},
  {"column": "id",         "var": "app.granted_case_ids", "type": "uuid_array"},
  {"column": "org_id",     "var": "app.org_id", "type": "uuid",
   "when": "pgvpd_context(''app.org_role'') = ''admin''"}
]');
```

This generates a single policy where a user sees a row if they own it, have
a direct grant, or are an org admin — all enforced by the database.

Supported path types: `text`, `uuid`, `uuid_array`, `text_array`.

## Tests

**Unit tests**:

```bash
cargo test
```

**Integration tests** (end-to-end against a real Postgres via Docker):

```bash
./tests/run.sh
```

This starts a Postgres container, loads fixtures, builds pgvpd, and runs
6 test suites: passthrough, pool, resolvers, admin API, tenant isolation,
and SQL helpers (33 integration tests). Requires Docker and `psql`.

**Benchmarks** (requires running Postgres + pgvpd):

```bash
cargo bench --bench throughput
```

## With Drizzle ORM

```typescript
import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";

// Point at Pgvpd, encode tenant in username
const pool = new Pool({
  host: "localhost",
  port: 6432,
  user: `app_user.${tenantId}`,   // <-- tenant goes here
  password: "app_user_password",   // password for app_user role
  database: "mydb",
});

const db = drizzle(pool);

// Every query is now tenant-scoped. No middleware. No context. No pinning.
const contacts = await db.select().from(contactMaster);
```

See **[docs/drizzle-integration.md](docs/drizzle-integration.md)** for the
full guide: Express integration, pool-per-tenant patterns, transactions,
migration from connection pinning, and troubleshooting.

## Documentation

- **[docs/architecture.md](docs/architecture.md)** — How Pgvpd works:
  connection lifecycle, state machine, security model, wire protocol, and
  comparison with alternatives.
- **[docs/drizzle-integration.md](docs/drizzle-integration.md)** — Step-by-step
  guide for Drizzle ORM: Express middleware, pool strategies, multi-context
  variables, migration from connection pinning.
- **[PLAN.md](PLAN.md)** — Design rationale, roadmap, and the problem
  Pgvpd solves.

## Architecture

Pgvpd is written in **Rust** using [tokio](https://tokio.rs/) for async
I/O. It implements the minimum subset of the Postgres v3 wire protocol needed
for:

- Parsing `StartupMessage` to extract the tenant-encoded username
- Rewriting the username before forwarding to upstream Postgres
- Relaying SCRAM-SHA-256 (and other) authentication exchanges
- Executing context resolvers (SQL queries to derive session state)
- Injecting `SET` commands after authentication
- Bidirectional piping for all subsequent traffic

In passthrough mode, after the initial handshake (~3 messages), Pgvpd
adds **zero overhead** — it's a direct TCP pipe via
`tokio::io::copy_bidirectional`. In pool mode, the pipe (`pipe_pooled`) does
message-aware forwarding to intercept Terminate messages and preserve
upstream connections for reuse.

Components: `protocol.rs` (wire protocol), `connection.rs` (state machine),
`auth.rs` (authentication), `pool.rs` (connection pool), `resolver.rs`
(context resolvers), `stream.rs` (plain/TLS abstraction), `tls.rs` (TLS
config), `admin.rs` (HTTP admin API), `metrics.rs` (observability counters).

Single static binary. No runtime dependencies.

See **[docs/architecture.md](docs/architecture.md)** for the full
architecture deep-dive.

## License

MIT
