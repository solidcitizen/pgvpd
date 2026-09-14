# pgvpd Threat Model

pgvpd makes tenant identity a property of the database connection. This
document states who is trusted, what each secret grants, where the boundary
is, and what an attacker who crosses it can do. Consumers should read it
before deciding where to run the proxy and who may reach its ports.

## Components and trust

| Component | Trusted? | Why |
|---|---|---|
| Application connecting through pgvpd | **yes** | It asserts the tenant context in the username. pgvpd does not verify that the caller is entitled to that tenant; the application is expected to derive it from its own authenticated session. |
| pgvpd process | yes | It rewrites the username, injects `SET` statements, and in pool mode holds the upstream credentials. |
| PostgreSQL | yes (enforcer) | Row Level Security policies are the only thing that filters rows. pgvpd only sets the context those policies read. |
| Anything else that can open a TCP connection to a pgvpd port | **no** | See "Boundary". |

## What each secret grants

- **`pool_password`** (pool mode): the right to open a session as **any tenant
  context** for the pool role. Whoever holds it is the application. Treat it
  like the upstream database password.
- **`upstream_password`** / the `app_user` credentials: pgvpd's own upstream
  login. Never given to clients. The role must be `NOSUPERUSER NOBYPASSRLS`
  (`sql/setup.sql` creates it that way) so that even a compromised pgvpd
  cannot read across tenants without the context being set.
- **The username** (`app_user.<tenant>` or `app_user.<a>:<b>:<c>`): not a
  secret. It is an assertion, accepted from anyone who authenticates.
- **Superuser bypass names** (`superuser_bypass`): connections with these
  usernames are relayed untouched to Postgres. Their security is Postgres's
  own authentication for that role; pgvpd adds nothing and removes nothing.

## Boundary

The boundary is the network reachability of the proxy port. Because the
username is an assertion, **every client that can reach the proxy port and
present `pool_password` (or, in passthrough mode, valid Postgres credentials
for the login role) can claim any tenant.**

Consequences:

- Run pgvpd on the same host as the application, or on a private network
  segment the application alone can reach. `listen_host` defaults to
  `127.0.0.1` for this reason.
- Do not expose the proxy port through a load balancer to the internet, even
  with TLS. TLS protects the wire, not the assertion.
- The admin API (`admin_port`) currently binds all interfaces and has no
  authentication (issue #13). The exposure is `/status`, which reveals database
  names, roles and pool occupancy. `/metrics` carries only aggregate counters,
  including rejections grouped by reason (`reason="deny|limit|rate"`) — no
  tenant identifiers or row data. Until the bind default and token land,
  restrict the admin port with a host firewall.

## What an attacker can do

| Attacker | Capability | Outcome |
|---|---|---|
| Can reach the proxy port, has `pool_password` | claim any tenant | full read/write within RLS for that tenant. This is the application's own privilege; protecting the password and the port is the whole defence. |
| Can reach the proxy port, no password | none | pool mode authenticates the client before checkout; passthrough relays Postgres authentication. Failed attempts are rate-limitable per tenant (`tenant_rate_limit`). |
| Can reach the admin port | read operational state | no data access; information disclosure only (#13). |
| Compromised pgvpd process | upstream credentials for `app_user` | bounded by `NOSUPERUSER NOBYPASSRLS` and `FORCE ROW LEVEL SECURITY`: rows are still filtered by whatever context the attacker sets, one tenant at a time; no cross-tenant query is possible in a single statement. |
| Another client of the same pgvpd (co-tenant) | shares the upstream pool | must never observe another session's messages or state. Guaranteed by drain-before-reset at checkin (issue #11, 1.0.3) and `DISCARD ALL` on checkin and checkout; verified by `tests/run.sh` 2.5, 2.6, 7P.4 and the reset-completeness suite planned in `docs/adversarial-test-plan.md`. |
| Postgres superuser | everything | out of scope; RLS does not bind superusers. |

## Fail-closed properties pgvpd relies on

- `current_tenant_id()` returns `NULL` when the variable is unset, and RLS
  policies compare against it, so a session without context matches no rows.
- A resolver failure terminates the connection rather than continuing with
  partial context.
- A pooled connection whose protocol state cannot be verified at checkin is
  closed, never reused.
- Empty context values are injected as `''`, which matches nothing.

## Session state does not survive a pooled hand-off

In pool mode a single upstream connection is reused across many client
sessions. `DISCARD ALL` at checkin (and checkout) clears all session-lifetime
state — temporary tables, prepared statements, session GUCs, `search_path`,
`SET ROLE`, cursors, `LISTEN` registrations, and **session-level advisory
locks** (`DISCARD ALL` runs `pg_advisory_unlock_all()`). This is correct and
required for isolation, but it has a consequence callers must respect:

- **Do not rely on session-lifetime state across requests through a pooled
  connection.** Anything a client sets on one checkout is gone on the next.
- **Session-level advisory locks must not be taken through pooled sessions.**
  A lock a client holds is released the moment its session is handed back, and
  a different tenant checking out the same backend can immediately acquire the
  same lock id. A verifier confirmed this: a rival tenant took the same lock
  one second later on the same backend pid. Code that needs a lock to outlive
  a single query — coordination leases, drain ownership — must use a direct,
  non-pooled connection (or transaction-level locks held within one
  transaction). Transaction-scoped advisory locks are safe because they are
  released at transaction end, before hand-off.

An in-flight query keeps its own session locks until it finishes, even after
the client disconnects, because Postgres runs the query to completion. A
client that abandons a slow locking query can therefore orphan a lock for the
duration of that query. Mitigation is tracked separately (see the issue
register); operators can bound it with `tenant_query_timeout`.

## Out of scope

- Attacks on PostgreSQL itself, or policies that are wrong or missing
  (`pgvpd_status()` exists to audit coverage; it does not enforce it).
- Denial of service against the proxy beyond the per-tenant limits
  (`tenant_max_connections`, `tenant_rate_limit`, `tenant_query_timeout`).
- Replication protocol and `LISTEN`/`NOTIFY` delivery across pooled
  hand-offs (not supported in pool mode).
- Query cancellation through the proxy (issue #12).
