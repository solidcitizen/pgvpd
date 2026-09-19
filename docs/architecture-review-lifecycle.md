# Architecture Review — Connection Lifecycle & Failure Handling

Scope: the connection lifecycle in `proxy.rs → connection.rs → pool.rs`, reviewed
after four independently-reported defects (#11, #20, #21, #24) turned out to share
a root. This document maps the class, states where the code is already sound, and
lists the latent defects the map predicts — including several not yet filed.

Reviewed at `v1.0.5` (commit line ending `222999f`). Severity is judged against
the deployed threat model: pgvpd fronts Postgres on loopback / a private network,
clients are the operator's own application instances (semi-trusted, possibly buggy
or overloaded), not arbitrary internet peers. So the findings below are
robustness/availability and information-exposure class, not RCE/hostile-input class.

## The lifecycle

```
accept (proxy.rs)                     ── inc connections_active (NOT raii)
 └─ spawn task
     └─ handshake()  ── wrapped in tokio::time::timeout(handshake_timeout, 30s)
         ├─ Phase 1: read StartupMessage        [loop, read_buf]
         ├─ superuser bypass → Passthrough
         ├─ extract tenant ctx from username
         ├─ tenant_registry.acquire → TenantGuard (raii ✓)
         └─ branch:
             ├─ handle_pooled
             │    ├─ authenticate_client
             │    ├─ pool.checkout   ── SlotReservation raii ✓ (#20)
             │    ├─ PoolLease raii ✓
             │    ├─ DISCARD ALL reset   [loop, read_buf]
             │    ├─ resolve_context     [loop, read_buf]
             │    ├─ inject SET/SET ROLE [loop, read_buf]
             │    └─ synthesize handshake to client
             └─ handle_passthrough
                  ├─ connect_upstream
                  ├─ auth relay          [loop, read_buf]
                  ├─ post-auth wait RFQ   [loop, read_buf]
                  └─ resolve + inject     [loop, read_buf]
     ── pipe phase ──
     ├─ Passthrough: copy_bidirectional
     └─ Pooled: pipe_pooled  ── handles Ok(0) EOF ✓ (#11)
         └─ lease.checkin → pool.checkin
              ├─ drain_outstanding  ── handles Ok(0) EOF ✓ (#11)
              └─ send_and_drain     ── is_err() only, MISSES Ok(0)
 └─ dec connections_active (NOT raii)
```

## What is already sound

- **Pool slot accounting is cancellation-safe.** `bucket.total` is reserved under a
  std `Mutex` never held across an await, and every reserved-across-await path is
  guarded: `SlotReservation` for create (#20), `PoolLease` for the leased slot. The
  idle-reuse path returns synchronously within one poll, so no cancellation window
  exists between checkout and lease. Verified by tracing every `await` between
  reservation and ownership. No remaining slot-leak path found.
- **The steady-state pipe is complete.** `pipe_pooled` intercepts Terminate, counts
  sync points vs. ReadyForQuery across arbitrary read boundaries, handles client and
  upstream EOF, and hands the pool enough state to drain-or-discard (#11). `checkin`
  drains outstanding responses and discards on any doubt. This is the model the rest
  of the code should have followed.
- **Logging is off the data path** (#21): non-blocking writer, no write from a
  connection task can panic it.

## The class: abnormal transitions are handled in the pipe, not in the handshake

The pipe phase was hardened bug-by-bug (#11, #20, #21). The **handshake, reset,
auth, resolve, and checkin-reset paths never received the same treatment.** Every
open register item is an instance of this one gap.

### Gap 1 — EOF-blindness in handshake-phase read loops  (#24 + family)

`read_buf()` returns `Ok(0)` on EOF; it is **not** an error. The pipe treats `Ok(0)`
as "peer closed" and finishes. The handshake-family loops instead use
`read_buf(...).await?` (error-only) or `.is_err()` and treat `Ok(0)` as "no data
yet, loop again" — so a FIN'd socket busy-spins the task, burning a core until a
timeout fires.

Instances (all confirmed by inspection):

| Loop | File:line | Peer | Bound |
|---|---|---|---|
| StartupMessage | connection.rs:362 | client | handshake_timeout 30s (#24) |
| auth relay | connection.rs:557 | upstream | 30s |
| auth challenge read | connection.rs:575 | client | 30s |
| post-auth RFQ | connection.rs:585 | upstream | 30s |
| pooled DISCARD ALL reset | connection.rs:700 | upstream | 30s |
| pooled inject | connection.rs:761 | upstream | 30s |
| passthrough inject | connection.rs:869 | upstream | 30s |
| pool create_connection | pool.rs:405 | upstream | 30s (checkout is inside handshake_timeout) |
| checkin send_and_drain | pool.rs:357 | upstream | reset_timeout 5s |

Correct model already in-tree: `pipe_pooled` (connection.rs:249,275) and
`drain_outstanding` (pool.rs:333). `auth.rs` and `resolver.rs` read loops share the
pattern and need auditing under the same fix.

**Fix shape (one change, not nine):** a shared EOF-aware read helper —
`read_or_eof(stream, buf) -> io::Result<usize>` that maps `Ok(0)` to a distinct
"peer closed during handshake" error — and route every loop above through it.
Uniform, testable, removes the whole class.

**Severity:** availability/CPU. Bounded per-connection by the timeouts, but a
connect-and-close storm (or an upstream that FINs mid-handshake) pins one spinning
core per event for up to 30s. Loopback-bounded, so not urgent — but cheap to kill.

### Gap 2 — no upstream-liveness handling / no discard-and-retry  (#15 + #14)

When a pooled connection's upstream has died (Postgres restart, failover, idle
server-side timeout), the death is discovered **only when a client checks the
connection out and the reset write/read fails.** Consequences:

- That client's connection fails (FATAL to the client, or — via Gap 1 — a 30s spin
  then handshake timeout) instead of transparently retrying on a fresh upstream.
- The `idle_reaper` reaps by wall-clock idle time only (pool.rs:454), never by
  liveness. After an upstream bounce, a bucket can hold N dead connections; under
  load, N clients are victimized one-by-one until the bucket is cleared.

**Fix shape (#15):** on a failed checkout-reset, discard and retry with a fresh
`create_connection` within the checkout call, transparent to the client (bounded
retry count). Optionally add a liveness probe / generation counter so an upstream
bounce invalidates a whole bucket at once.

**Related (#14):** an abandoned in-flight query pins its slot through checkin —
`drain_outstanding` *waits* for the orphaned query to finish (capped at the 5s reset
timeout, then discard). The fix is to **cancel** the orphaned query rather than wait,
which requires the cancel machinery below.

### Gap 3 — `connections_active` is not panic-safe

`connections_active` is inc'd (proxy.rs:212/257) and dec'd (233/271) as bare
statements bracketing the `.await` on `handle_connection`. `tokio::spawn` catches a
panic, so a panic anywhere in the connection path **skips the dec and leaks the
gauge permanently.** This is the exact mechanism by which #21 presented as a "wedge":
the leaked gauge is what NexusPlus's monitoring reads. The #21 *fix* removed one
panic source (logging); the *structural* vulnerability — any future panic leaks the
gauge — remains, and the gauge is load-bearing for the customer's wedge detection.

**Fix shape:** a `ConnectionGuard` that inc's on construction and dec's on `Drop`,
replacing the bracketing statements. Cheap, and makes the gauge honest under panic.
(The tenant count already does this correctly via `TenantGuard`.)

## Discrete design findings (not pure lifecycle, surfaced by the review)

### D1 — cancel keys are shared per bucket; CancelRequest is a no-op  (#12)

- `CancelRequest` is dropped on the floor (connection.rs:370): a client's query
  cancel (psql Ctrl-C, `pg_cancel_backend`) does nothing in pooled mode.
- Worse for any future fix: the synthesized handshake sends the **bucket-cached**
  `backend_key_data` (pool.rs:189, connection.rs:790) to *every* client on that
  bucket. So all clients share one cancel key, and it maps to whichever upstream
  connection happens to hold it. A naive #12 implementation that forwarded the
  client's CancelRequest would cancel the **wrong tenant's** query.

**Fix shape:** pgvpd must mint a **unique per-client** BackendKeyData at synthesis,
keep a `cancel_key → (upstream conn identity)` map for the life of the checkout, and
translate an incoming CancelRequest to a real upstream CancelRequest. #12 and #14
both depend on this. This is the highest-value item in the register: it is the one
with a correctness/isolation edge, not just availability.

### D2 — admin API binds `0.0.0.0` with no auth  (#13)

`admin::serve` binds `0.0.0.0:{admin_port}` (admin.rs:39). `/status` and `/metrics`
expose pool topology — every `database`, `role`, and bucket count — to anything that
can route to the host. On a single-homed loopback deployment this is inert; on a
multi-homed host it is an information leak of the tenant/role namespace.

**Fix shape:** bind a configurable address defaulting to `127.0.0.1`; optionally a
bearer token. Backward-compatible via an opt-in `admin_host`.

### D3 — no maximum connection lifetime; `created_at` is meaningless

`checkin` rebuilds the `PooledConn` with `created_at: Instant::now()` (pool.rs:305),
so a pooled upstream connection is only ever aged out by *idle* time, never by total
age. A steadily-used bucket can hold connections that live for the process lifetime,
accumulating server-side memory/state. Minor, but it means there is no backstop for a
slowly-degrading upstream connection.

**Fix shape:** preserve real `created_at`; add an optional `pool_max_lifetime` checked
at checkout/checkin.

### D4 — slowloris / large-message slot pinning in the pipe

`forward_client_messages` buffers a full frontend message before forwarding
(connection.rs:329); a client can announce a large length and dribble bytes. The
idle deadline resets on *any* read progress (connection.rs:273), so a slow-dribble
never trips the query timeout, pinning a pooled slot and growing per-connection
memory up to the ~2GB protocol max. Loopback-bounded, low priority, but it is a
resource-exhaustion path with no current backstop.

**Fix shape:** cap in-flight frontend message size and/or use an absolute (not
sliding) deadline for a single request.

## Register mapped to the class

| Item | Gap | Class |
|---|---|---|
| #24 | Gap 1 | availability (EOF spin) |
| #15 | Gap 2 | availability (no retry) |
| #14 | Gap 2 / D1 | availability (orphan-query pin) |
| #12 | D1 | **correctness/isolation** (cancel) |
| #13 | D2 | information exposure |
| #16 | — | metric/log/CI-lint cleanup |
| *new* | Gap 3 | availability (panic leaks gauge) |
| *new* | D3 | robustness (no max lifetime) |
| *new* | D4 | robustness (slowloris pin) |

## Recommended sequencing for 1.0.6

1. **Gap 1** — shared EOF-aware read helper. Retires #24 and hardens eight sibling
   loops in one reviewable change. Lowest risk, highest breadth.
2. **D1 + #12 + #14** — per-client cancel-key machinery. Highest value (the only
   isolation-class item); #14 rides it.
3. **Gap 2 / #15** — discard-and-retry on dead-upstream checkout.
4. **Gap 3** — `ConnectionGuard` for `connections_active`.
5. **D2 / #13** — admin bind hardening (opt-in, backward compatible).
6. **D3, D4, #16** — cleanup tail.

The adversarial sweep (`docs/adversarial-test-plan.md`) exists to *prove this map*:
each gap gets a red-then-green scenario against 1.0.5 before any fix lands.
</content>
</invoke>
