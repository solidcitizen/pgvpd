// Regression test for solidcitizen/pgvpd#11 — pool-mode session hand-off.
//
// Many concurrent short-lived checkouts from several node-postgres pools, each
// running one query, while (in "poison" mode) a client periodically sends a
// slow query and destroys its socket before the response arrives. Before the
// fix, the abandoned response stayed on the shared upstream connection and the
// next holder saw it: either "Received unexpected commandComplete message from
// backend" or, worse, its own query resolving with an empty, shifted result.
//
// Exit 0: every query on every fresh holder returned exactly its own result.
// Exit 2: a protocol error or a shifted/empty result was observed.
//
// Env: PGVPD_HOST, PGVPD_PORT, PG_DB, PG_PASS (pool password), ROUNDS,
//      TENANT_POOLS, CONC, POISON_EVERY.  Arg: "poison" (default) or "clean".
import pg from 'pg';

const { Pool, Client } = pg;

const mode = process.argv[2] || 'poison';
const base = {
  host: process.env.PGVPD_HOST || '127.0.0.1',
  port: +(process.env.PGVPD_PORT || 16432),
  database: process.env.PG_DB || 'pgvpd_test',
  password: process.env.PG_PASS || 'testpass',
};
// Defaults are tuned for tests/pgvpd-pool-desync-test.conf (pool_size 8): run
// with pool_size >= CONC so hand-offs are immediate. A saturated pool queues
// checkouts, which tends to coalesce a stale response with the fresh one in a
// single read and hides the defect this test exists to catch.
const ROUNDS = +(process.env.ROUNDS || 200);
const TENANT_POOLS = +(process.env.TENANT_POOLS || 6);
const CONC = +(process.env.CONC || 8);
// About one drop in four produced a visible shift on 1.0.2; 40 drops per run
// make a silent pass on a broken build vanishingly unlikely.
const POISON_EVERY = +(process.env.POISON_EVERY || 5);

const stats = { ok: 0, shifted: 0, protocol: 0, other: 0, dropsInjected: 0, samples: [] };
const PROTOCOL_RE = /unexpected \w+ message from backend/i;

function record(kind, message, extra = {}) {
  stats[kind]++;
  if (stats.samples.length < 10) stats.samples.push({ kind, ...extra, message });
}

const tenants = Array.from({ length: TENANT_POOLS }, (_, i) => (i % 2 ? 'tenant_b' : 'tenant_a'));
const pools = tenants.map((tenant) => {
  const pool = new Pool({ ...base, user: `app_user.${tenant}`, max: 2, idleTimeoutMillis: 40, connectionTimeoutMillis: 15000 });
  pool.on('error', (e) => record(PROTOCOL_RE.test(e.message) ? 'protocol' : 'other', e.message, { tenant, at: 'pool' }));
  pool.on('acquire', (client) => {
    if (client.__guarded) return;
    client.__guarded = true;
    client.on('error', (e) => record(PROTOCOL_RE.test(e.message) ? 'protocol' : 'other', e.message, { tenant, at: 'client' }));
  });
  return pool;
});

async function checkout(round, i) {
  const idx = (round * CONC + i) % pools.length;
  const pool = pools[idx];
  const tenant = tenants[idx];
  let client;
  try {
    client = await pool.connect();
    const r = await client.query(
      "SELECT current_setting('app.current_tenant_id') AS t, count(*)::int AS n FROM tenants",
    );
    const row = r.rows && r.rows.length === 1 ? r.rows[0] : null;
    if (!row || row.t !== tenant || row.n !== 2) {
      // The data-integrity failure mode: a shifted or empty response with no error.
      record('shifted', `expected ${tenant}/2, got ${JSON.stringify(r.rows)} (command=${r.command})`, { round, i, tenant });
      client.release(new Error('shifted result'));
      client = null;
    } else {
      stats.ok++;
    }
  } catch (e) {
    record(PROTOCOL_RE.test(e.message) ? 'protocol' : 'other', e.message, { round, i, tenant });
    if (client) {
      client.release(e);
      client = null;
    }
  }
  if (client) client.release();
}

// A client that sends a query and drops its socket before the response arrives —
// what node-postgres does on end() with an active query, and what any abrupt
// process or connection failure looks like to the proxy.
async function dropMidQuery() {
  const client = new Client({ ...base, user: 'app_user.tenant_a' });
  client.on('error', () => {});
  try {
    await client.connect();
    client.query('SELECT pg_sleep(0.3)').catch(() => {});
    await new Promise((resolve) => setTimeout(resolve, 60));
    client.connection.stream.destroy();
    stats.dropsInjected++;
  } catch (e) {
    record('other', `drop client: ${e.message}`);
  }
}

const started = Date.now();
for (let round = 0; round < ROUNDS; round++) {
  const work = Array.from({ length: CONC }, (_, i) => checkout(round, i));
  if (mode === 'poison' && round % POISON_EVERY === 0) work.push(dropMidQuery());
  await Promise.all(work);
}
await Promise.all(pools.map((pool) => pool.end()));

const seconds = ((Date.now() - started) / 1000).toFixed(1);
console.log(JSON.stringify({ mode, rounds: ROUNDS, conc: CONC, tenantPools: TENANT_POOLS, seconds, ...stats }, null, 2));
process.exit(stats.protocol + stats.shifted > 0 ? 2 : 0);
