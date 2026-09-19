// Regression test for solidcitizen/pgvpd#15 — a pooled connection whose
// upstream has gone away (Postgres restart/failover, or an admin terminating
// the backend) must not victimize the next client. pgvpd should discard the
// dead connection and transparently retry checkout with a fresh one.
//
// Flow: warm the pool, kill pgvpd's upstream backends directly in Postgres
// (pg_terminate_backend), then reconnect through the proxy. Before the fix, the
// checkouts that reuse the now-dead idle connections fail (the client sees an
// error). After the fix, they recover on a fresh connection and the tenant
// context is still correct.
//
// Exit 0 (GREEN): all post-kill clients succeed with the right tenant context.
// Exit 2 (RED):   a post-kill client failed (dead connection surfaced).
//
// Env: PGVPD_BIN (required); UP_HOST/UP_PORT (upstream, default 127.0.0.1:15432),
//      PG_DB (default pgvpd_test), PG_PASS (default testpass).
import { spawn } from 'node:child_process';
import net from 'node:net';
import pg from 'pg';

const BIN = process.env.PGVPD_BIN;
if (!BIN) { console.error('PGVPD_BIN required'); process.exit(3); }

const PROXY = 16472, ADMIN = 16473;
let UP_HOST = process.env.UP_HOST || '127.0.0.1';
if (UP_HOST === 'localhost') UP_HOST = '127.0.0.1';
const UP_PORT = +(process.env.UP_PORT || 15432);
const DB = process.env.PG_DB || 'pgvpd_test';
const PASS = process.env.PG_PASS || 'testpass';
const POOL_ROLE = 'app_user';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const child = spawn(BIN, [], { env: { ...process.env,
  PGVPD_HOST: '127.0.0.1', PGVPD_PORT: String(PROXY), PGVPD_ADMIN_PORT: String(ADMIN),
  PGVPD_UPSTREAM_HOST: UP_HOST, PGVPD_UPSTREAM_PORT: String(UP_PORT),
  PGVPD_CONTEXT_VARIABLES: 'app.current_tenant_id', PGVPD_TENANT_SEPARATOR: '.',
  PGVPD_SUPERUSER_BYPASS: 'postgres', PGVPD_LOG_LEVEL: 'info',
  PGVPD_POOL_MODE: 'session', PGVPD_POOL_SIZE: '3',
  PGVPD_POOL_PASSWORD: PASS, PGVPD_UPSTREAM_PASSWORD: PASS,
  PGVPD_POOL_CHECKOUT_TIMEOUT: '5' },
  stdio: ['ignore', 'pipe', 'pipe'] });
let childErr = '';
child.stdout.on('data', () => {});
child.stderr.on('data', (d) => { if (childErr.length < 2000) childErr += d.toString(); });
child.on('error', (e) => { childErr += 'spawn error: ' + e.message + '\n'; });

function portOpen(port) {
  return new Promise((resolve) => {
    const s = new net.Socket();
    s.setTimeout(1000);
    s.once('connect', () => { s.destroy(); resolve(true); });
    s.once('timeout', () => { s.destroy(); resolve(false); });
    s.once('error', () => { s.destroy(); resolve(false); });
    s.connect(port, '127.0.0.1');
  });
}
async function waitForProxy(deadlineMs) {
  const end = Date.now() + deadlineMs;
  while (Date.now() < end) {
    if (child.exitCode !== null) return false;
    if (await portOpen(PROXY)) return true;
    await sleep(200);
  }
  return false;
}
// Connect through the proxy as a tenant, run a context-checking query.
async function probe() {
  const c = new pg.Client({ user: `${POOL_ROLE}.tenant_a`, password: PASS, host: '127.0.0.1', port: PROXY, database: DB });
  try {
    await c.connect();
    const r = await c.query("select current_setting('app.current_tenant_id') as t");
    return r.rows[0].t === 'tenant_a' ? 'ok' : 'BADCTX:' + r.rows[0].t;
  } catch (e) { return 'ERR:' + e.message.slice(0, 50); }
  finally { await c.end().catch(() => {}); }
}
// Kill pgvpd's upstream backends directly in Postgres.
async function killUpstreamBackends() {
  const admin = new pg.Client({ user: 'postgres', password: PASS, host: UP_HOST, port: UP_PORT, database: DB });
  await admin.connect();
  const r = await admin.query(
    "select pg_terminate_backend(pid) from pg_stat_activity where usename=$1 and pid<>pg_backend_pid()",
    [POOL_ROLE]);
  await admin.end().catch(() => {});
  return r.rowCount;
}

let code = 0;
try {
  if (!(await waitForProxy(20000))) { console.log('SETUP FAIL: proxy never came up | exit=', child.exitCode, '| err:', childErr.slice(0, 300)); child.kill('SIGKILL'); process.exit(3); }
  await sleep(300);

  // Warm the pool so idle connections exist to be killed.
  const before = [await probe(), await probe(), await probe()];
  if (before.some((r) => r !== 'ok')) { console.log('SETUP FAIL before kill:', before); child.kill('SIGKILL'); process.exit(3); }
  await sleep(300);

  const killed = await killUpstreamBackends();
  await sleep(300);

  // These checkouts reuse the now-dead idle connections first.
  const after = [];
  for (let i = 0; i < 6; i++) after.push(await probe());

  const allOk = after.every((r) => r === 'ok');
  console.log(JSON.stringify({ before, upstream_backends_killed: killed, afterKill: after, allOk }, null, 2));
  if (!allOk) code = 2;
} finally {
  child.kill('SIGKILL');
  await sleep(150);
}
process.exit(code);
