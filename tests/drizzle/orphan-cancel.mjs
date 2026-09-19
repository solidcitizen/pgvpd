// Regression test for solidcitizen/pgvpd#14 — when a client abandons an
// in-flight query (drops its socket mid-query), pgvpd should cancel the orphaned
// query upstream at checkin instead of leaving it running until the drain times
// out. Rides the #12 cancel machinery (the connection's real backend key).
//
// A starts a long pg_sleep and drops its socket. Shortly after, no app_user
// pg_sleep should still be active upstream.
//
// Exit 0 (GREEN): the orphaned query is gone (cancelled) shortly after the drop.
// Exit 2 (RED):   it is still running (no cancel; runs until drain timeout).
//
// Env: PGVPD_BIN (required); UP_HOST/UP_PORT, PG_DB, PG_PASS as elsewhere.
import { spawn } from 'node:child_process';
import net from 'node:net';
import pg from 'pg';

const BIN = process.env.PGVPD_BIN;
if (!BIN) { console.error('PGVPD_BIN required'); process.exit(3); }

const PROXY = 16492, ADMIN = 16493;
let UP_HOST = process.env.UP_HOST || '127.0.0.1';
if (UP_HOST === 'localhost') UP_HOST = '127.0.0.1';
const UP_PORT = +(process.env.UP_PORT || 15432);
const DB = process.env.PG_DB || 'pgvpd_test';
const PASS = process.env.PG_PASS || 'testpass';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const child = spawn(BIN, [], { env: { ...process.env,
  PGVPD_HOST: '127.0.0.1', PGVPD_PORT: String(PROXY), PGVPD_ADMIN_PORT: String(ADMIN),
  PGVPD_UPSTREAM_HOST: UP_HOST, PGVPD_UPSTREAM_PORT: String(UP_PORT),
  PGVPD_CONTEXT_VARIABLES: 'app.current_tenant_id', PGVPD_TENANT_SEPARATOR: '.',
  PGVPD_SUPERUSER_BYPASS: 'postgres', PGVPD_LOG_LEVEL: 'info',
  PGVPD_POOL_MODE: 'session', PGVPD_POOL_SIZE: '2',
  PGVPD_POOL_PASSWORD: PASS, PGVPD_UPSTREAM_PASSWORD: PASS },
  stdio: ['ignore', 'pipe', 'pipe'] });
child.stdout.on('data', () => {});
let childErr = '';
child.stderr.on('data', (d) => { if (childErr.length < 2000) childErr += d.toString(); });

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
async function waitForProxy(ms) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (child.exitCode !== null) return false;
    if (await portOpen(PROXY)) return true;
    await sleep(200);
  }
  return false;
}
// Count only OUR marked query, so leftover sleeps from other runs don't pollute.
async function activeMarked(marker) {
  const admin = new pg.Client({ user: 'postgres', password: PASS, host: UP_HOST, port: UP_PORT, database: DB });
  await admin.connect();
  const r = await admin.query(
    "select count(*)::int as n from pg_stat_activity where usename='app_user' and state='active' and query like $1",
    ['%' + marker + '%']);
  await admin.end().catch(() => {});
  return r.rows[0].n;
}

let code = 0;
try {
  if (!(await waitForProxy(20000))) { console.log('SETUP FAIL: proxy never came up | err:', childErr.slice(0, 300)); child.kill('SIGKILL'); process.exit(3); }
  await sleep(300);

  const marker = 'orphan_' + Math.random().toString(36).slice(2, 10);
  const a = new pg.Client({ user: 'app_user.tenant_a', password: PASS, host: '127.0.0.1', port: PROXY, database: DB });
  a.on('error', () => {}); // swallow the client error from the abrupt socket drop
  await a.connect();
  a.query(`select pg_sleep(30) /* ${marker} */`).catch(() => {}); // fire, do not await
  await sleep(600); // query now active upstream
  const activeBefore = await activeMarked(marker);

  // Abandon the query: drop the client socket abruptly (no Terminate).
  a.connection.stream.destroy();
  await sleep(1800); // pgvpd detects EOF, checks in, cancels the orphan

  const activeAfter = await activeMarked(marker);
  console.log(JSON.stringify({ active_before_drop: activeBefore, active_after_drop: activeAfter }, null, 2));
  // GREEN: it was running before, and cancelled shortly after the drop.
  if (activeBefore < 1 || activeAfter !== 0) code = 2;
} catch (e) {
  console.log('ERROR:', e.message);
  code = 3;
} finally {
  child.kill('SIGKILL');
  await sleep(150);
}
process.exit(code);
