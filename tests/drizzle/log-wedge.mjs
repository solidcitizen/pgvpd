// Regression test for solidcitizen/pgvpd#21 — logging must never kill a
// connection task. Spawns pgvpd with piped stdout+stderr (as a parent that
// re-emits its logs would), warms up 2 tenant connections, then DESTROYS both
// pipes while pgvpd keeps running. Before the fix, the next per-connection log
// write panicked the task (tracing's error fallback eprintln! hit the closed
// stderr and panicked), so every subsequent connection was accepted then
// dropped, connections_active leaked upward, and checkouts froze — a permanent
// wedge. With logging on a non-blocking writer, connections keep working.
//
// Exit 0: connections after the pipe close all succeed and active does not leak.
// Exit 2: a connection failed or active leaked (wedged).
//
// Env: PGVPD_BIN (required), PGVPD_HOST/PGVPD_PORT for the upstream, PG_DB/PG_PASS.
import { spawn } from 'node:child_process';
import pg from 'pg';

const BIN = process.env.PGVPD_BIN;
if (!BIN) { console.error('PGVPD_BIN required'); process.exit(3); }
const PROXY = 16432, ADMIN = 16433;
const UP_HOST = process.env.PGVPD_HOST || '127.0.0.1';
const UP_PORT = process.env.PGVPD_PORT || '15432';
const DB = process.env.PG_DB || 'pgvpd_test';
const PASS = process.env.PG_PASS || 'testpass';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const child = spawn(BIN, [], { env: { ...process.env,
  PGVPD_PORT: String(PROXY), PGVPD_ADMIN_PORT: String(ADMIN),
  PGVPD_UPSTREAM_HOST: UP_HOST, PGVPD_UPSTREAM_PORT: String(UP_PORT),
  PGVPD_CONTEXT_VARIABLES: 'app.current_tenant_id', PGVPD_TENANT_SEPARATOR: '.',
  PGVPD_SUPERUSER_BYPASS: 'postgres', PGVPD_LOG_LEVEL: 'info',
  PGVPD_POOL_MODE: 'session', PGVPD_POOL_SIZE: '8',
  PGVPD_POOL_PASSWORD: PASS, PGVPD_UPSTREAM_PASSWORD: PASS,
  PGVPD_POOL_IDLE_TIMEOUT: '300', PGVPD_POOL_CHECKOUT_TIMEOUT: '5' },
  stdio: ['ignore', 'pipe', 'pipe'] });
child.stdout.on('data', () => {}); child.stderr.on('data', () => {});

async function activeCount() {
  try { const j = await (await fetch(`http://127.0.0.1:${ADMIN}/status`)).json(); return j.connections_active; }
  catch { return -1; }
}
async function probe(n) {
  const out = [];
  for (let i = 0; i < n; i++) {
    const c = new pg.Client({ user: 'app_user.tenant_a', password: PASS, host: '127.0.0.1', port: PROXY, database: DB });
    try { await c.connect(); await c.query('select 1'); out.push('ok'); }
    catch (e) { out.push('ERR:' + e.message.slice(0, 40)); }
    finally { await c.end().catch(() => {}); }
  }
  return out;
}

let code = 0;
try {
  await sleep(1000);
  const before = await probe(2);
  if (before.some((r) => r !== 'ok')) { console.log('SETUP FAIL before pipe close:', before); process.exitCode = 3; child.kill('SIGKILL'); process.exit(3); }

  child.stdout.destroy();
  child.stderr.destroy();
  await sleep(200);

  const after = [...await probe(6), ...(await sleep(400), await probe(3))];
  const active = await activeCount();
  const allOk = after.every((r) => r === 'ok');
  const leaked = active > 1; // healthy: returns to ~0; wedged: climbs and stays
  console.log(JSON.stringify({ before, afterPipeClose: after, connections_active: active, allOk, leaked, childAlive: child.exitCode === null }, null, 2));
  if (!allOk || leaked) code = 2;
} finally {
  child.kill('SIGKILL');
  await sleep(150);
}
process.exit(code);
