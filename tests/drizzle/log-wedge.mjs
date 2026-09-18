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
import net from 'node:net';
import pg from 'pg';

const BIN = process.env.PGVPD_BIN;
if (!BIN) { console.error('PGVPD_BIN required'); process.exit(3); }
// Dedicated ports so this suite never races another suite's pgvpd on port
// release (a bind conflict would make the spawned pgvpd exit before binding).
const PROXY = +(process.env.WEDGE_PROXY_PORT || 16442), ADMIN = +(process.env.WEDGE_ADMIN_PORT || 16443);
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
let childErr = '';
child.on('error', (e) => { childErr += 'spawn error: ' + e.message + '\n'; });
child.stdout.on('data', () => {});
child.stderr.on('data', (d) => { if (childErr.length < 2000) childErr += d.toString(); });

// Wait until the proxy is actually accepting TCP (a fixed sleep is flaky on
// slow/cold CI runners — the spawned pgvpd may not have bound the port yet).
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
    if (child.exitCode !== null) return false; // pgvpd died
    if (await portOpen(PROXY)) return true;
    await sleep(200);
  }
  return false;
}
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
  if (!(await waitForProxy(20000))) { console.log('SETUP FAIL: proxy never came up on', PROXY, '| childExit=', child.exitCode, 'signal=', child.signalCode, '| BIN=', BIN, '| childErr:', childErr.slice(0,500)); child.kill('SIGKILL'); process.exit(3); }
  // Give post-listen startup a beat to settle.
  await sleep(300);
  const before = await probe(2);
  if (before.some((r) => r !== 'ok')) { console.log('SETUP FAIL before pipe close:', before); child.kill('SIGKILL'); process.exit(3); }

  child.stdout.destroy();
  child.stderr.destroy();
  await sleep(200);

  const after = [...await probe(6), ...(await sleep(400), await probe(3))];
  await sleep(500); // let the just-closed connections settle before reading active
  const active = await activeCount();
  const allOk = after.every((r) => r === 'ok');
  // Healthy: active settles back to ~0 (a connection mid-close may briefly show
  // 1-2). Wedged: every accepted-then-dropped task leaks, so active tracks the
  // number of post-close attempts (9 here) and never falls.
  const leaked = active > 4;
  console.log(JSON.stringify({ before, afterPipeClose: after, connections_active: active, allOk, leaked, childAlive: child.exitCode === null }, null, 2));
  if (!allOk || leaked) code = 2;
} finally {
  child.kill('SIGKILL');
  await sleep(150);
}
process.exit(code);
