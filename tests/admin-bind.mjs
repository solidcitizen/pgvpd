// Regression test for solidcitizen/pgvpd#13 — the admin API must not bind all
// interfaces by default. /status and /metrics are unauthenticated and reveal
// pool topology (databases, roles, bucket counts), so on a multi-homed host a
// 0.0.0.0 bind leaks the tenant/role namespace to anything that can route in.
//
// Default bind must be 127.0.0.1; PGVPD_ADMIN_HOST opts into wider exposure.
// The proof is direct: bind default, then try to reach the admin port over a
// non-loopback address of this host — refused when bound to 127.0.0.1, accepted
// when bound to 0.0.0.0. (Corroborated by the logged bind address.)
//
// Exit 0 (GREEN): default reachable on loopback, NOT on a non-loopback address,
//                 and PGVPD_ADMIN_HOST=0.0.0.0 re-opens it.
// Exit 2 (RED):   default reachable on a non-loopback address (pre-fix 0.0.0.0).
//
// Env: PGVPD_BIN (required). Needs no Postgres — the admin server is independent.
import { spawn } from 'node:child_process';
import net from 'node:net';
import os from 'node:os';

const BIN = process.env.PGVPD_BIN;
if (!BIN) { console.error('PGVPD_BIN required'); process.exit(3); }

const PROXY = 16462;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const stripAnsi = (s) => s.replace(/\x1b\[[0-9;]*m/g, '');

function nonLoopbackIPs() {
  const out = [];
  for (const addrs of Object.values(os.networkInterfaces()))
    for (const i of addrs) if (i.family === 'IPv4' && !i.internal) out.push(i.address);
  return out;
}
function boot(env) {
  const child = spawn(BIN, [], { env: { ...process.env,
    PGVPD_HOST: '127.0.0.1', PGVPD_PORT: String(PROXY),
    PGVPD_UPSTREAM_HOST: '127.0.0.1', PGVPD_UPSTREAM_PORT: '1',
    PGVPD_CONTEXT_VARIABLES: 'app.current_tenant_id', PGVPD_TENANT_SEPARATOR: '.',
    PGVPD_LOG_LEVEL: 'info', ...env },
    stdio: ['ignore', 'pipe', 'pipe'] });
  let logs = '';
  child.stdout.on('data', (d) => { logs += d.toString(); });
  child.stderr.on('data', (d) => { logs += d.toString(); });
  return { child, logs: () => logs };
}
function connectOk(host, port) {
  return new Promise((resolve) => {
    const s = new net.Socket();
    s.setTimeout(1200);
    s.once('connect', () => { s.destroy(); resolve(true); });
    s.once('timeout', () => { s.destroy(); resolve(false); });
    s.once('error', () => { s.destroy(); resolve(false); });
    s.connect(port, host);
  });
}
async function waitAdmin(logsFn, child, port) {
  for (let i = 0; i < 60; i++) {
    if (child.exitCode !== null) return null;
    if (await connectOk('127.0.0.1', port)) break;
    await sleep(100);
  }
  const line = stripAnsi(logsFn()).split('\n').find((l) => l.includes('admin API'));
  const m = line && line.match(/addr=([^\s]+)/);
  return m ? m[1] : null;
}
async function anyReachable(hosts, port) {
  for (const h of hosts) if (await connectOk(h, port)) return true;
  return false;
}

const lan = nonLoopbackIPs();
let code = 0;
try {
  // ── Phase 1: default bind ──────────────────────────────────────────────
  const ADMIN1 = 16463;
  const a = boot({ PGVPD_ADMIN_PORT: String(ADMIN1) });
  const addr1 = await waitAdmin(a.logs, a.child, ADMIN1);
  const loopbackReachable = await connectOk('127.0.0.1', ADMIN1);
  const lanReachable1 = await anyReachable(lan, ADMIN1);
  a.child.kill('SIGKILL'); await sleep(150);

  // ── Phase 2: explicit opt-in to wider exposure ─────────────────────────
  const ADMIN2 = 16464;
  const b = boot({ PGVPD_ADMIN_PORT: String(ADMIN2), PGVPD_ADMIN_HOST: '0.0.0.0' });
  const addr2 = await waitAdmin(b.logs, b.child, ADMIN2);
  const lanReachable2 = await anyReachable(lan, ADMIN2);
  b.child.kill('SIGKILL'); await sleep(150);

  const addrLoopback = addr1 === null ? true : addr1.startsWith('127.0.0.1:');
  const defaultSafe = loopbackReachable && !lanReachable1 && addrLoopback;
  const optInHonored = (addr2 !== null && addr2.startsWith('0.0.0.0:')) || lanReachable2;

  console.log(JSON.stringify({
    non_loopback_addrs: lan,
    default_bind_logged: addr1, default_reachable_loopback: loopbackReachable,
    default_reachable_non_loopback: lanReachable1, default_safe: defaultSafe,
    optin_bind_logged: addr2, optin_reachable_non_loopback: lanReachable2,
    optin_honored: optInHonored,
  }, null, 2));

  if (!defaultSafe || !optInHonored) code = 2;
} finally {
  await sleep(50);
}
process.exit(code);
