// Black-hole TCP server for the slot-leak regression test (issue #20).
// Accepts connections and holds them open without ever responding, so a pgvpd
// upstream connection through it never completes its startup and the
// per-connection handshake timeout cancels the checkout mid-reservation.
import net from 'node:net';
const port = +(process.argv[2] || 15999);
const held = [];
const server = net.createServer((sock) => { held.push(sock); sock.on('data', () => {}); sock.on('error', () => {}); });
server.listen(port, '127.0.0.1', () => console.log(`blackhole listening on 127.0.0.1:${port}`));
process.on('SIGTERM', () => process.exit(0));
process.on('SIGINT', () => process.exit(0));
