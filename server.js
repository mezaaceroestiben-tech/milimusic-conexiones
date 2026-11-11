// miliMusic - Servidor de conexiones a distancia (sin dependencias, Node 18 o más nuevo).
// Hace de "buzón" entre dos dispositivos con miliMusic: vincula con un código de 6 cifras y reenvía los mensajes.
// Los mensajes llevan una firma que solo conocen los dos dispositivos, así que este servidor no puede falsificarlos.
// Licencia: GPL-3.0

'use strict';
const http = require('http');
const crypto = require('crypto');

const PORT = process.env.PORT || 8080;
const MAX_FRAME = 64 * 1024;
const MAX_BODY = 8 * 1024;
const CODE_TTL_MS = 5 * 60 * 1000;
const PING_MS = 30 * 1000;

const clients = new Map(); // id -> { ws, id, name, keyHash, ip, alive, sent: [] }
const keyHashes = new Map(); // id -> hash de su clave (mientras el servidor esté encendido)
const codes = new Map(); // código -> { id, name, exp }
const ipHits = new Map(); // ip -> [instantes]

function sha(s) { return crypto.createHash('sha256').update(String(s)).digest('hex'); }

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end('miliMusic conexiones: en línea. Dispositivos conectados: ' + clients.size + '\n');
});

// ---- WebSocket mínimo (RFC 6455): solo texto, con tope de tamaño ----
function frame(opcode, payload) {
  const data = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, 'utf8');
  let head;
  if (data.length < 126) { head = Buffer.from([0x80 | opcode, data.length]); }
  else if (data.length < 65536) { head = Buffer.alloc(4); head[0] = 0x80 | opcode; head[1] = 126; head.writeUInt16BE(data.length, 2); }
  else { head = Buffer.alloc(10); head[0] = 0x80 | opcode; head[1] = 127; head.writeBigUInt64BE(BigInt(data.length), 2); }
  return Buffer.concat([head, data]);
}

class Conn {
  constructor(socket, ip) {
    this.socket = socket; this.ip = ip; this.buf = Buffer.alloc(0); this.parts = []; this.partsLen = 0;
    this.id = null; this.name = ''; this.alive = true; this.failures = 0; this.recent = [];
    socket.on('data', (d) => this.onData(d));
    socket.on('close', () => this.onClose());
    socket.on('error', () => { try { socket.destroy(); } catch (e) { /* nada */ } });
    socket.setNoDelay(true);
  }
  send(obj) { if (!this.socket.destroyed) this.socket.write(frame(0x1, JSON.stringify(obj))); }
  close(code) {
    try { const b = Buffer.alloc(2); b.writeUInt16BE(code || 1000); this.socket.write(frame(0x8, b)); } catch (e) { /* nada */ }
    try { this.socket.end(); } catch (e) { /* nada */ }
  }
  onClose() {
    const c = this.id && clients.get(this.id);
    if (c === this) clients.delete(this.id);
    for (const [code, v] of codes) if (v.id === this.id && c === this) codes.delete(code);
  }
  onData(chunk) {
    this.buf = Buffer.concat([this.buf, chunk]);
    for (;;) {
      if (this.buf.length < 2) return;
      const b0 = this.buf[0], b1 = this.buf[1];
      const fin = (b0 & 0x80) !== 0, opcode = b0 & 0x0f, masked = (b1 & 0x80) !== 0;
      let len = b1 & 0x7f, off = 2;
      if (len === 126) { if (this.buf.length < 4) return; len = this.buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (this.buf.length < 10) return; len = Number(this.buf.readBigUInt64BE(2)); off = 10; }
      if (!masked || len > MAX_FRAME) { this.close(1009); this.socket.destroy(); return; }
      if (this.buf.length < off + 4 + len) return;
      const mask = this.buf.subarray(off, off + 4);
      const data = Buffer.from(this.buf.subarray(off + 4, off + 4 + len));
      for (let i = 0; i < data.length; i++) data[i] ^= mask[i % 4];
      this.buf = this.buf.subarray(off + 4 + len);
      if (opcode === 0x8) { this.close(1000); return; }
      if (opcode === 0x9) { this.socket.write(frame(0xA, data)); continue; }
      if (opcode === 0xA) { this.alive = true; continue; }
      if (opcode === 0x1 || opcode === 0x0) {
        this.parts.push(data); this.partsLen += data.length;
        if (this.partsLen > MAX_FRAME) { this.close(1009); this.socket.destroy(); return; }
        if (fin) {
          const text = Buffer.concat(this.parts).toString('utf8');
          this.parts = []; this.partsLen = 0;
          this.onMessage(text);
        }
      }
    }
  }
  limited() {
    const now = Date.now();
    this.recent = this.recent.filter((t) => now - t < 10000);
    this.recent.push(now);
    return this.recent.length > 40;
  }
  onMessage(text) {
    let m; try { m = JSON.parse(text); } catch (e) { return; }
    if (!m || typeof m !== 'object') return;
    if (this.limited()) { this.send({ t: 'error', code: 'slow_down' }); return; }
    switch (m.t) {
      case 'hello': return this.hello(m);
      case 'ping': return this.send({ t: 'pong' });
      case 'pair_open': return this.pairOpen();
      case 'pair_join': return this.pairJoin(m);
      case 'msg': return this.forward(m);
      default: return;
    }
  }
  hello(m) {
    const id = String(m.id || ''), key = String(m.key || '');
    if (!/^[0-9a-f]{16}$/.test(id) || key.length < 16 || key.length > 128) { this.send({ t: 'error', code: 'bad_hello' }); this.close(1008); return; }
    const h = sha(key);
    const known = keyHashes.get(id);
    if (known && known !== h) { this.send({ t: 'error', code: 'id_taken' }); this.close(1008); return; }
    keyHashes.set(id, h);
    const old = clients.get(id);
    if (old && old !== this) { old.id = null; old.close(1000); }
    this.id = id; this.name = String(m.name || '').slice(0, 40);
    clients.set(id, this);
    this.send({ t: 'hello_ok' });
  }
  pairOpen() {
    if (!this.id) return this.send({ t: 'error', code: 'no_hello' });
    for (const [code, v] of codes) if (v.id === this.id) codes.delete(code);
    let code; do { code = String(crypto.randomInt(0, 1000000)).padStart(6, '0'); } while (codes.has(code));
    codes.set(code, { id: this.id, name: this.name, exp: Date.now() + CODE_TTL_MS });
    this.send({ t: 'pair_code', code, ttl: CODE_TTL_MS / 1000 });
  }
  pairJoin(m) {
    if (!this.id) return this.send({ t: 'error', code: 'no_hello' });
    const now = Date.now();
    const hits = (ipHits.get(this.ip) || []).filter((t) => now - t < 60000);
    hits.push(now); ipHits.set(this.ip, hits);
    if (hits.length > 20) return this.send({ t: 'pair_fail', code: 'too_many' });
    const entry = codes.get(String(m.code || ''));
    const target = entry && entry.id !== this.id && entry.exp > now ? clients.get(entry.id) : null;
    if (!target) {
      this.failures++;
      this.send({ t: 'pair_fail', code: 'bad_code' });
      if (this.failures >= 5) this.close(1008);
      return;
    }
    codes.delete(String(m.code));
    const secret = crypto.randomBytes(32).toString('hex');
    const joinerName = String(m.name || this.name || '').slice(0, 40);
    this.send({ t: 'paired', peerId: target.id, peerName: target.name, secret });
    target.send({ t: 'paired', peerId: this.id, peerName: joinerName, secret });
  }
  forward(m) {
    if (!this.id) return this.send({ t: 'error', code: 'no_hello' });
    const to = String(m.to || ''), body = String(m.body || '');
    if (body.length > MAX_BODY) return this.send({ t: 'error', code: 'too_big' });
    const target = clients.get(to);
    if (!target) return this.send({ t: 'offline', to, nonce: String(m.nonce || '') });
    target.send({ t: 'msg', from: this.id, to, ts: m.ts, nonce: String(m.nonce || ''), body, mac: String(m.mac || '') });
  }
}

server.on('upgrade', (req, socket) => {
  const url = (req.url || '').split('?')[0];
  const key = req.headers['sec-websocket-key'];
  if (url !== '/link' || !key || String(req.headers.upgrade || '').toLowerCase() !== 'websocket') {
    socket.write('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n'); socket.destroy(); return;
  }
  const accept = crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n');
  const ip = String(req.headers['x-forwarded-for'] || socket.remoteAddress || '').split(',')[0].trim();
  const conn = new Conn(socket, ip);
  conn.pingTimer = null;
  socket.on('close', () => { if (conn.pingTimer) clearInterval(conn.pingTimer); });
  conn.pingTimer = setInterval(() => {
    if (!conn.alive) { socket.destroy(); return; }
    conn.alive = false;
    try { socket.write(frame(0x9, Buffer.alloc(0))); } catch (e) { /* nada */ }
  }, PING_MS);
});

setInterval(() => { const now = Date.now(); for (const [c, v] of codes) if (v.exp < now) codes.delete(c); }, 60000).unref();

if (require.main === module) {
  server.listen(PORT, () => console.log('miliMusic conexiones escuchando en el puerto ' + PORT));
}
module.exports = { server };
