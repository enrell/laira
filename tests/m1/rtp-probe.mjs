// Dumps per-packet RTP metadata from a PlainTransport consumer for ~3s.
// Usage: run `laira-desktop test-video` first, then `node tests/m1/rtp-probe.mjs`
import WebSocket from 'ws';
import dgram from 'node:dgram';
const ws = new WebSocket('ws://127.0.0.1:4443');
let id = 0; const pend = new Map();
const req = (m, p={}) => new Promise((res, rej) => { const i=++id; pend.set(i,{res,rej}); ws.send(JSON.stringify({id:i,method:m,params:p})); });
ws.on('message', d => { const m=JSON.parse(d); if(m.type==='event')return; const p=pend.get(m.id); pend.delete(m.id); m.ok?p.res(m.data):p.rej(new Error(m.error)); });
await new Promise(r => ws.on('open', r));
await req('join');
const { producers } = await req('listProducers');
const vp = producers.find(p => p.kind === 'video');
if (!vp) { console.error('no video producer'); process.exit(1) }

const recv = dgram.createSocket('udp4');
await new Promise(r => recv.bind(0, '127.0.0.1', r));
const rport = recv.address().port;
const pkts = [];
recv.on('message', m => {
  const cc = m[0] & 0x0f, xbit = m[0] & 0x10, pad = m[0] & 0x20;
  let off = 12 + cc * 4;
  if (xbit) off += 4 + m.readUInt16BE(off + 2) * 4;
  pkts.push({
    seq: m.readUInt16BE(2), ts: m.readUInt32BE(4), ssrc: m.readUInt32BE(8),
    m: m[1] >> 7, pt: m[1] & 0x7f, pad, xbit: xbit >> 4, cc,
    payLen: m.length - off, p0: m[off] ?? -1, p1: m[off + 1] ?? -1,
  });
});
const tr = await req('createPlainRecv');
await req('connectPlain', {transportId: tr.transportId, ip:'127.0.0.1', port: rport});
await req('consumePlain', {transportId: tr.transportId, producerId: vp.producerId});
await new Promise(r => setTimeout(r, 3000));

console.log(`pkts=${pkts.length}`);
// stats
const pts = new Map(); for (const p of pkts) pts.set(p.pt, (pts.get(p.pt) ?? 0) + 1);
const ssrcs = new Map(); for (const p of pkts) ssrcs.set(p.ssrc, (ssrcs.get(p.ssrc) ?? 0) + 1);
console.log('pts:', [...pts], 'ssrcs:', [...ssrcs], 'xbit pkts:', pkts.filter(p=>p.xbit).length, 'pad pkts:', pkts.filter(p=>p.pad).length);
let gaps = 0; for (let i = 1; i < pkts.length; i++) if (pkts[i].seq !== ((pkts[i-1].seq + 1) & 0xffff)) gaps++;
console.log('seq gaps:', gaps);
const tss = new Set(pkts.map(p => p.ts)); console.log('distinct ts:', tss.size);
// per-ts packet counts and how many have marker
const byTs = new Map();
for (const p of pkts) { const e = byTs.get(p.ts) ?? {n:0, m:0}; e.n++; e.m += p.m; byTs.set(p.ts, e); }
const arr = [...byTs.entries()].slice(-20);
for (const [ts, e] of arr) console.log(`ts=${ts} pkts=${e.n} markers=${e.m}`);
ws.close(); process.exit(0);
