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
const recv = dgram.createSocket('udp4');
await new Promise(r => recv.bind(0, '127.0.0.1', r));
const pkts = [];
recv.on('message', m => {
  const cc = m[0] & 0x0f, xb = (m[0] & 0x10) >> 4;
  let off = 12 + cc * 4;
  let extlen = -1, profile = -1;
  if (xb && m.length >= off + 4) { profile = m.readUInt16BE(off); extlen = m.readUInt16BE(off + 2); off += 4 + extlen * 4; }
  pkts.push({ len: m.length, cc, xb, profile, extlen, off, payLen: m.length - off, p0: m[off] });
});
const tr = await req('createPlainRecv');
await req('connectPlain', {transportId: tr.transportId, ip:'127.0.0.1', port: recv.address().port});
await req('consumePlain', {transportId: tr.transportId, producerId: vp.producerId});
await new Promise(r => setTimeout(r, 2500));
const video = pkts.filter(p => p.payLen > 0);
const dropped = pkts.filter(p => p.payLen <= 0);
console.log(`total=${pkts.length} video=${video.length} noPayload=${dropped.length}`);
const extlens = {}; for (const p of pkts) extlens[p.profile + ':' + p.extlen] = (extlens[p.profile+':'+p.extlen] ?? 0) + 1;
console.log('ext profile:len counts', extlens);
// payload type distribution by first byte (nal type)
const nt = {}; for (const p of video) { const t = p.p0 & 0x1f; nt[t] = (nt[t] ?? 0) + 1; }
console.log('first-payload-byte nal types:', nt);
ws.close(); process.exit(0);
