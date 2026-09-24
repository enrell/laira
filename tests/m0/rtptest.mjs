import WebSocket from 'ws';
import dgram from 'node:dgram';
const ws = new WebSocket('ws://127.0.0.1:4443');
let id = 0; const pend = new Map();
const req = (m, p={}) => new Promise((res, rej) => { const i=++id; pend.set(i,{res,rej}); ws.send(JSON.stringify({id:i,method:m,params:p})); });
ws.on('message', d => { const m=JSON.parse(d); if(m.type==='event')return; const p=pend.get(m.id); pend.delete(m.id); m.ok?p.res(m.data):p.rej(new Error(m.error)); });
await new Promise(r => ws.on('open', r));
await req('join');

// fake audio producer on plain transport
const SSRC = 0x00c0ffee, PT = 111;
const ts = await req('createPlainSend');
const { producerId } = await req('producePlain', {transportId: ts.transportId, kind:'audio',
  rtpParameters: { mid:'1', codecs:[{mimeType:'audio/opus',payloadType:PT,clockRate:48000,channels:2}],
    encodings:[{ssrc:SSRC}], headerExtensions:[], rtcp:{cname:'t',reducedSize:true,mux:true} },
  appData:{stream:'mic'}});

// consumer -> local udp port
const recv = dgram.createSocket('udp4');
await new Promise(r => recv.bind(0, '127.0.0.1', r));
const rport = recv.address().port;
let got = 0, bytes = 0, firstSsrc = null;
recv.on('message', m => { got++; bytes += m.length; if (firstSsrc===null) firstSsrc = m.readUInt32BE(8); });
const tr = await req('createPlainRecv');
await req('connectPlain', {transportId: tr.transportId, ip:'127.0.0.1', port: rport});
const c = await req('consumePlain', {transportId: tr.transportId, producerId});
console.log(`consumer: pt=${c.rtpParameters.codecs[0].payloadType} ssrc=${c.rtpParameters.encodings[0].ssrc} -> udp:${rport}`);

// send 100 fake RTP packets (20ms cadence)
const send = dgram.createSocket('udp4');
let seq = 1000, ts0 = 160;
const pkt = () => { const b = Buffer.alloc(12+160);
  b[0]=0x80; b[1]=PT; b.writeUInt16BE(seq++,2); b.writeUInt32BE(ts0,4); ts0+=960; b.writeUInt32BE(SSRC,8); return b; };
for (let i=0;i<100;i++){ send.send(pkt(), ts.port, ts.ip); await new Promise(r=>setTimeout(r,20)); }
await new Promise(r=>setTimeout(r,400));
console.log(`sent=100 received=${got} bytes=${bytes} ssrc_on_wire=0x${firstSsrc?.toString(16)}`);
const st = await req('producerStats',{producerId});
console.log('producerStats byteCount:', JSON.stringify(st.stats.map(s=>s.byteCount)));
console.log(got >= 95 ? 'RTP FORWARDING OK' : 'FORWARDING BROKEN');
ws.close(); process.exit(got>=95?0:1);
