import WebSocket from 'ws';
const ws = new WebSocket('ws://127.0.0.1:4443');
let id=0; const pend=new Map();
const req=(m,p={})=>new Promise((res,rej)=>{const i=++id;pend.set(i,{res,rej});ws.send(JSON.stringify({id:i,method:m,params:p}))});
ws.on('message',d=>{const m=JSON.parse(d);if(m.type==='event')return;const p=pend.get(m.id);pend.delete(m.id);m.ok?p.res(m.data):p.rej(new Error(m.error))});
await new Promise(r=>ws.on('open',r));
const { producers } = (await req('listProducers'));
for (const p of producers) {
  const a = await req('producerStats',{producerId:p.producerId});
  await new Promise(r=>setTimeout(r,1500));
  const b = await req('producerStats',{producerId:p.producerId});
  const ba=a.stats.reduce((s,x)=>s+(x.byteCount||0),0), bb=b.stats.reduce((s,x)=>s+(x.byteCount||0),0);
  console.log(p.kind, p.appData?.stream, 'bytes delta/1.5s:', bb-ba, '| pkts:', b.stats[0]?.packetCount);
}
process.exit(0);
