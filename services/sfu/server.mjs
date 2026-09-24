// laira M0 SFU: mediasoup router + JSON/WS signaling.
// Ingest from the native client uses mediasoup PlainTransport (plain RTP over
// UDP, one transport per stream). Browser viewers use WebRtcTransport.
// Signaling message shapes live in crates/protocol (keep in sync).

import { createServer as createHttpServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { readFileSync, existsSync, statSync, createReadStream } from 'node:fs';
import { resolve, extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { WebSocketServer } from 'ws';
import * as mediasoup from 'mediasoup';

const env = process.env;
const config = {
  port: Number(env.LAIRA_SFU_PORT || 4443),
  host: env.LAIRA_SFU_HOST || '0.0.0.0',
  // Address told to clients for RTP (must be reachable by them).
  announcedIp: env.LAIRA_ANNOUNCED_IP || '127.0.0.1',
  rtcMinPort: Number(env.LAIRA_RTC_MIN_PORT || 40000),
  rtcMaxPort: Number(env.LAIRA_RTC_MAX_PORT || 49999),
  tlsCert: env.LAIRA_TLS_CERT || '',
  tlsKey: env.LAIRA_TLS_KEY || '',
  staticDir: env.LAIRA_STATIC_DIR ||
    resolve(fileURLToPath(new URL('.', import.meta.url)), '../../apps/web/dist'),
};

const MIME = {
  '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css',
  '.json': 'application/json', '.map': 'application/json',
  '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
  '.webmanifest': 'application/manifest+json',
};

const mediaCodecs = [
  { kind: 'audio', mimeType: 'audio/opus', clockRate: 48000, channels: 2 },
  { kind: 'video', mimeType: 'video/VP8', clockRate: 90000 },
  {
    kind: 'video', mimeType: 'video/H264', clockRate: 90000,
    parameters: {
      'packetization-mode': 1,
      'profile-level-id': '42e01f',
      'level-asymmetry-allowed': 1,
    },
  },
];

const worker = await mediasoup.createWorker({
  rtcMinPort: config.rtcMinPort,
  rtcMaxPort: config.rtcMaxPort,
  logLevel: 'warn',
});
worker.on('died', (err) => {
  console.error('mediasoup worker died:', err);
  process.exit(1);
});

const router = await worker.createRouter({ mediaCodecs });

// peerId -> { transports: Map, producers: Map, consumers: Map }
const peers = new Map();
// producerId -> { peerId, kind, appData }
const producerIndex = new Map();

function serveStatic(req, res) {
  const url = new URL(req.url, 'http://x');
  if (url.pathname === '/healthz') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, peers: peers.size, producers: producerIndex.size }));
    return;
  }
  let path = normalize(url.pathname === '/' ? '/index.html' : url.pathname);
  const file = join(config.staticDir, path);
  if (!file.startsWith(config.staticDir) || !existsSync(file) || !statSync(file).isFile()) {
    res.writeHead(404); res.end('not found'); return;
  }
  res.writeHead(200, { 'content-type': MIME[extname(file)] || 'application/octet-stream' });
  createReadStream(file).pipe(res);
}

const server = config.tlsCert && config.tlsKey
  ? createHttpsServer({ cert: readFileSync(config.tlsCert), key: readFileSync(config.tlsKey) }, serveStatic)
  : createHttpServer(serveStatic);

const wss = new WebSocketServer({ server });

function broadcast(event, data, except) {
  const msg = JSON.stringify({ type: 'event', event, data });
  for (const peer of peers.values()) {
    if (peer.socket !== except && peer.socket.readyState === 1) peer.socket.send(msg);
  }
}

function listenInfo(ip = '0.0.0.0') {
  return { protocol: 'udp', ip, announcedAddress: config.announcedIp };
}

const handlers = {
  async join(peer, params, socket) {
    peer.socket = socket;
    return {
      peerId: peer.id,
      rtpCapabilities: router.rtpCapabilities,
      producers: [...producerIndex.entries()].map(([producerId, p]) => (
        { producerId, kind: p.kind, appData: p.appData || {}, peerId: p.peerId })),
    };
  },

  async createSendTransport(peer) {
    const t = await router.createWebRtcTransport({
      listenInfos: [listenInfo(), { ...listenInfo(), protocol: 'tcp' }],
      enableUdp: true, enableTcp: true, preferUdp: true,
      initialAvailableOutgoingBitrate: 4_000_000,
    });
    peer.transports.set(t.id, t);
    t.on('dtlsstatechange', (s) => { if (s === 'closed') t.close(); });
    return {
      transportId: t.id,
      iceParameters: t.iceParameters,
      iceCandidates: t.iceCandidates,
      dtlsParameters: t.dtlsParameters,
    };
  },

  async createRecvTransport(peer) { return handlers.createSendTransport(peer); },

  async connect(peer, { transportId, dtlsParameters }) {
    await peer.transports.get(transportId).connect({ dtlsParameters });
    return {};
  },

  async produce(peer, { transportId, kind, rtpParameters, appData }) {
    const producer = await peer.transports.get(transportId).produce({ kind, rtpParameters, appData });
    registerProducer(peer, producer, appData);
    return { producerId: producer.id };
  },

  async consume(peer, { transportId, producerId, rtpCapabilities }) {
    const t = peer.transports.get(transportId);
    if (!router.canConsume({ producerId, rtpCapabilities })) {
      throw new Error(`cannot consume ${producerId}`);
    }
    const consumer = await t.consume({ producerId, rtpCapabilities, paused: true });
    peer.consumers.set(consumer.id, consumer);
    consumer.on('transportclose', () => peer.consumers.delete(consumer.id));
    return { consumerId: consumer.id, producerId, kind: consumer.kind, rtpParameters: consumer.rtpParameters };
  },

  async resumeConsumer(peer, { consumerId }) {
    await peer.consumers.get(consumerId).resume();
    return {};
  },

  async pauseProducer(peer, { producerId }) {
    await peer.producers.get(producerId).pause();
    return {};
  },

  async resumeProducer(peer, { producerId }) {
    await peer.producers.get(producerId).resume();
    return {};
  },

  // ---- native client plain-RTP ingest ----

  async createPlainSend(peer) {
    const t = await router.createPlainTransport({
      listenInfo: listenInfo(),
      rtcpMux: true,
      comedia: true,
      enableSctp: false, enableSrtp: false,
    });
    peer.transports.set(t.id, t);
    return {
      transportId: t.id,
      ip: config.announcedIp,
      port: t.tuple.localPort,
    };
  },

  async producePlain(peer, { transportId, kind, rtpParameters, appData }) {
    const producer = await peer.transports.get(transportId).produce({ kind, rtpParameters, appData });
    registerProducer(peer, producer, appData);
    return { producerId: producer.id };
  },

  // ---- native client plain-RTP receive (mediasoup -> our udpsrc) ----

  async createPlainRecv(peer) {
    const t = await router.createPlainTransport({
      listenInfo: listenInfo(),
      rtcpMux: true,
      comedia: false,
      enableSctp: false, enableSrtp: false,
    });
    peer.transports.set(t.id, t);
    return { transportId: t.id };
  },

  async connectPlain(peer, { transportId, ip, port }) {
    await peer.transports.get(transportId).connect({ ip, port });
    return {};
  },

  async consumePlain(peer, { transportId, producerId }) {
    const t = peer.transports.get(transportId);
    const consumer = await t.consume({
      producerId,
      rtpCapabilities: router.rtpCapabilities,
      paused: true,
    });
    peer.consumers.set(consumer.id, consumer);
    consumer.on('transportclose', () => peer.consumers.delete(consumer.id));
    await consumer.resume();
    return { consumerId: consumer.id, producerId, kind: consumer.kind, rtpParameters: consumer.rtpParameters };
  },

  async producerStats(_peer, { producerId }) {
    const p = producerIndex.get(producerId);
    if (!p) throw new Error('unknown producer');
    return { stats: await p.producer.getStats() };
  },

  async listProducers() {
    return {
      producers: [...producerIndex.entries()].map(([producerId, p]) => (
        { producerId, kind: p.kind, appData: p.appData || {}, peerId: p.peerId })),
    };
  },
};

function registerProducer(peer, producer, appData) {
  peer.producers.set(producer.id, producer);
  producerIndex.set(producer.id, {
    peerId: peer.id, kind: producer.kind, appData, producer,
  });
  producer.on('transportclose', () => unregisterProducer(peer, producer.id));
  producer.observer.on('close', () => unregisterProducer(peer, producer.id));
  broadcast('newProducer', {
    producerId: producer.id, kind: producer.kind, appData: appData || {}, peerId: peer.id,
  });
}

function unregisterProducer(peer, producerId) {
  if (!producerIndex.delete(producerId)) return;
  peer.producers.delete(producerId);
  broadcast('producerClosed', { producerId });
}

wss.on('connection', (socket) => {
  const peer = {
    id: crypto.randomUUID(),
    socket,
    transports: new Map(),
    producers: new Map(),
    consumers: new Map(),
  };
  peers.set(peer.id, peer);
  console.log(`peer connected: ${peer.id}`);

  socket.on('message', async (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    const { id, method, params = {} } = msg;
    const handler = handlers[method];
    const reply = (data) => socket.send(JSON.stringify({ id, ok: true, data }));
    const fail = (error) =>
      socket.send(JSON.stringify({ id, ok: false, error: String(error?.message || error) }));
    if (!handler) return fail(`unknown method ${method}`);
    try { reply(await handler(peer, params, socket)); }
    catch (e) { fail(e); }
  });

  socket.on('close', () => {
    peers.delete(peer.id);
    for (const t of peer.transports.values()) t.close();
    for (const producerId of [...peer.producers.keys()]) unregisterProducer(peer, producerId);
    console.log(`peer left: ${peer.id}`);
  });
});

// Periodic per-producer bitrate log for M0 measurements (MED-02/goal metrics).
setInterval(async () => {
  for (const [id, p] of producerIndex) {
    try {
      const stats = await p.producer.getStats();
      const bytes = stats.reduce((s, x) => s + (x.byteCount || 0), 0);
      const prev = p._bytes || 0;
      p._bytes = bytes;
      const kbps = ((bytes - prev) * 8 / 5000 / 1000).toFixed(0);
      console.log(`stat producer=${id.slice(0, 8)} peer=${p.peerId.slice(0, 8)} kind=${p.kind} bitrate=${kbps}kbps`);
    } catch { /* producer closing */ }
  }
}, 5000).unref();

server.listen(config.port, config.host, () => {
  const scheme = config.tlsCert ? 'https' : 'http';
  console.log(`laira-sfu listening on ${scheme}://${config.host}:${config.port}`);
  console.log(`rtp announced=${config.announcedIp} ports=${config.rtcMinPort}-${config.rtcMaxPort}`);
  console.log(`static dir: ${config.staticDir} (${existsSync(config.staticDir) ? 'found' : 'MISSING — build apps/web'})`);
});
