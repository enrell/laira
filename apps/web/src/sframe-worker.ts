// SFrame (RFC 9605, AES_128_GCM_SHA256_128) transform worker for
// RTCRtpScriptTransform — decrypts encoded frames on receivers, encrypts on
// senders. Mirrors crates/media/src/sframe.rs exactly:
//   key  = HKDF-SHA256(base, salt="SFrame 1.0", info="key")  -> 16B
//   salt = HKDF-SHA256(base, salt="SFrame 1.0", info="salt") -> 12B
//   wire = cfg((kid<<4)|3) || ctr4BE || ct || tag(16)
//   nonce = salt XOR ctr12 ; aad = header bytes
//
// Keys: per-sender, derived from the community epoch (see laira.ts).

const te = new TextEncoder();

// Per-sender keys arrive from the page (derived from the community epoch);
// nothing is hardcoded. `previous` keeps the outgoing epoch until the page
// clears it so frames in flight across a rekey still decode.
interface Ctx { key: CryptoKey; salt: Uint8Array }
let current = new Map<number, Ctx>();
let previous = new Map<number, Ctx>();
let sendKid = 0;
let sendCtx: Ctx | undefined;
const sendCtr = { c: 0 };

async function derive(baseKey: Uint8Array): Promise<Ctx> {
  const ikm = await crypto.subtle.importKey('raw', baseKey as BufferSource, 'HKDF', false, ['deriveBits']);
  const keyBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: te.encode('SFrame 1.0'), info: te.encode('key') }, ikm, 128);
  const saltBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: te.encode('SFrame 1.0'), info: te.encode('salt') }, ikm, 96);
  const key = await crypto.subtle.importKey('raw', keyBits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  return { key, salt: new Uint8Array(saltBits) };
}

function nonceFor(salt: Uint8Array, ctr: bigint | number): Uint8Array {
  const n = new Uint8Array(salt);
  let c = BigInt(ctr);
  for (let i = 11; i >= 4 && c > 0n; i--) { n[i] ^= Number(c & 0xffn); c >>= 8n; }
  return n;
}

// Page -> worker: {type:'keys', kid, senders:[[kid, base]]} rotates to a new
// epoch; {type:'forget-previous'} ends the grace period.
self.addEventListener('message', async (e: MessageEvent) => {
  const m = e.data;
  if (m?.type === 'keys') {
    const next = new Map<number, Ctx>();
    for (const [kid, base] of m.senders as [number, Uint8Array][]) next.set(kid, await derive(base));
    previous = current;
    current = next;
    sendKid = m.kid;
    sendCtx = next.get(m.kid);
    sendCtr.c = 0; // new key, fresh counter
  } else if (m?.type === 'forget-previous') {
    previous = new Map();
  }
});

let loggedFormat = false;
let loggedPlain = false;
function logFormat(tag: string, data: ArrayBuffer | Uint8Array) {
  if (loggedFormat) return;
  loggedFormat = true;
  const b = new Uint8Array(data instanceof ArrayBuffer ? data : data.buffer, 0, 16);
  const hex = [...b.slice(0, 16)].map(x => x.toString(16).padStart(2, '0')).join(' ');
  console.log(`[sframe] ${tag} first16: ${hex}`);
}

// frame.data is Annex-B (per W3C encoded-transform: "NAL units separated by
// Annex B start codes"). Split into units: {startLen, bytes} where bytes is
// the NAL content without the start code.
function annexBUnits(data: Uint8Array): { raw: Uint8Array; nal: Uint8Array }[] {
  const starts: { off: number; len: number }[] = [];
  for (let i = 0; i + 3 <= data.length; i++) {
    if (data[i] === 0 && data[i + 1] === 0) {
      if (data[i + 2] === 1) { starts.push({ off: i, len: 3 }); i += 2; }
      else if (data[i + 2] === 0 && i + 3 < data.length && data[i + 3] === 1) { starts.push({ off: i, len: 4 }); i += 3; }
    }
  }
  return starts.map((s, i) => ({
    raw: data.slice(s.off, i + 1 < starts.length ? starts[i + 1].off : data.length),
    nal: data.slice(s.off + s.len, i + 1 < starts.length ? starts[i + 1].off : data.length),
  }));
}

// Wire format v2 (crates/media/src/wire.rs): blob = slice-typed NAL (1 or 5)
// whose unescaped payload is PREFIX || sframe || 0x80.
const PREFIX = [0x88, 0x80, 0x4c, 0x32];

function unescape(d: Uint8Array): Uint8Array {
  const out: number[] = [];
  let zeros = 0;
  for (const b of d) {
    if (zeros >= 2 && b === 3) { zeros = 0; continue; }
    out.push(b);
    zeros = b === 0 ? zeros + 1 : 0;
  }
  return Uint8Array.from(out);
}

/** SFrame buffer inside a blob NAL, or undefined if this NAL isn't one. */
function blobPayload(nal: Uint8Array): Uint8Array | undefined {
  const t = nal[0] & 0x1f;
  if (t !== 1 && t !== 5) return undefined;
  const body = unescape(nal.subarray(1));
  if (body.length < PREFIX.length + 22 || body[body.length - 1] !== 0x80) return undefined;
  if (!PREFIX.every((v, i) => body[i] === v)) return undefined;
  return body.slice(PREFIX.length, body.length - 1);
}

/** Audio: the whole Opus payload is the SFrame buffer (crates/media/src/rtp_relay.rs). */
async function decryptAudio(frame: RTCEncodedAudioFrame) {
  const blob = new Uint8Array(frame.data);
  const cfg = blob[0];
  const ctrLen = (cfg & 0x0f) + 1;
  let ctr = 0;
  for (let i = 0; i < ctrLen; i++) ctr = ctr * 256 + blob[1 + i];
  const kid = (cfg >> 4) & 0x07;
  const aad = blob.slice(0, 1 + ctrLen);
  const attempt = (ctx: Ctx | undefined) => {
    if (!ctx) throw new Error(`no key for kid ${kid}`);
    return crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonceFor(ctx.salt, ctr) as BufferSource, additionalData: aad as BufferSource, tagLength: 128 },
      ctx.key, blob.slice(1 + ctrLen) as BufferSource);
  };
  let pt: ArrayBuffer;
  try { pt = await attempt(current.get(kid)); }
  catch (err) { pt = await attempt(previous.get(kid)).catch(() => { throw err; }); }
  frame.data = pt;
  return frame;
}

async function decryptFrame(frame: RTCEncodedVideoFrame | RTCEncodedAudioFrame) {
  const data = new Uint8Array(frame.data);
  const units = annexBUnits(data);
  // Encrypted AUs arrive as [SPS decoy][SEI-typed 0x66 + sframe blob]; the SPS
  // decoy exists to pass the SFU's keyframe gate. Plaintext frames have no
  // 0x66 unit -> passthrough.
  const blobs = units.map((u) => blobPayload(u.nal));
  if (!blobs.some(Boolean)) {
    if (!loggedFormat) {
      loggedFormat = true;
      const hex = [...data.slice(0, 32)].map(x => x.toString(16).padStart(2, '0')).join(' ');
      (self as any).postMessage({ sframeFormat: `passthrough first32: ${hex}` });
    }
    return frame;
  }
  logFormat('rx-wire', data);
  const out: Uint8Array[] = [];
  for (const blob of blobs) {
    if (!blob) continue; // real SPS/PPS ahead of the blob: the plaintext AU repeats them
    const cfg = blob[0];
    const ctrLen = (cfg & 0x0f) + 1;
    let ctr = 0;
    for (let i = 0; i < ctrLen; i++) ctr = ctr * 256 + blob[1 + i];
    const kid = (cfg >> 4) & 0x07;
    const aad = blob.slice(0, 1 + ctrLen);
    const attempt = async (ctx: Ctx | undefined) => {
      if (!ctx) throw new Error(`no key for kid ${kid}`);
      return crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonceFor(ctx.salt, ctr) as BufferSource, additionalData: aad as BufferSource, tagLength: 128 },
        ctx.key, blob.slice(1 + ctrLen) as BufferSource);
    };
    let pt: ArrayBuffer;
    try { pt = await attempt(current.get(kid)); }
    catch (err) { pt = await attempt(previous.get(kid)).catch(() => { throw err; }); }
    out.push(new Uint8Array(pt)); // plaintext is already Annex-B
  }
  const total = out.reduce((s, b) => s + b.length, 0);
  const res = new Uint8Array(total);
  let o = 0;
  for (const b of out) { res.set(b, o); o += b.length; }
  if (!loggedPlain) {
    loggedPlain = true;
    const hex = [...res.slice(0, 32)].map(x => x.toString(16).padStart(2, '0')).join(' ');
    (self as any).postMessage({ sframeFormat: `decrypted first32: ${hex}` });
  }
  frame.data = res.buffer;
  return frame;
}

async function encryptFrame(frame: RTCEncodedVideoFrame | RTCEncodedAudioFrame) {
  if (!sendCtx) throw new Error('no send key');
  const data = new Uint8Array(frame.data);
  const ctr = sendCtr.c++;
  const header = new Uint8Array(1 + 4);
  header[0] = (sendKid << 4) | 0x03;
  new DataView(header.buffer).setUint32(1, ctr >>> 0);
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonceFor(sendCtx.salt, ctr) as BufferSource, additionalData: header as BufferSource, tagLength: 128 },
    sendCtx.key, data as BufferSource));
  const out = new Uint8Array(header.length + ct.length);
  out.set(header); out.set(ct, header.length);
  frame.data = out.buffer;
  return frame;
}

// The transform runs in a dedicated worker context (RTCRtpScriptTransform).
const stats = { ok: 0, dropped: 0, firstErr: '' };
setInterval(() => {
  if (stats.ok || stats.dropped) (self as any).postMessage({ sframe: stats });
}, 2000);

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(self as any).onrtctransform = (event: any) => {
  const transformer = event.transformer;
  const mode = transformer.options?.mode || 'decrypt';
  const kind = transformer.options?.kind || 'video';
  transformer.readable
    .pipeThrough(new TransformStream({
      async transform(frame, controller) {
        try {
          if (mode === 'encrypt') controller.enqueue(await encryptFrame(frame));
          else if (kind === 'audio') controller.enqueue(await decryptAudio(frame as RTCEncodedAudioFrame));
          else controller.enqueue(await decryptFrame(frame));
          stats.ok++;
        } catch (e) {
          // Drop undecryptable frames — wrong key or non-SFrame sender.
          stats.dropped++;
          if (!stats.firstErr) stats.firstErr = String(e);
        }
      },
    }))
    .pipeTo(transformer.writable)
    .catch((e: any) => (self as any).postMessage({ sframeFormat: `transform pipe error ${e}` }));
};
