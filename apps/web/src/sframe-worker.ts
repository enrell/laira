// SFrame (RFC 9605, AES_128_GCM_SHA256_128) transform worker for
// RTCRtpScriptTransform — decrypts encoded frames on receivers, encrypts on
// senders. Mirrors crates/media/src/sframe.rs exactly:
//   key  = HKDF-SHA256(base, salt="SFrame 1.0", info="key")  -> 16B
//   salt = HKDF-SHA256(base, salt="SFrame 1.0", info="salt") -> 12B
//   wire = cfg(0x03: kid=0, ctr_len=4) || ctr4BE || ct || tag(16)
//   nonce = salt XOR ctr12 ; aad = header bytes
//
// M1 test vector: fixed base key, same as TEST_BASE_KEY in Rust.

const te = new TextEncoder();
const BASE_KEY = te.encode('laira-m0-sframe!'); // 16 bytes — test vector only

async function derive(baseKey: Uint8Array) {
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

// Our encrypted blob marker: SEI NAL (0x66) carrying cfg byte 0x03.
const isBlob = (nal: Uint8Array) => nal.length > 6 && nal[0] === 0x66 && nal[1] === 0x03;

async function decryptFrame(frame: RTCEncodedVideoFrame | RTCEncodedAudioFrame, ctx: Awaited<ReturnType<typeof derive>>) {
  const data = new Uint8Array(frame.data);
  const units = annexBUnits(data);
  // Encrypted AUs arrive as [SPS decoy][SEI-typed 0x66 + sframe blob]; the SPS
  // decoy exists to pass the SFU's keyframe gate. Plaintext frames have no
  // 0x66 unit -> passthrough.
  if (!units.some(u => isBlob(u.nal))) {
    if (!loggedFormat) {
      loggedFormat = true;
      const hex = [...data.slice(0, 32)].map(x => x.toString(16).padStart(2, '0')).join(' ');
      (self as any).postMessage({ sframeFormat: `passthrough first32: ${hex}` });
    }
    return frame;
  }
  logFormat('rx-wire', data);
  const out: Uint8Array[] = [];
  for (const u of units) {
    if (!isBlob(u.nal)) { out.push(u.raw); continue } // SPS decoy & friends pass through
    const blob = u.nal.slice(1);
    const cfg = blob[0];
    const ctrLen = (cfg & 0x0f) + 1;
    let ctr = 0;
    for (let i = 0; i < ctrLen; i++) ctr = ctr * 256 + blob[1 + i];
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonceFor(ctx.salt, ctr) as BufferSource, additionalData: blob.slice(0, 1 + ctrLen) as BufferSource, tagLength: 128 },
      ctx.key, blob.slice(1 + ctrLen) as BufferSource);
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

async function encryptFrame(frame: RTCEncodedVideoFrame | RTCEncodedAudioFrame, ctx: Awaited<ReturnType<typeof derive>>, ctrBox: { c: number }) {
  const data = new Uint8Array(frame.data);
  const ctr = ctrBox.c++;
  const header = new Uint8Array(1 + 4);
  header[0] = 0x03;
  new DataView(header.buffer).setUint32(1, ctr >>> 0);
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonceFor(ctx.salt, ctr) as BufferSource, additionalData: header as BufferSource, tagLength: 128 },
    ctx.key, data as BufferSource));
  const out = new Uint8Array(header.length + ct.length);
  out.set(header); out.set(ct, header.length);
  frame.data = out.buffer;
  return frame;
}

// The transform runs in a dedicated worker context (RTCRtpScriptTransform).
const ctxPromise = derive(BASE_KEY);
const sendCtr = { c: 0 };
const stats = { ok: 0, dropped: 0, firstErr: '' };
setInterval(() => {
  if (stats.ok || stats.dropped) (self as any).postMessage({ sframe: stats });
}, 2000);

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(self as any).onrtctransform = (event: any) => {
  const transformer = event.transformer;
  const mode = transformer.options?.mode || 'decrypt';
  transformer.readable
    .pipeThrough(new TransformStream({
      async transform(frame, controller) {
        try {
          if (mode === 'encrypt') controller.enqueue(await encryptFrame(frame, await ctxPromise, sendCtr));
          else controller.enqueue(await decryptFrame(frame, await ctxPromise));
          stats.ok++;
        } catch (e) {
          // Drop undecryptable frames — wrong key or non-SFrame sender.
          stats.dropped++;
          if (!stats.firstErr) stats.firstErr = String(e);
        }
      },
    }))
    .pipeTo(transformer.writable);
};
