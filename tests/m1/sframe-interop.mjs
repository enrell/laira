// M1 SFrame interop vector: decrypts a ciphertext produced by the Rust
// SframeEncryptor (crates/media/src/sframe.rs) using WebCrypto — the exact
// code path the browser transform worker (apps/web/src/sframe-worker.ts)
// runs. Regenerate the vector with:
//   cargo test -p laira-media sframe::tests::write_interop_vector
// then: node tests/m1/sframe-interop.mjs
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';

const crypto = webcrypto;
const te = new TextEncoder();
const v = JSON.parse(readFileSync('/tmp/sframe-vector.json', 'utf8'));
const hex = (s) => new Uint8Array(s.match(/../g).map((h) => parseInt(h, 16)));

const baseKey = hex(v.baseKey);
const ikm = await crypto.subtle.importKey('raw', baseKey, 'HKDF', false, ['deriveBits']);
const keyBits = await crypto.subtle.deriveBits(
  { name: 'HKDF', hash: 'SHA-256', salt: te.encode('SFrame 1.0'), info: te.encode('key') }, ikm, 128);
const saltBits = await crypto.subtle.deriveBits(
  { name: 'HKDF', hash: 'SHA-256', salt: te.encode('SFrame 1.0'), info: te.encode('salt') }, ikm, 96);
const key = await crypto.subtle.importKey('raw', keyBits, { name: 'AES-GCM' }, false, ['decrypt']);
const salt = new Uint8Array(saltBits);

const data = hex(v.ciphertext);
// wire format = Annex-B unit: 00 00 00 01 || 0x66 (SEI marker) || sframe blob
if (!(data[0] === 0 && data[1] === 0 && data[2] === 0 && data[3] === 1 && data[4] === 0x66)) {
  console.error('missing Annex-B + 0x66 wire prefix'); process.exit(1)
}
const blob = data.slice(5); // same as sframe-worker.ts blob extraction
const cfg = blob[0];
const ctrLen = (cfg & 0x0f) + 1;
let ctr = 0;
for (let i = 0; i < ctrLen; i++) ctr = ctr * 256 + blob[1 + i];
const nonce = new Uint8Array(salt);
let c = BigInt(ctr);
for (let i = 11; i >= 4 && c > 0n; i--) { nonce[i] ^= Number(c & 0xffn); c >>= 8n; }

const pt = new Uint8Array(await crypto.subtle.decrypt(
  { name: 'AES-GCM', iv: nonce, additionalData: blob.slice(0, 1 + ctrLen), tagLength: 128 },
  key, blob.slice(1 + ctrLen)));

const ok = Buffer.from(pt).toString('hex') === v.plaintext;
console.log(`vector: cfg=0x${cfg.toString(16)} ctr=${ctr} pt=${Buffer.from(pt).toString('hex')}`);
if (!ok) { console.error(`MISMATCH want=${v.plaintext}`); process.exit(1) }
console.log('SFRAME INTEROP OK');
