// Browser-port interop: the JS Member (apps/web/src/laira.ts) joins a real
// control service, opens the sealed epoch and derives the same SFrame key
// (fingerprint) as the Rust desktop for the same epoch.
//   node --experimental-strip-types tests/web/join-interop.mjs <control-url> <invite.json> <rust-key0-fp>
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { Member } from '../../apps/web/src/laira.ts';

const [control, invitePath, rustFp] = process.argv.slice(2);
const m = await Member.join(control, JSON.parse(readFileSync(invitePath, 'utf8')));
const ep = await m.latestEpoch();
const fp = createHash('sha256').update(ep.sframeBaseKey(0)).digest('hex').slice(0, 12);
console.log(`js member ${m.pubHex.slice(0, 8)} kid=${ep.kid} epoch=${ep.epoch} key0-fp=${fp}`);
if (rustFp && fp !== rustFp) { console.error(`MISMATCH rust=${rustFp}`); process.exit(1); }
const tok = await m.sessionToken();
console.log('token expires_at', tok.expires_at);
console.log('JS INTEROP OK');
