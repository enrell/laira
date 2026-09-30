# laira

**A self-hostable, end-to-end encrypted voice and screen/game streaming
platform** — the streaming half of a Discord replacement, built so that the
server that relays your media can never see it.

> **Status: pre-alpha.** The media and membership core work end to end
> (native desktop ⇄ SFU ⇄ browser), but there is no chat, no file sharing, no
> recovery, and no security audit. See [SECURITY.md](SECURITY.md) before
> trusting it, and [PLAN.md](PLAN.md) (Portuguese) for the full roadmap.

## What works today

- **Native screen + game capture on Linux/Wayland**: XDG ScreenCast portal →
  PipeWire → FFmpeg (x264) → RTP, with per-app game audio isolated from the
  voice call (the call's return audio never re-enters the capture).
- **mediasoup SFU** with plain-RTP ingest for the native client and WebRTC for
  browsers. The SFU only forwards ciphertext.
- **End-to-end encryption with SFrame (RFC 9605)** for both video and Opus
  audio, in the native client *and* the browser (WebRTC Encoded Transform).
  Automated tests cover native send → browser decode for video and audio and
  browser microphone → browser decode; the native `stream` command's real
  PipeWire audio path is implemented but not covered by automated tests.
- **Private communities**: an admin creates a community, issues expiring
  invites, members join from the desktop client or a browser link. Group keys
  are per-epoch secrets sealed to each member; removing a member re-keys the
  group and their viewers stop within seconds.
- **Membership-gated SFU**: peers must present a short-lived, admin-signed
  session token.
- **End-to-end encrypted chat and files** (desktop CLI and browser): channels
  created by moderators, messages sealed with a per-epoch key and signed by the
  sender, files encrypted in 64 KiB authenticated chunks with a per-file key
  that only travels inside the chat message. The relay stores ciphertext only.
- **SFU failover**: the admin publishes a signed route listing several SFUs;
  the native sender and viewer and the browser viewer verify it, and when an
  SFU dies they move to the next one and resume (measured 1.6 s native, 3.5 s
  browser, against an 8 s target). The native `stream` command does not fail
  over yet — only `test-video`, `watch` and the browser do.
- **Admin recovery**: guardians chosen at community creation can replace a
  lost admin by threshold signature (2-of-3 by default); clients and the SFU
  verify the recovery chain against the genesis, and the old admin is locked out.
- Rust ⇄ browser interop tested for the crypto (Ed25519, X25519 sealing, HKDF,
  SFrame) and for real decoded video/audio in headless Chromium.

## Architecture

```
            ┌────────────┐  invite / join / epoch / token   ┌──────────────┐
            │ laira-     │ ───────────────────────────────▶ │ laira-control│
            │ desktop    │                                  │ (admin,      │
            │ (capture)  │ ◀─────── sealed epoch keys ───── │  mailbox)    │
            └─────┬──────┘                                  └──────▲───────┘
   SFrame-encrypted│ RTP                                            │ same API
                  ▼                                                │
            ┌────────────┐  ciphertext only   ┌──────────────────┐ │
            │ mediasoup  │ ─────────────────▶ │ browser viewer   │─┘
            │ SFU        │                    │ (apps/web)       │
            └────────────┘                    └──────────────────┘
```

| Path | What it is |
| --- | --- |
| `apps/desktop` | `laira-desktop`: capture, RTP send/receive, join, native viewer |
| `apps/web` | Browser client (Vite + TypeScript, mediasoup-client, SFrame worker) |
| `services/sfu` | Node/mediasoup SFU with WebSocket signaling and token auth |
| `services/control` | `laira-control`: admin authority, invites, epochs, tokens, mailbox |
| `crates/identity` | Identities, genesis, invites, membership, epoch key schedule |
| `crates/media` | PipeWire capture, FFmpeg wrappers, RTP, SFrame, wire format |
| `crates/protocol` | Signaling message types shared with the SFU |
| `tests/` | Interop vectors and end-to-end scripts (`m0`, `m1`, `m2`, `web`) |

## Requirements

- Linux with **PipeWire** and a Wayland compositor that provides an
  `xdg-desktop-portal` ScreenCast backend (tested on Hyprland).
- `ffmpeg` (with libx264 and libopus), `pw-record`.
- Rust (stable) and a recent Node.js (developed on 26).
- A Chromium-based browser for the web viewer (RTCRtpScriptTransform is
  required; Chromium 153 is what the automated tests use — other browsers are
  untested).

## Quick start

```bash
cargo build                                # desktop client + control service
(cd apps/web && npm install && npm run build)
(cd services/sfu && npm install)           # also builds the mediasoup worker

# 1. Create a community (prints its id and the admin key; keep ./community private).
#    Add three recovery guardians so a lost admin can be replaced (strongly advised):
#      G1=$(target/debug/laira-control keygen --out g1.json)   # likewise g2, g3
#      ... init --dir ./community --guardian $G1 --guardian $G2 --guardian $G3
target/debug/laira-control init --dir ./community

# 2. Run the control service and the SFU (bound to your community)
target/debug/laira-control serve --dir ./community --bind 127.0.0.1:4500 &
(cd services/sfu && LAIRA_COMMUNITY_ID=<community_id> LAIRA_ADMIN_KEY=<admin_key> \
   LAIRA_CONTROL_URL=http://127.0.0.1:4500 node server.mjs)                        # also serves the web app on :4443

# 3. Use the admin identity on this machine, then stream
target/debug/laira-desktop adopt-admin --control http://127.0.0.1:4500 --dir ./community
target/debug/laira-desktop stream --e2ee   # portal picker appears

# 4. Invite a friend — they open the link in a browser and press Watch
target/debug/laira-control invite --dir ./community --web http://<sfu-host>:4443
```

Publish a failover route with `laira-control route --dir ./community --sfu ws://a:4443 --sfu ws://b:4443`
(clients then prefer the signed route over `--sfu`).

Chat from the terminal: `laira-desktop chat channels|create <name>|send <channel> <text>|read <channel> [--follow]|send-file <channel> <path>|save-file <channel> <seq>`.
The browser page shows the same channels with an attach button.

Desktop members join with
`laira-desktop join --control <url> invite.json` (create the JSON with
`laira-control invite` without `--web`). `laira-desktop whoami` shows your
member key, roster slot and current epoch. Revoke with
`laira-control revoke --dir ./community <member-key>`.

Recovering a lost admin (control service stopped, state dir restored):

```bash
NEW=$(laira-control keygen --out newadmin.json)
laira-control recovery-propose --dir ./community --new-admin $NEW > rec.json
laira-control recovery-sign --guardian-key g1.json rec.json    # each guardian
laira-control recovery-sign --guardian-key g3.json rec.json
laira-control recover --dir ./community --new-admin-key newadmin.json rec.json
```

Notes:

- For viewers outside localhost set `LAIRA_ANNOUNCED_IP=<reachable-ip>` on the
  SFU and open UDP ports 40000–49999. Browser microphone access needs HTTPS
  (`LAIRA_TLS_CERT` / `LAIRA_TLS_KEY`). Put TLS in front of the control service
  before exposing it — see [SECURITY.md](SECURITY.md).
- Without `LAIRA_COMMUNITY_ID` / `LAIRA_ADMIN_KEY` the SFU runs **open** (dev
  mode, logged at startup). Without a community profile, `--e2ee` falls back to
  a public test key and warns.

## Tests

```bash
cargo test                                 # unit tests (identity, sframe, wire, relays)
tests/m2/e2e.sh                            # membership + native E2EE + live rekey + revocation
tests/m2/recovery.sh                       # 2-of-3 admin recovery, SFU follows the chain
tests/web/run.sh                           # headless Chromium joins by invite, decodes E2EE video + audio
tests/web/mic.sh                           # browser microphone -> another browser, E2EE
tests/m3/failover.sh                       # kill SFU 1: sender + viewer move to SFU 2, measured recovery
tests/web/failover.sh                      # same, for the browser viewer
tests/m2/chat.sh                           # chat + files: permissions, ciphertext-only relay, tamper, revocation
tests/web/chat.sh                          # browser <-> desktop chat and file transfer
node tests/m1/sframe-interop.mjs           # Rust ↔ WebCrypto SFrame vector
```

The end-to-end scripts start their own control service and SFU on ports 4599 and
4443, so stop any SFU you have running first. Detailed per-milestone notes and
gotchas are in [docs/dev-notes.md](docs/dev-notes.md).

## Roadmap

Following [PLAN.md](PLAN.md): M0 ✅ vertical proof · M1 ✅ E2EE media · **M2
(private entry) mostly done** — remaining: OpenMLS, dead-drop transport · M3 SFU failover (viewer + test sender done; real `stream` sender, controller failover and load-based selection pending) · M4 chat and channels (basic: no DMs, search, unread state or fine-grained
permissions yet) · M5 file sharing via the relay (no peer-to-peer/cooperative
cache yet) · M6 packaging and daily use.

## Contributing

Issues and pull requests are welcome. For anything security-relevant, follow
[SECURITY.md](SECURITY.md) instead of opening a public issue.

## License

[MIT](LICENSE) © 2026 enrell
