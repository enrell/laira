# laira

Distributed Discord replacement — see [PLAN.md](PLAN.md) for the product and
engineering plan. Current state: **M0 vertical proof** (section 19 of the plan).

## M0 scope

Native Wayland capture → mediasoup SFU → browser viewers, with bidirectional
voice and per-app game audio that never includes call return.

Stack note: media follows the **OBS model** — PipeWire capture via libpipewire
directly, FFmpeg for encode. H.264 leaves ffmpeg as an Annex-B elementary
stream and **Rust packetizes RTP itself** (`rtp_send`): we own the socket, see
RTCP (RR/PLI), and have the insertion point SFrame needs. Audio still goes
through ffmpeg's Opus + RTP muxer; VP8 stays on ffmpeg's muxer as a
transitional path. No GStreamer dependency.

```
apps/desktop   laira-desktop: portal capture + RTP ingest + return voice
apps/web       viewer: mediasoup-client page (watch, mic, mute, stats)
services/sfu   mediasoup + WS signaling; PlainTransport ingest for native
crates/media   PipeWire capture (pipewire crate) + ffmpeg subprocesses
crates/protocol  signaling message types shared with the SFU
tests/m0       signaling + RTP forwarding + video E2E scripts
```

## Requirements

`ffmpeg`, `pipewire`, `pw-record` (all stock on a desktop Linux; no plugins to
install), Rust, Node. For LAN viewers: `LAIRA_ANNOUNCED_IP=<lan-ip>` on the SFU.

## Run

```bash
# 1. SFU (serves the viewer too)
cd services/sfu && npm install && node server.mjs

# 2. capture — start the game/app first so its audio stream exists
cargo run -p laira-desktop -- list-audio        # find --audio-target serial
cargo run -p laira-desktop -- stream            # portal picker appears
#   options: --audio-target <serial> --mic <serial> --codec h264|vp8
#            --bitrate 3000000 --sfu ws://host:4443

# 3. viewer: open http://<sfu-host>:4443/ -> Watch -> Mic
```

Remote (non-localhost) mic needs HTTPS (`LAIRA_TLS_CERT`/`LAIRA_TLS_KEY`);
watching works over plain HTTP since it does not call getUserMedia.

## M0 verification status

- [x] Signaling: join, plain send/recv transports, produce/consume, stats
- [x] RTP forwarding: 100 pkts in -> 102 out (2 RTCP), SSRC rewritten per consumer
- [x] Video E2E: testsrc2 -> libx264 -> RTP -> SFU -> consume -> decoded PNG
- [x] Per-app audio capture: `pw-record --target` taps a playback stream only
- [x] Real portal capture + browser playback: xdg-desktop-portal-hyprland
  picker -> PipeWire BGRA frames -> libx264 -> RTP -> SFU -> mediasoup-client
  video in the browser. Observed ~0.8–2 Mbps at 1896x1030, damage-driven
  capture rate ~5–50 fps
- [x] Bidirectional voice: browser mic -> WebRtcTransport -> SFU ->
  PlainTransport -> ffmpeg `-f pulse` playback heard on the streamer's output
- [x] No call-return: while remote voice played, the game-audio producer RMS
  stayed at the synthetic source's -18 dB — return audio is a separate
  playback stream and never enters the per-app capture
- [ ] Two viewers on other networks (same-machine verified; LAN needs
  `LAIRA_ANNOUNCED_IP`)

## M0 gotchas discovered

- Portal screencast is **damage-driven**: a static or disabled source emits
  zero frames, so producer byte counts legitimately flatline — not a stall.
  Capturing a monitor that later gets disabled (laptop lid) stops video while
  audio keeps flowing.
- PipeWire may negotiate a meaningless framerate (1/1). The desktop clamps it
  to [15,120] and passes `-use_wallclock_as_timestamps 1` so RTP timestamps
  track arrival under variable-rate capture.
- mediasoup `PlainTransport` in `comedia` mode locks the learned remote tuple;
  probes from a different source port are ignored (audio unaffected since each
  track uses its own transport).

## Known M0 limitations

- RTCP is now received and parsed on the native sender (RR/PLI/FIR logged).
  PLI still can't force an x264 keyframe inside an ffmpeg subprocess, so
  keyframes come from `-g` (~2 s); mid-stream joins wait for the next GOP.
  Encoder-side control is tracked under MED-02.
- Portal picker needs a visible desktop session.

## M1: SFrame E2EE (native path verified)

Verified live: `stream --e2ee` (portal capture) → AES-128-GCM SFrame per
access unit → RTP → mediasoup → `watch --e2ee` (Rust depacketize + decrypt +
ffplay) renders the desktop correctly.

- `crates/media/src/sframe.rs` — RFC 9605-style AES-128-GCM + HKDF-SHA256.
  Header `0x03` = KID 0, 4-byte BE counter; nonce = derived salt XOR ctr.
  Fixed test key `laira-m0-sframe!` — interop vector only, NOT key management
  (OpenMLS is M2).
- Encrypted wire format per AU: a real SPS NAL (decoy — mediasoup's
  SimpleConsumer gates forwarding on NAL type 7 keyframe detection, which
  ciphertext would hide) + a SEI-typed unit `0x66 || sframe_blob` carrying the
  encrypted Annex-B AU. Rust `rtp_recv` depacketizes, strips `0x66`, decrypts.
- `laira-desktop watch [--e2ee] [--dump file.h264]` — native viewer:
  PlainTransport consumer → `rtp_recv` → ffplay (or Annex-B dump).
- `tests/m1/sframe-interop.mjs` — Node/WebCrypto decrypts the Rust encryptor's
  bytes (`SFRAME INTEROP OK`); `sframe-forward.mjs` — SFU forwards the format.
- Browser insertable-streams decrypt exists (`sframe-worker.ts`) but the
  Chrome depacketizer/transform path is still unproven (video stays black);
  the native path is the reference implementation for now.
- Audio is still plaintext (per-track SFrame on Opus is a later step).
- Gotcha fixed in test-video: `-pixel_format bgra` is ignored on ffmpeg
  rawvideo **output** (use `-pix_fmt`); it emitted yuv420p while the reader
  expected bgra, producing a tiled grayscale encode — never caught because the
  test was only validated by SFU byte counts, not visually.
