#!/usr/bin/env bash
# M2 end-to-end: admin creates a community, invites B, both derive the same
# SFrame keys from the sealed epoch, B decrypts A's video; an outsider using
# the public test key cannot; after revocation B can't open the new epoch.
set -euo pipefail
cd "$(dirname "$0")/../.."
W=${TMPDIR:-/tmp}/laira-m2.$$; mkdir -p "$W"
CTL=target/debug/laira-control; D=target/debug/laira-desktop
cleanup() { kill -9 $(jobs -p) 2>/dev/null || true; pkill -9 -f "services/sfu/node_modules/mediasoup/worker" 2>/dev/null || true; }; trap cleanup EXIT
fail() { echo "FAIL: $*"; exit 1; }

$CTL init --dir "$W/ctl" >"$W/init.log"
$CTL serve --dir "$W/ctl" --bind 127.0.0.1:4599 >"$W/ctl.log" 2>&1 &
CID=$(awk '/^community_id/{print $3}' "$W/init.log"); AK=$(awk '/^admin_key/{print $3}' "$W/init.log")
(cd services/sfu && LAIRA_COMMUNITY_ID=$CID LAIRA_ADMIN_KEY=$AK exec node server.mjs >"$W/sfu.log" 2>&1) &
sleep 3
export LAIRA_HOME_A="$W/A" LAIRA_HOME_B="$W/B"
A() { LAIRA_HOME="$LAIRA_HOME_A" "$@"; }; B() { LAIRA_HOME="$LAIRA_HOME_B" "$@"; }
A $D adopt-admin --control http://127.0.0.1:4599 --dir "$W/ctl"
$CTL invite --dir "$W/ctl" --url http://127.0.0.1:4599 >"$W/invite.json"
B $D join --control http://127.0.0.1:4599 "$W/invite.json"
# same invite again by a new identity must be refused (single use)
if LAIRA_HOME="$W/C" $D join --control http://127.0.0.1:4599 "$W/invite.json" 2>/dev/null; then fail "exhausted invite accepted"; fi
A $D whoami; B $D whoami

watch() { # $1=name, env for the viewer, $2=out
  A $D test-video --e2ee --seconds 9 >"$W/tv.log" 2>&1 & local T=$!
  sleep 2; timeout 6 "${@:3}" $D watch --e2ee --dump "$2" >"$W/w_$1.log" 2>&1 || true; wait $T
  echo "$1: $(stat -c %s "$2" 2>/dev/null || echo 0) bytes, decrypt-fails=$(grep -c 'decrypt failed' "$W/w_$1.log" || true)"
}
watch member "$W/b.h264" env LAIRA_HOME="$LAIRA_HOME_B"
watch outsider "$W/o.h264" env LAIRA_HOME="$W/none"
[ "$(stat -c %s "$W/b.h264")" -gt 100000 ] || fail "member could not decrypt"
[ "$(stat -c %s "$W/o.h264" 2>/dev/null || echo 0)" -lt 10000 ] || fail "outsider decrypted"
grep -q "auth: membership tokens required" "$W/sfu.log" || fail "sfu auth not enabled"
# an outsider cannot even join the SFU (no token)
OUT=$(LAIRA_HOME="$W/none" $D test-video --seconds 2 2>&1 || true)
echo "$OUT" | grep -qi "token\|join" || fail "outsider was not refused by the SFU: $OUT"

# --- live rekey: A streams for a long time; C joins mid-stream (epoch rotates,
# A's encoder must rekey and C must decode); then B is revoked and B's viewer
# must stop by itself while C keeps decoding.
A $D test-video --e2ee --seconds 40 >"$W/tv2.log" 2>&1 & TV=$!
sleep 2
B timeout 30 $D watch --e2ee --dump "$W/b2.h264" >"$W/w_b2.log" 2>&1 & WB=$!
$CTL invite --dir "$W/ctl" --url http://127.0.0.1:4599 >"$W/invite2.json"
LAIRA_HOME="$W/C" $D join --control http://127.0.0.1:4599 "$W/invite2.json"
sleep 5   # pollers pick up the new epoch
LAIRA_HOME="$W/C" timeout 8 $D watch --e2ee --dump "$W/c.h264" >"$W/w_c.log" 2>&1 || true
CSZ=$(stat -c %s "$W/c.h264"); echo "C joined mid-stream: $CSZ bytes"
[ "$CSZ" -gt 100000 ] || fail "member added mid-stream could not decode (sender rekey?)"
grep -q "rekeyed to new epoch" "$W/tv2.log" || fail "sender did not rekey live"

BKEY=$(B $D whoami | awk '/^member/{print $2}')
$CTL revoke --dir "$W/ctl" --url http://127.0.0.1:4599 "$BKEY"
sleep 5
kill -0 $WB 2>/dev/null && fail "revoked viewer still running"
grep -q "removed from the community" "$W/w_b2.log" || fail "revoked viewer did not report removal"
if B $D whoami >/dev/null 2>&1; then fail "revoked member still opens epoch"; fi
A $D whoami >/dev/null || fail "admin lost access"
LAIRA_HOME="$W/C" timeout 8 $D watch --e2ee --dump "$W/c2.h264" >"$W/w_c2.log" 2>&1 || true
[ "$(stat -c %s "$W/c2.h264")" -gt 100000 ] || fail "remaining member lost the stream after revocation"
kill $TV 2>/dev/null || true
echo "M2 E2E OK"
