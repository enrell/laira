#!/usr/bin/env bash
# Browser E2E driver: control + auth'd SFU (serving apps/web/dist) + native
# sender, then headless Chromium joins by invite link and must decode video.
set -euo pipefail
cd "$(dirname "$0")/../.."
W=$(mktemp -d); CTL=target/debug/laira-control; D=target/debug/laira-desktop
cleanup() { kill -9 $(jobs -p) 2>/dev/null || true; pkill -9 -f "services/sfu/node_modules/mediasoup/worker" 2>/dev/null || true; }; trap cleanup EXIT
$CTL init --dir $W/ctl >$W/init.log
CID=$(awk '/^community_id/{print $3}' $W/init.log); AK=$(awk '/^admin_key/{print $3}' $W/init.log)
$CTL serve --dir $W/ctl --bind 127.0.0.1:4599 >$W/ctl.log 2>&1 &
(cd services/sfu && LAIRA_COMMUNITY_ID=$CID LAIRA_ADMIN_KEY=$AK exec node server.mjs >$W/sfu.log 2>&1) &
sleep 3
LAIRA_HOME=$W/A $D adopt-admin --control http://127.0.0.1:4599 --dir $W/ctl >/dev/null
LAIRA_HOME=$W/A $D test-video ${E2EE_FLAG---e2ee} --seconds ${STREAM_SECS:-40} >$W/tv.log 2>&1 &
LAIRA_HOME=$W/A $D test-audio --e2ee --seconds ${STREAM_SECS:-40} >$W/ta.log 2>&1 &
sleep 2
LINK=$($CTL invite --dir $W/ctl --url http://127.0.0.1:4599 --web http://127.0.0.1:4443)
echo "$W"
node tests/web/browser-e2e.mjs "$LINK" ${1:-12}
