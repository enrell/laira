#!/usr/bin/env bash
# Two browser members: A's microphone (SFrame-encrypted in the sender
# transform) must be decrypted and decoded by B.
set -euo pipefail
cd "$(dirname "$0")/../.."
W=$(mktemp -d); CTL=target/debug/laira-control
cleanup() { kill -9 $(jobs -p) 2>/dev/null || true; pkill -9 -f "services/sfu/node_modules/mediasoup/worker" 2>/dev/null || true; }; trap cleanup EXIT
$CTL init --dir $W/ctl >$W/init.log
CID=$(awk '/^community_id/{print $3}' $W/init.log); AK=$(awk '/^admin_key/{print $3}' $W/init.log)
$CTL serve --dir $W/ctl --bind 127.0.0.1:4599 >$W/ctl.log 2>&1 &
(cd services/sfu && LAIRA_COMMUNITY_ID=$CID LAIRA_ADMIN_KEY=$AK exec node server.mjs >$W/sfu.log 2>&1) &
sleep 3
LA=$($CTL invite --dir $W/ctl --url http://127.0.0.1:4599 --web http://127.0.0.1:4443)
LB=$($CTL invite --dir $W/ctl --url http://127.0.0.1:4599 --web http://127.0.0.1:4443)
node tests/web/mic-e2e.mjs "$LA" "$LB" ${1:-10}
