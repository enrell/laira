#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
W=$(mktemp -d); CTL=target/debug/laira-control; D=$PWD/target/debug/laira-desktop; URL=http://127.0.0.1:4599
cleanup() { kill -9 $(jobs -p) ${SFU1:-} ${SFU2:-} 2>/dev/null || true; }; trap cleanup EXIT
$CTL init --dir $W/ctl >$W/init.log
CID=$(awk '/^community_id/{print $3}' $W/init.log); AK=$(awk '/^admin_key/{print $3}' $W/init.log)
$CTL serve --dir $W/ctl --bind 127.0.0.1:4599 >$W/ctl.log 2>&1 &
sfu() { (cd services/sfu && LAIRA_SFU_PORT=$1 LAIRA_RTC_MIN_PORT=$2 LAIRA_RTC_MAX_PORT=$3 LAIRA_COMMUNITY_ID=$CID LAIRA_ADMIN_KEY=$AK LAIRA_CONTROL_URL=$URL exec node server.mjs >$W/sfu$4.log 2>&1) & }
sfu 4443 40000 44999 1; SFU1=$!
sfu 4444 45000 49999 2; SFU2=$!
sleep 3
LAIRA_HOME=$W/A $D adopt-admin --control $URL --dir $W/ctl >/dev/null
$CTL route --dir $W/ctl --url $URL --sfu ws://127.0.0.1:4443 --sfu ws://127.0.0.1:4444 >/dev/null
LAIRA_HOME=$W/A $D test-video --e2ee --seconds 70 >$W/tv.log 2>&1 &
sleep 2
LINK=$($CTL invite --dir $W/ctl --url $URL --web http://127.0.0.1:4443)
node tests/web/failover-e2e.mjs "$LINK" ${1:-25} >$W/page.out 2>&1 &
NODE=$!
for i in $(seq 1 120); do grep -q "^READY" $W/page.out 2>/dev/null && break; sleep 0.5; done
grep -q "^READY" $W/page.out || { cat $W/page.out; echo "page never became ready"; exit 1; }
kill -9 $SFU1
wait $NODE && RC=0 || RC=$?
cat $W/page.out
exit $RC
