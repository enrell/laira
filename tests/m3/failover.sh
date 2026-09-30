#!/usr/bin/env bash
# SFU failover: two SFUs behind an admin-signed route. The sender and a native
# viewer are streaming through SFU 1 (E2EE); SFU 1 is killed; both must move to
# SFU 2 and video must flow again. Prints the measured recovery time.
set -euo pipefail
cd "$(dirname "$0")/../.."
W=${TMPDIR:-/tmp}/laira-fo.$$; mkdir -p "$W"
CTL=target/debug/laira-control; D=target/debug/laira-desktop; URL=http://127.0.0.1:4599
cleanup() { kill -9 $(jobs -p) 2>/dev/null || true; kill -9 ${SFU1:-} ${SFU2:-} 2>/dev/null || true; }; trap cleanup EXIT
fail() { echo "FAIL: $*"; exit 1; }
MAX_RECOVERY=${MAX_RECOVERY:-12}

$CTL init --dir $W/ctl >$W/init.log
CID=$(awk '/^community_id/{print $3}' $W/init.log); AK=$(awk '/^admin_key/{print $3}' $W/init.log)
$CTL serve --dir $W/ctl --bind 127.0.0.1:4599 >$W/ctl.log 2>&1 &
sfu() { (cd services/sfu && LAIRA_SFU_PORT=$1 LAIRA_RTC_MIN_PORT=$2 LAIRA_RTC_MAX_PORT=$3 LAIRA_COMMUNITY_ID=$CID LAIRA_ADMIN_KEY=$AK LAIRA_CONTROL_URL=$URL exec node server.mjs >$W/sfu$4.log 2>&1) & }
sfu 4443 40000 44999 1; SFU1=$!
sfu 4444 45000 49999 2; SFU2=$!
sleep 3
A() { LAIRA_HOME=$W/A "$@"; }; B() { LAIRA_HOME=$W/B "$@"; }
A $D adopt-admin --control $URL --dir $W/ctl >/dev/null
$CTL invite --dir $W/ctl --url $URL >$W/inv.json; B $D join --control $URL $W/inv.json >/dev/null
$CTL route --dir $W/ctl --url $URL --sfu ws://127.0.0.1:4443 --sfu ws://127.0.0.1:4444 | grep -q "revision 1" || fail "route not published"

A $D test-video --e2ee --seconds 60 >$W/tv.log 2>&1 &
sleep 2
B $D watch --e2ee --dump $W/out.h264 >$W/watch.log 2>&1 &
sleep 8
S1=$(stat -c %s $W/out.h264); [ "$S1" -gt 100000 ] || fail "no video through SFU 1 before the failure (size $S1)"
echo "before failure: $S1 bytes via SFU 1"

kill -9 $SFU1; T0=$(date +%s%N); SIZE_AT_KILL=$(stat -c %s $W/out.h264)
REC=""
for i in $(seq 1 120); do
  sleep 0.25
  if [ "$(stat -c %s $W/out.h264)" -gt $((SIZE_AT_KILL + 30000)) ]; then REC=$(( ($(date +%s%N) - T0) / 1000000 )); break; fi
done
[ -n "$REC" ] || { tail -n 5 $W/tv.log $W/watch.log; fail "video did not resume on SFU 2"; }
echo "recovery: ${REC} ms (limit ${MAX_RECOVERY} s)"
grep -q "sender failover complete" $W/tv.log || fail "sender did not report failover"
grep -q "viewer failover complete" $W/watch.log || fail "viewer did not report failover"
[ "$REC" -le $((MAX_RECOVERY * 1000)) ] || fail "recovery slower than $MAX_RECOVERY s"
# the stream is decodable after the switch (keyframe resync)
ffprobe -v error -count_frames -select_streams v:0 -show_entries stream=nb_read_frames -of csv=p=0 $W/out.h264 >$W/frames.txt 2>/dev/null || true
echo "decodable frames: $(cat $W/frames.txt)"
[ "$(cat $W/frames.txt || echo 0)" -gt 250 ] || fail "too few decodable frames"
echo "M3 FAILOVER OK"
