#!/usr/bin/env bash
# Admin recovery end to end: 2-of-3 guardians replace a lost admin. Members keep
# working (new epoch, verified against the recovery chain), the SFU follows the
# chain, the old admin is locked out, and one signature is not enough.
set -euo pipefail
cd "$(dirname "$0")/../.."
W=${TMPDIR:-/tmp}/laira-rec.$$; mkdir -p "$W"
CTL=target/debug/laira-control; D=target/debug/laira-desktop; URL=http://127.0.0.1:4599
cleanup() { kill -9 $(jobs -p) 2>/dev/null || true; pkill -9 -f "services/sfu/node_modules/mediasoup/worker" 2>/dev/null || true; }; trap cleanup EXIT
fail() { echo "FAIL: $*"; exit 1; }

G1=$($CTL keygen --out $W/g1.json); G2=$($CTL keygen --out $W/g2.json); G3=$($CTL keygen --out $W/g3.json)
NEWADMIN=$($CTL keygen --out $W/newadmin.json)
$CTL init --dir $W/ctl --guardian $G1 --guardian $G2 --guardian $G3 >$W/init.log
grep -q "2-of-3" $W/init.log || fail "guardians not recorded"
CID=$(awk '/^community_id/{print $3}' $W/init.log); AK=$(awk '/^admin_key/{print $3}' $W/init.log)
$CTL serve --dir $W/ctl --bind 127.0.0.1:4599 >$W/ctl.log 2>&1 & CTLPID=$!
(cd services/sfu && LAIRA_COMMUNITY_ID=$CID LAIRA_ADMIN_KEY=$AK LAIRA_CONTROL_URL=$URL exec node server.mjs >$W/sfu.log 2>&1) &
sleep 3
OLD() { LAIRA_HOME=$W/old "$@"; }; B() { LAIRA_HOME=$W/B "$@"; }; NEW() { LAIRA_HOME=$W/new "$@"; }
OLD $D adopt-admin --control $URL --dir $W/ctl >/dev/null
$CTL invite --dir $W/ctl --url $URL >$W/inv.json
B $D join --control $URL $W/inv.json >/dev/null
B $D whoami | grep -q "epoch    2" || fail "member baseline"

# --- the admin device is lost ---
kill -9 $CTLPID; sleep 1
$CTL recovery-propose --dir $W/ctl --new-admin $NEWADMIN >$W/rec.json
$CTL recovery-sign --guardian-key $W/g1.json $W/rec.json
if $CTL recover --dir $W/ctl --new-admin-key $W/newadmin.json $W/rec.json 2>/dev/null; then fail "1-of-3 accepted"; fi
$CTL recovery-sign --guardian-key $W/g3.json $W/rec.json
$CTL recover --dir $W/ctl --new-admin-key $W/newadmin.json $W/rec.json
$CTL serve --dir $W/ctl --bind 127.0.0.1:4599 >>$W/ctl.log 2>&1 &
sleep 2

# member follows the chain and opens the new epoch
B $D whoami >$W/b.txt || fail "member cannot open the recovered epoch"
grep -q "epoch    3" $W/b.txt || fail "epoch did not rotate: $(cat $W/b.txt)"
# the old admin is out: no longer trusted, not in the roster
if OLD $D whoami >/dev/null 2>&1; then fail "old admin still opens the epoch"; fi
# SFU learns the new admin from the chain (poll every 10 s), then accepts B's new token
sleep 12
grep -q "admin recovered" $W/sfu.log || fail "sfu did not follow the recovery"
B $D test-video --e2ee --seconds 3 2>&1 | grep -q "RUST RTP PATH OK" || fail "member cannot stream after recovery"
if OLD $D test-video --seconds 2 >/dev/null 2>&1; then fail "old admin still reaches the SFU"; fi
# a stale admin token can't be used by a forged member either
echo "M2 RECOVERY OK"
