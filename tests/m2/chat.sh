#!/usr/bin/env bash
# E2EE chat end to end: channels, message exchange, late joiners can't read
# earlier epochs, the relay stores only ciphertext, permissions, revocation.
set -euo pipefail
cd "$(dirname "$0")/../.."
W=${TMPDIR:-/tmp}/laira-chat.$$; mkdir -p "$W"
CTL=target/debug/laira-control; D=target/debug/laira-desktop; URL=http://127.0.0.1:4599
cleanup() { kill -9 $(jobs -p) 2>/dev/null || true; }; trap cleanup EXIT
fail() { echo "FAIL: $*"; exit 1; }

$CTL init --dir $W/ctl >$W/init.log
$CTL serve --dir $W/ctl --bind 127.0.0.1:4599 >$W/ctl.log 2>&1 &
sleep 2
A() { LAIRA_HOME=$W/A "$@"; }; B() { LAIRA_HOME=$W/B "$@"; }; C() { LAIRA_HOME=$W/C "$@"; }
A $D adopt-admin --control $URL --dir $W/ctl >/dev/null
A $D chat create "General Chat" | grep -q "#general-chat" || fail "admin cannot create channel"
A $D chat send general-chat "message before bob joined" >/dev/null

$CTL invite --dir $W/ctl --url $URL >$W/i1.json; B $D join --control $URL $W/i1.json >/dev/null
$CTL invite --dir $W/ctl --url $URL >$W/i2.json; C $D join --control $URL $W/i2.json >/dev/null

A $D chat send general-chat "hello from admin" >/dev/null
B $D chat send general-chat "hi admin, bob here" >/dev/null
B $D chat read general-chat >$W/b.txt
A $D chat read general-chat >$W/a.txt
grep -q "hello from admin" $W/b.txt || fail "member cannot read admin's message"
grep -q "hi admin, bob here" $W/a.txt || fail "admin cannot read member's message"
grep -q "unreadable" $W/b.txt || fail "late joiner read a message from before they joined"
! grep -q "message before bob joined" $W/b.txt || fail "late joiner decrypted pre-join history"
grep -q "message before bob joined" $W/a.txt || fail "admin lost own history"

# the relay holds only ciphertext
! grep -rqE "hello from admin|hi admin|before bob" $W/ctl || fail "plaintext found in the control service's storage"
# permissions: members can't create channels; unauthenticated requests are refused
OUT=$(B $D chat create "sneaky" 2>&1 || true)
echo "$OUT" | grep -qi "moderator" || fail "member created a channel: $OUT"
[ "$(curl -s -o /dev/null -w '%{http_code}' $URL/v1/chat/general-chat)" = "401" ] || fail "chat readable without a token"
[ "$(curl -s -o /dev/null -w '%{http_code}' $URL/v1/channels)" = "401" ] || fail "channels listed without a token"

# files: encrypted chunks on the relay, key only in the E2EE message
head -c 150000 /dev/urandom > $W/src.bin; printf 'TOPSECRETMARKER-%.0s' $(seq 200) >> $W/src.bin
A $D chat send-file general-chat $W/src.bin | grep -q "shared src.bin" || fail "file upload failed"
B $D chat read general-chat --after 0 >$W/b2.txt
SEQ=$(grep "\[file\] src.bin" $W/b2.txt | sed -E 's/^\[([0-9]+)\].*/\1/')
[ -n "$SEQ" ] || fail "attachment not listed for member: $(cat $W/b2.txt)"
mkdir -p $W/dl; B $D chat save-file general-chat $SEQ --out-dir $W/dl >/dev/null
cmp $W/src.bin $W/dl/src.bin || fail "downloaded file differs"
! grep -rqa "TOPSECRETMARKER" $W/ctl || fail "file plaintext found on the relay"
[ "$(curl -s -o /dev/null -w '%{http_code}' $URL/v1/blob/00000000000000000000000000000000/0)" = "401" ] || fail "blob readable without a token"
# tampering with a stored chunk is detected by the receiver
CH=$(ls -d $W/ctl/blobs/*/ | head -1); printf 'X' | dd of=${CH}0 bs=1 seek=100 conv=notrunc 2>/dev/null
mkdir -p $W/dl2; if B $D chat save-file general-chat $SEQ --out-dir $W/dl2 >/dev/null 2>&1; then fail "tampered chunk was accepted"; fi

# revocation: bob loses read and write access; charlie is unaffected
BKEY=$(B $D whoami | awk '/^member/{print $2}')
$CTL revoke --dir $W/ctl --url $URL $BKEY >/dev/null
if B $D chat read general-chat >/dev/null 2>&1; then fail "revoked member can still read"; fi
if B $D chat send general-chat "still here?" >/dev/null 2>&1; then fail "revoked member can still send"; fi
A $D chat send general-chat "after revocation" >/dev/null
C $D chat read general-chat | grep -q "after revocation" || fail "remaining member cannot read post-revocation message"
echo "CHAT E2E OK"
