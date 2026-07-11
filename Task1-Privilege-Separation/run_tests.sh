#!/usr/bin/env bash
# run_tests.sh -- build, functionally test, and collect security evidence for
# the privilege-separated authentication service (Task 1).
#
# The backend must start as root so it can drop privileges. It then serves an
# unprivileged client (the frontend) over a UNIX domain socket. Because the
# backend enforces owner_uid == SO_PEERCRED uid, the frontend must run as the
# same unprivileged user the backend dropped to.
#
# Usage:  sudo ./run_tests.sh
#
# Valid demo credentials (see Backend.c): username "student", password
# "SecurePass123".

set -u

SOCK=/tmp/privsep_auth.sock
RUNDIR=$(mktemp -d /tmp/privsep_test.XXXXXX)
BACKEND_LOG="$RUNDIR/backend.log"
USER=student
PASS=SecurePass123

pass=0; fail=0
ok()  { echo "  PASS: $1"; pass=$((pass+1)); }
bad() { echo "  FAIL: $1"; fail=$((fail+1)); }

cleanup() {
    [ -n "${BPID:-}" ] && kill "$BPID" 2>/dev/null
    wait 2>/dev/null
    rm -f "$SOCK"
    rm -rf "$RUNDIR"
}
trap cleanup EXIT

echo "== [1/6] Building =="
make all >/dev/null 2>&1 || { echo "  BUILD FAILED"; exit 1; }
# copy to a world-traversable dir so an unprivileged user can exec them
cp backend frontend "$RUNDIR"/
chmod 755 "$RUNDIR" "$RUNDIR"/backend "$RUNDIR"/frontend
echo "  built backend + frontend"

# Determine an unprivileged uid to run the frontend as.
if [ "$(id -u)" = 0 ]; then
    if id -u nobody >/dev/null 2>&1; then DUID=$(id -u nobody); DGID=$(id -g nobody); else DUID=1000; DGID=1000; fi
    RUN_AS() { setpriv --reuid "$DUID" --regid "$DGID" --clear-groups "$@"; }
    echo "  frontend will run as uid=$DUID (backend drops to the same)"
else
    RUN_AS() { "$@"; }
    echo "  not root: running everything as $(id -u) (privilege-drop step limited)"
fi

echo "== [2/6] Starting backend =="
rm -f "$SOCK"
( cd "$RUNDIR" && ./backend ) > "$BACKEND_LOG" 2>&1 &
BPID=$!
sleep 1
if ! kill -0 "$BPID" 2>/dev/null; then echo "  BACKEND FAILED TO START"; cat "$BACKEND_LOG"; exit 1; fi
sed 's/^/    /' "$BACKEND_LOG"

echo "== [3/6] Privilege-drop verification =="
if [ "$(id -u)" = 0 ]; then
    UIDLINE=$(grep -E "^Uid:" /proc/$BPID/status)
    echo "    /proc/$BPID/status $UIDLINE"
    if echo "$UIDLINE" | grep -qE "Uid:[[:space:]]+$DUID[[:space:]]+$DUID[[:space:]]+$DUID"; then
        ok "backend dropped to uid=$DUID on all IDs"
    else
        bad "backend did not fully drop privileges"
    fi
else
    echo "    (skipped: not running as root)"
fi

echo "== [4/6] Functional tests =="
run_case() { # desc  expected_exit  username  password  [extra-args]
    local desc="$1" exp="$2" u="$3" p="$4"; shift 4
    out=$(printf '%s\n%s\n' "$u" "$p" | RUN_AS "$RUNDIR/frontend" "$@" 2>/dev/null)
    rc=$?
    msg=$(echo "$out" | sed -n 's/.*Authentication result: //p')
    if [ "$rc" = "$exp" ]; then ok "$desc -> [$msg] (exit $rc)"; else bad "$desc (exit $rc, wanted $exp) [$msg]"; fi
}
run_case "correct credentials" 0 "$USER" "$PASS"
run_case "wrong password"      1 "$USER" "WrongPass"
run_case "unknown user"        1 "hacker" "$PASS"

echo "== [5/6] Attack resistance =="
run_case "invalid operation code rejected" 1 "$USER" "$PASS" --invalid-op

echo "== [6/6] Secure-memory evidence =="
echo "    secure_wipe scrubbing preserved at -O2:"
if objdump -d backend | grep -A6 '<secure_wipe>:' | grep -q explicit_bzero; then
    ok "explicit_bzero call retained in secure_wipe (no dead-store elimination)"
else
    bad "secure_wipe scrubbing may have been optimized away"
fi
echo "    privilege syscalls linked:"
objdump -d backend | grep -oE 'setresuid@plt|setresgid@plt|setgroups@plt' | sort -u | sed 's/^/      /'

echo
echo "==== SUMMARY: $pass passed, $fail failed ===="
[ "$fail" = 0 ]
