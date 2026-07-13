#!/usr/bin/env bash
# race_demo.sh -- shows why the shared verdict must be claimed atomically.
#
# Sandbox_racy.c is identical to Sandbox.c except that claim_verdict() uses a
# naive check-then-set instead of a compare-exchange, and both monitor threads
# are made to reach the deadline at the same moment. Under those conditions the
# watchdog and the sampler BOTH believe they are the killer: the child is
# signalled twice and two contradictory verdicts are logged for one event.
#
# The real Sandbox.c claims the verdict with atomic_compare_exchange_strong(),
# so exactly one thread wins and the other backs off.
#
# Usage: ./race_demo.sh

set -u
RUNS=8

echo "=================================================================="
echo " BROKEN: claim_verdict() uses check-then-set (no atomicity)"
echo "=================================================================="
races=0
for i in $(seq 1 $RUNS); do
    k=$(./sandbox_racy -t 1 -c 1 -- ./test_racy 2>&1 | grep -c "ENFORCE")
    if [ "$k" -gt 1 ]; then
        races=$((races + 1))
        echo "  run $i:  ENFORCE lines = $k   <-- RACE: child killed twice"
    else
        echo "  run $i:  ENFORCE lines = $k"
    fi
done
echo "  --> races observed: $races / $RUNS"

echo
echo "=================================================================="
echo " FIXED: claim_verdict() uses atomic_compare_exchange_strong()"
echo "=================================================================="
races=0
for i in $(seq 1 $RUNS); do
    k=$(./sandbox -t 1 -c 1 -- ./test_racy 2>&1 | grep -c "ENFORCE")
    [ "$k" -gt 1 ] && races=$((races + 1))
    echo "  run $i:  ENFORCE lines = $k"
done
echo "  --> races observed: $races / $RUNS"
echo
echo "Exactly one thread may claim the verdict. That is what the CAS buys."
