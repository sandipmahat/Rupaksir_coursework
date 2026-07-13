#!/usr/bin/env bash
# run_tests.sh -- runs each test binary under the sandbox and saves the logs.
#
#   1. normal    -- behaves, should be allowed to finish
#   2. infinite  -- never exits, must be stopped by the wall-clock watchdog
#   3. cpu       -- burns CPU, must be stopped by the CPU-time policy
#   4. stubborn  -- catches SIGTERM and refuses to die; only SIGKILL works
#
# Usage: ./run_tests.sh

set -u
mkdir -p logs

run() {
    echo
    echo "================================================================"
    echo " TEST: $1"
    echo "================================================================"
    shift
    ./sandbox "$@"
    echo "  [sandbox exit code: $?]"
}

run "normal binary (expect COMPLETED)" \
    -t 3 -c 2 -o logs/normal.log -- ./test_normal

run "infinite loop (expect KILLED_WALLCLOCK)" \
    -t 2 -c 5 -o logs/infinite.log -- ./test_infinite

run "cpu burner (expect KILLED_CPU)" \
    -t 10 -c 1 -o logs/cpu.log -- ./test_cpu

run "stubborn, ignores SIGTERM (expect KILLED_WALLCLOCK via SIGKILL)" \
    -t 2 -c 5 -o logs/stubborn.log -- ./test_stubborn

echo
echo "================================================================"
echo " SUMMARY"
echo "================================================================"
for f in logs/*.log; do
    printf "  %-22s %s\n" "$(basename "$f")" \
        "$(grep -o 'verdict *: .*' "$f" | sed 's/verdict *: //')"
done
echo
echo "Logs written to logs/"
