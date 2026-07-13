# Task 2 — User-Space Malware Analysis Sandbox

Process control, resource isolation and concurrency.

A sandbox controller in C. The supervisor forks a child, execve()s an untrusted
binary, and monitors it entirely from the parent using three pthreads. When a
policy is breached, the parent signals the child — escalating to SIGKILL if it
refuses to die. The binary takes no part in its own monitoring or termination.

## Build and run

    make            # builds sandbox, sandbox_racy, and the 5 test binaries
    make test       # runs each test binary under the sandbox -> logs/
    make race       # demonstrates the shared-state race -> logs/race_demo.log
    make clean

Requires gcc and pthreads. No root needed.

## Files

    Sandbox.c        the sandbox controller
    Sandbox_racy.c   identical, but claim_verdict() uses a naive check-then-set
                     instead of a compare-exchange. Used to prove the race is
                     real rather than merely asserted.

    test_normal.c    behaves; should be allowed to finish
    test_infinite.c  loops forever; must be stopped by the wall-clock watchdog
    test_cpu.c       spins; must be stopped by the CPU-time policy
    test_stubborn.c  catches SIGTERM and refuses to die; only SIGKILL works
    test_racy.c      spins so both limits fall due together (for the race demo)

    run_tests.sh     runs the four policy tests
    race_demo.sh     runs the broken and fixed builds side by side
    logs/            output from the above

## Results

    normal.log       COMPLETED
    infinite.log     KILLED_WALLCLOCK
    cpu.log          KILLED_CPU
    stubborn.log     KILLED_WALLCLOCK  (via SIGKILL, after SIGTERM was ignored)
    race_demo.log    broken: 8/8 races   fixed: 0/8 races

## The two logs that matter

`logs/stubborn.log` shows the binary announcing that it caught SIGTERM and will
not comply — and being killed anyway two lines later. Termination does not
depend on the target's cooperation.

`logs/race_demo.log` shows the same policy violation producing two kill
sequences without the compare-exchange, and exactly one with it.

Usage:  ./sandbox [-t wall_secs] [-c cpu_secs] [-m rss_kb] [-o log] -- <binary>
