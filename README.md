# Rupaksir Coursework

Operating-systems security coursework.

## Task 1 — Privilege-Separated Password Validation

A password-validation service split across two processes: process isolation,
secure IPC over a UNIX domain socket, irreversible privilege dropping, POSIX
shared memory, and secret scrubbing. See the `Task1-Privilege-Separation/`
directory for the code, build system, tests, and written analysis.

## Build and test

    cd Task1-Privilege-Separation
    make            # build backend and frontend
    sudo make test  # run the automated test harness

Linux only (uses setresuid, POSIX shared memory, and SO_PEERCRED). On Windows,
run inside WSL.

## Author

Sandip Mahat
