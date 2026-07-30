# Rupaksir Coursework

Operating-systems security coursework: two independent C projects covering
process isolation, privilege separation, secure IPC, and sandboxing an
untrusted binary. Open this folder in VS Code (`File → Open Folder…`) and the
build/test tasks and debug configs under `.vscode/` are ready to use.

## Contents

- **Task1-Privilege-Separation/** — a privilege-separated password-validation
  service written in C, demonstrating process isolation, secure IPC over a UNIX
  domain socket, an irreversible privilege drop, POSIX shared memory for the
  password, and compiler-proof secret scrubbing. See its own `README.md` for the
  full design and its `ANALYSIS.md` for the written discussion.
- **Task2-Sandbox/** — a user-space sandbox in C that forks a child,
  execve()s an untrusted binary into it, and monitors and terminates it
  entirely from the parent across pthreads, using C11 atomics for race-free
  shared state. Includes a deliberately naive (`Sandbox_racy.c`) build used to
  demonstrate the race it fixes. See its own `README.md` for build/run
  instructions and captured logs.
- **Task_1_2_Privilege_Separation_and_Sandbox_Report.docx** — the merged
  coursework report covering both tasks: design, threat model, evidence of
  execution (screenshots and logs), and evaluation/limitations for each.

## Quick start (VS Code)

1. Open this folder in VS Code. When prompted, install the recommended
   extensions (C/C++ and Makefile Tools).
2. Build: **Terminal → Run Build Task…** (`Ctrl+Shift+B`) → *build (make all)*.
3. Run the tests: **Terminal → Run Task…** → *run tests (needs sudo)*.

## Quick start (terminal)

```sh
# Task 1 — privilege separation
cd Task1-Privilege-Separation
make            # build backend and frontend
sudo make test  # run the automated harness (needs root to drop privileges)
```

```sh
# Task 2 — sandbox
cd Task2-Sandbox
make            # builds sandbox, sandbox_racy, and the 5 test binaries
make test       # runs each test binary under the sandbox -> logs/
make race       # demonstrates the shared-state race -> logs/race_demo.log
```

Requires `gcc`, `make`, `pthread`, and the standard Linux C library (with
`-lrt` for POSIX shared memory, used only by Task 1). Task 1's backend must be
started as root so it can permanently drop privileges at startup; see
`Task1-Privilege-Separation/README.md` for details. Task 2 needs no root.
