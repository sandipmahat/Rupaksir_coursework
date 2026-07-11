# Task 1 — Privilege-Separated Password Validation

A privilege-separated authentication service for Unix/Linux that enforces the
**principle of least privilege** using operating-system primitives: separate
processes, a UNIX domain socket with kernel-verified peer credentials, an
irreversible privilege drop, POSIX shared memory for the password, and
compiler-proof secret scrubbing.

## Architecture

```
   unprivileged client                UNIX domain socket                privileged service
   ┌────────────────────┐   request   /tmp/privsep_auth.sock   ┌──────────────────────────┐
   │     Frontend.c     │ ──────────────────────────────────▶ │        Backend.c         │
   │  runs as the user  │                                      │  starts as root          │
   │  - reads username  │                                      │  - bind + chmod 0600     │
   │  - reads password  │        password bytes travel in      │  - drop privileges       │
   │    (echo off)      │        POSIX shared memory, NOT      │    (setresuid, permanent)│
   │  - shm_open buffer │◀──── over the socket ───────────────│  - SO_PEERCRED peer check │
   │  - mlock+DONTDUMP  │   accept / reject + message          │  - validate, wipe, reply │
   └────────────────────┘                                      └──────────────────────────┘
```

The password itself is never sent through the socket. The frontend places it in
a POSIX shared-memory object (`shm_open`) that is `mlock`ed (kept out of swap)
and marked `MADV_DONTDUMP` (kept out of core dumps). Only the shared-memory
*name* travels in the request; the backend opens it, verifies its owner, size
and permissions, `shm_unlink`s it to prevent replay, maps it, validates, and
scrubs it.

## Security properties and where they live

| Property                        | Implementation                                                         |
|---------------------------------|------------------------------------------------------------------------|
| Process isolation               | two independent executables, separate address spaces                   |
| Secure IPC                      | `AF_UNIX` socket, `0600`, owner-only; peer verified via `SO_PEERCRED`   |
| Irreversible privilege drop     | `setgroups(0)` → `setresgid` → `setresuid` (all three IDs) in Backend.c |
| Runtime drop verification       | re-reads IDs and confirms `seteuid(0)` now fails                       |
| Attack resistance               | magic + operation check, `owner_uid == peer_uid`, field validation     |
| Password confidentiality        | POSIX shared memory, `mlock`, `MADV_DONTDUMP`, unlink-after-open        |
| Constant-time comparison        | `constant_time_password_equal()` avoids timing leaks                   |
| Secure memory scrubbing         | `secure_wipe()` → `explicit_bzero()`; survives `-O2` (see disassembly)  |

## Build

```sh
make            # produces ./backend and ./frontend
```

Requires `gcc` and `-lrt` (POSIX shared memory), both standard on Linux.

## Run

The backend needs to start as root so it can drop privileges. It drops to
`nobody` (or to the invoking user via `SUDO_UID` when started with `sudo`).

```sh
# terminal 1 — start the privileged service
sudo ./backend
#   Backend IDs before drop: ruid=0 euid=0
#   Backend IDs after drop:  ruid=65534 euid=65534
#   Runtime check: permanent privilege drop verified
#   Backend listening on /tmp/privsep_auth.sock

# terminal 2 — run the client as the same unprivileged user the backend dropped to
./frontend
#   Username: student
#   Password: (hidden)
#   Authentication result: authentication accepted
```

Demo credentials (defined in `Backend.c`): **student / SecurePass123**.

> Note on the peer-UID check: the backend enforces `owner_uid == SO_PEERCRED uid`,
> so the frontend must run as the same user the backend dropped to. In the test
> harness this is handled with `setpriv --reuid`.

## Test

```sh
sudo make test        # 6 checks: build, drop verification, 3 functional, attack, memory
```

Expected result: `6 passed, 0 failed`, with the backend's `/proc/<pid>/status`
`Uid:` line showing the drop and the invalid-operation request rejected.

## Evidence for the write-up

```sh
make disassembly      # shows secure_wipe tail-calling explicit_bzero at -O2
make evidence         # lists setresuid/setresgid/setgroups linked into backend
```

The `ANALYSIS.md` document discusses the design against the assessment's
theoretical questions (least privilege, irreversible dropping, IPC choice,
shared-memory isolation, dead-store elimination, etc.), with references.

## Files

- `Frontend.c` — unprivileged client: reads input, stages the password in shared
  memory, sends the request, prints the result.
- `Backend.c` — privileged validator: binds the socket, drops privileges
  permanently, authenticates the peer, validates, and scrubs secrets.
- `Makefile` — `make`, `make test`, `make disassembly`, `make evidence`, `make clean`.
- `run_tests.sh` — automated build + functional + security harness.
- `ANALYSIS.md` — written analysis mapped to the assessment questions.
