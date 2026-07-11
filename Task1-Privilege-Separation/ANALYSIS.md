# Analysis and Verification

This goes with my two programs, `Frontend.c` and `Backend.c`, and answers the
questions from the brief. Where I say the code does something, I checked it: the
test script reports 6 passed, 0 failed, and I used `make disassembly` /
`make evidence` to look at the compiled binary.

Quick reminder of the design so the answers make sense. The frontend is the
unprivileged program that reads the username and password. The backend starts as
root, drops privileges for good, then validates requests over a UNIX domain
socket. The password itself never goes over the socket — it goes through a POSIX
shared-memory object instead.

---

## 1. Why is it insecure for one process to both take input and hold the auth data?

If one process does both, the code parsing attacker-controlled input runs with the
same access as the code guarding the secrets, with nothing between them. A single
bug in the parser — an overflow, a format-string mistake, a use-after-free — lands
the attacker right next to the credentials, because it's all one address space at
one privilege level.

That's the point of least privilege (Saltzer and Schroeder, 1975): code that
doesn't need the secrets shouldn't have access to them. In my design the frontend
never sees the expected password or the validation logic, and the backend only
parses the request *after* dropping to an unprivileged user. So breaking the
frontend gets you one request; breaking the backend's handler gets you the powers
of `nobody`.

## 2. How can you enforce least privilege with processes instead of threads?

Threads share the address space, the file descriptors, and the user ID — they all
run as the same user, so a thread can't be a security boundary. Break one and
you've broken all of them. Processes are different: the kernel gives each one its
own memory (via the MMU), its own descriptors, and its own credentials, and
enforces that split.

So I used two separate programs over a socket. Only the backend starts as root,
and it drops that immediately; the frontend has no elevated rights at all. Because
the kernel enforces the separation, a bug on one side can't reach the other. It's
the same idea as OpenSSH's privilege separation (Provos, Friedl and Honeyman,
2003): keep the untrusted work unprivileged and let only a small piece stay
privileged.

## 3. What can still go wrong if privilege dropping is done wrong?

The big one is a drop that isn't actually permanent. `setuid()` doesn't always
change all three IDs (real, effective, saved-set). If the saved-set UID stays 0,
the process can call `seteuid(0)` later and get root back (Chen and Wagner,
*Setuid Demystified*; CERT POS37-C). So it can look dropped while only the
effective UID changed — still one syscall from root. That family of bugs is
CWE-271 and CWE-273.

Other traps: not checking the return value (the call can fail and leave you root),
not dropping supplementary groups first, and dropping the GID after the UID when
you no longer can. My backend does groups, then GID, then UID, with
`setresgid`/`setresuid` so all three IDs change at once, checks every return value,
and re-checks the result (question 8).

## 4. How can two processes exchange requests without leaking to other processes?

Two things. First, the socket at `/tmp/privsep_auth.sock` is `0600` and owned by
the unprivileged user, so nobody else can connect. On each connection the backend
reads the peer's real UID with `SO_PEERCRED` (filled in by the kernel, so it can't
be faked) and rejects the request unless `owner_uid` matches.

Second — the part I'm most happy with — the password never travels over the
socket. The frontend puts it in a shared-memory object (`0600`, locked into RAM,
kept out of core dumps) and only sends its *name*. The backend opens it, uses
`fstat` to check the owner, size and permissions, `shm_unlink`s it so nobody can
reopen or replay it, then maps it, checks the password, and wipes it. The request
is a fixed-size struct with a magic number and operation code, so malformed input
is rejected rather than parsed.

## 5. Why are UNIX domain sockets better than network sockets here?

For same-machine communication they're a better fit:

- Nothing on the network can reach them, so remote attackers, port scans and
  firewall mistakes aren't a concern.
- The receiver gets the peer's real UID/GID/PID from the kernel via `SO_PEERCRED`.
  TCP can't do that — you'd need TLS and certificates to get close.
- Access is by file permissions. Mine is `0600` owned by the unprivileged user, so
  the OS decides who can connect.
- No source-address spoofing and none of the TCP overhead — it's basically a copy
  through the kernel.

A `127.0.0.1` TCP socket would need a lot of extra machinery to match any of this.

## 6. What OS mechanisms let processes share data in a controlled way?

A few, all with the kernel staying in charge of who gets in:

- UNIX domain sockets, which can also pass file descriptors or credentials as
  ancillary data. I use these for control messages.
- POSIX shared memory (`shm_open` + `mmap`) — a named region mapped into more than
  one process, controlled by its ownership and permission bits. I use this for the
  password, plus the `fstat` check and unlink-after-open to make it authenticated
  and single-use.
- Pipes/FIFOs, System V shared memory and semaphores, signals or `eventfd`.

The common thread is that each one has a gate — file permissions, descriptor
inheritance, or a credential check — so the sharing is scoped. The processes
aren't giving up isolation; they're agreeing on one controlled window through it
that the kernel enforces.

## 7. How can a process give up root for good, and why must it be permanent?

Set all three UIDs (and GIDs) to the unprivileged value in one go, after dropping
the extra groups:

```c
setgroups(0, NULL);
setresgid(target_gid, target_gid, target_gid);
setresuid(target_uid, target_uid, target_uid);
```

The saved-set UID is the important bit. The `setuid(2)` man page says once a root
process sets all its user IDs to a non-zero value, it can't get root back. If you
only lower the effective UID, the saved UID is still 0 and the process can climb
back with `seteuid(0)` — no real boundary.

It has to be permanent because the code running *after* the drop is what might
get compromised. If root were recoverable the attacker would just call
`seteuid(0)`, and the separation would mean nothing. Making it irreversible means
the kernel guarantees there's no way back. My backend proves it: after dropping it
tries `seteuid(0)` and treats success as a fatal error.

## 8. What can you look at to confirm the drop worked?

Three things, all from the running backend:

1. It re-reads the IDs with `getuid`/`geteuid`/`getgid`/`getegid` and fails if any
   isn't the target — that catches a partial drop.
2. `/proc/<pid>/status` shows the real/effective/saved/fs IDs in its `Uid:` line.
   My test output shows this going to `Uid: 65534 65534 65534 65534`, which is the
   kernel's own record, not something my program claims.
3. `seteuid(0)` has to fail with `EPERM` afterwards. If it succeeded, the saved UID
   was still 0.

From outside you can check with `ps -o ruid,euid,suid`, `grep Uid
/proc/<pid>/status`, or `strace` showing `setresuid` then `seteuid(0) = -1 EPERM`.
`make evidence` also shows those syscalls are compiled in.

## 9. What would an attacker get if a process kept root by mistake?

Pretty much everything. With root, or even a recoverable root, they could read or
overwrite any file — the shadow file, SSH keys, the logs — load kernel modules,
add users or change passwords, turn off logging, and leave a root shell for later.
A recoverable root is enough on its own, since the exploit can call `seteuid(0)`
first.

In my design the risky input handling is in the frontend and the backend only
parses after dropping, so the worst case for a bug in either is acting as `nobody`
on one socket. That containment is exactly what dropping before parsing buys, and
it vanishes the moment root is kept by accident (CWE-271/273).

## 10. Why wipe secrets from memory even after authentication is done?

Because the password is still in RAM and can leak later — through a core dump if
the process crashes, a debugger or `/proc/<pid>/mem`, the page being swapped to
disk, a cold-boot attack, or another bug that over-reads memory (Heartbleed was
exactly this). The longer it stays, the bigger the window, so the buffer should
hold it as briefly as possible and be zeroed the moment it's done.

I keep that window small on both sides: the frontend locks the buffer into RAM so
it can't be swapped and keeps it out of core dumps, and both programs wipe the
password and the request struct as soon as they're finished, including on error
paths. The backend also unlinks the shared object so it can't be reopened.

## 11. Why can normal memory-clearing calls be unreliable in C?

Because of how C treats writes that are never read. If you zero a local buffer
right before it goes out of scope, nothing in a correct program can observe those
zeros, so the write has no visible effect — and the compiler is allowed to delete
it. This is "dead store elimination," a legal optimisation rather than a bug. So a
`memset(buf, 0, n)` added *for security* can compile down to nothing, leaving the
secret in memory. It's CWE-14, and Yang et al. showed it still happening in real
code (USENIX Security 2017).

## 12. How do explicit memory primitives fix that?

Functions built for this — `explicit_bzero()`, `memset_s()`, `SecureZeroMemory()`,
`OPENSSL_cleanse()` — are defined so the compiler can't drop the write. They add
something the optimiser can't see through (a barrier, a volatile access, or a call
it can't treat as side-effect-free), so the zeroing happens whether or not the
buffer is read afterwards.

All my wiping goes through one `secure_wipe()` helper that calls `explicit_bzero`
on glibc, with a volatile-loop fallback otherwise, marked `noinline` so it's easy
to spot. And you can see it worked: `make disassembly` shows `secure_wipe`
tail-calling `__explicit_bzero_chk` in the `-O2` build, so it wasn't optimised
away. Two honest limitations (Yang et al. again): it only clears the buffer I name,
so copies spilled to registers or other stack slots aren't covered; and no
source-level trick is guaranteed for every compiler, which is why there's been work
on proper support like `memset_s`. For this assignment it's the right choice and I
showed it works with my compiler.

---

## References

- Saltzer, J. H. and Schroeder, M. D. (1975) 'The Protection of Information in
  Computer Systems', *Proceedings of the IEEE*, 63(9).
- Provos, N., Friedl, M. and Honeyman, P. (2003) 'Preventing Privilege
  Escalation', *USENIX Security Symposium*.
- Chen, H. and Wagner, D. *Setuid Demystified*. University of California, Berkeley.
- SEI CERT C Coding Standard, POS37-C: 'Ensure that privilege relinquishment is
  successful'.
- Linux man pages: `setresuid(2)`, `setuid(2)`, `seteuid(2)`, `unix(7)`,
  `shm_open(3)`, `explicit_bzero(3)`.
- MITRE CWE-14, CWE-271, CWE-273. Available at: https://cwe.mitre.org/
- Yang, Z. et al. (2017) 'Dead Store Elimination (Still) Considered Harmful',
  *USENIX Security Symposium*.
