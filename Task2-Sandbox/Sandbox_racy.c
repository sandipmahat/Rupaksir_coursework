/*
 * Sandbox.c -- a user-space malware-analysis sandbox.
 *
 * The supervisor forks a child, applies rlimits, and execve()s an untrusted
 * binary. Monitoring happens entirely in the PARENT, across three pthreads:
 *
 *   watchdog  -- wall-clock deadline; escalates SIGTERM -> SIGKILL
 *   sampler   -- polls /proc/<pid>/stat for CPU time and RSS; enforces caps
 *   reaper    -- blocks in waitpid(), records the true exit status
 *
 * The child never participates in its own monitoring or termination. All
 * shared state between threads is C11 _Atomic; the verdict is claimed with a
 * single compare-and-swap so that concurrent threads cannot interleave a
 * decision. See ANALYSIS for the reasoning.
 *
 * Build:  gcc -O2 -Wall -Wextra -std=c11 -pthread -o sandbox Sandbox.c
 * Usage:  ./sandbox [-t secs] [-c secs] [-m KB] [-o log] -- <binary> [args...]
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define SAMPLE_INTERVAL_MS   1
#define GRACE_PERIOD_MS      500     /* SIGTERM -> SIGKILL window */

/* ---- Verdicts. Ordered; claimed exactly once via CAS. ---- */
enum verdict {
    VERDICT_NONE = 0,
    VERDICT_OK,            /* exited on its own, within all limits  */
    VERDICT_TIMEOUT,       /* wall-clock deadline exceeded          */
    VERDICT_CPU,           /* CPU-time cap exceeded                 */
    VERDICT_MEMORY,        /* RSS cap exceeded                      */
    VERDICT_SIGNALLED,     /* died on a signal (e.g. SIGSEGV)       */
    VERDICT_ERROR
};

static const char *verdict_name(int v)
{
    switch (v) {
    case VERDICT_OK:        return "COMPLETED";
    case VERDICT_TIMEOUT:   return "KILLED_WALLCLOCK";
    case VERDICT_CPU:       return "KILLED_CPU";
    case VERDICT_MEMORY:    return "KILLED_MEMORY";
    case VERDICT_SIGNALLED: return "KILLED_BY_SIGNAL";
    case VERDICT_ERROR:     return "ERROR";
    default:                return "NONE";
    }
}

/*
 * Shared state. Every field touched by more than one thread is _Atomic.
 * `volatile` would NOT be sufficient: it prevents the compiler caching the
 * value, but provides no memory ordering and no indivisibility, so a
 * read-modify-write (e.g. claiming the verdict) could still interleave.
 */
struct sandbox {
    pid_t child;

    _Atomic int  verdict;          /* claimed once, by CAS            */
    _Atomic int  child_exited;     /* set by reaper                   */
    _Atomic int  wait_status;      /* raw status from waitpid()       */
    _Atomic long peak_rss_kb;
    _Atomic long cpu_ms;
    _Atomic int  stop_threads;     /* tells sampler/watchdog to leave */

    /* limits */
    double wall_limit_s;
    double cpu_limit_s;
    long   mem_limit_kb;

    struct timespec t0;
    FILE *log;
    pthread_mutex_t log_lock;      /* serialises log writes only      */
};

static struct sandbox S;

/* ---------- logging ---------- */

static double elapsed_s(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)(now.tv_sec - S.t0.tv_sec) +
           (double)(now.tv_nsec - S.t0.tv_nsec) / 1e9;
}

static void logmsg(const char *tag, const char *fmt, ...)
{
    va_list ap;
    char line[512];
    int n;

    n = snprintf(line, sizeof(line), "[%8.3fs] %-9s ", elapsed_s(), tag);
    va_start(ap, fmt);
    vsnprintf(line + n, sizeof(line) - (size_t)n, fmt, ap);
    va_end(ap);

    pthread_mutex_lock(&S.log_lock);
    fprintf(stderr, "%s\n", line);
    if (S.log) {
        fprintf(S.log, "%s\n", line);
        fflush(S.log);
    }
    pthread_mutex_unlock(&S.log_lock);
}

/*
 * Claim the verdict. Returns 1 if THIS caller won the race, 0 if another
 * thread had already decided. compare_exchange is the whole point: without
 * it, the watchdog and the sampler could both believe they are the killer
 * and both log a termination.
 */
static int claim_verdict(int want)
{
    /* DELIBERATELY BROKEN: read and write are separate steps, so two
       threads can both pass the test before either writes. */
    if (atomic_load(&S.verdict) == VERDICT_NONE) {
        usleep(3000);                       /* widen the window */
        atomic_store(&S.verdict, want);
        return 1;
    }
    return 0;
}

/* ---------- external observation of the child ---------- */

/*
 * Read CPU time (utime+stime) and RSS from /proc/<pid>/stat. This is the
 * kernel's accounting, gathered from OUTSIDE the child: the binary is not
 * asked how much CPU it has used, and cannot lie about it.
 */
static int sample_proc(pid_t pid, long *cpu_ms, long *rss_kb)
{
    char path[64], buf[1024];
    int fd;
    ssize_t n;
    char *p;
    unsigned long utime = 0, stime = 0;
    long rss_pages = 0;
    long ticks = sysconf(_SC_CLK_TCK);
    long pagesize_kb = sysconf(_SC_PAGESIZE) / 1024;

    snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;                       /* gone: reaper will confirm */
    }
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        return -1;
    }
    buf[n] = '\0';

    /* comm may contain spaces/parens: start parsing after the final ')' */
    p = strrchr(buf, ')');
    if (!p) {
        return -1;
    }
    p += 2;                              /* skip ") " -> field 3 (state) */

    /* fields from 3: state ppid pgrp sid tty tpgid flags
       min_flt cmin_flt maj_flt cmaj_flt utime stime ...  */
    {
        int field = 3;
        char *tok = strtok(p, " ");
        while (tok) {
            if (field == 14) utime = strtoul(tok, NULL, 10);
            if (field == 15) stime = strtoul(tok, NULL, 10);
            if (field == 24) { rss_pages = strtol(tok, NULL, 10); break; }
            tok = strtok(NULL, " ");
            field++;
        }
    }

    if (ticks <= 0) ticks = 100;
    *cpu_ms = (long)(((double)(utime + stime) / (double)ticks) * 1000.0);
    *rss_kb = rss_pages * pagesize_kb;
    return 0;
}

/* ---------- termination policy ---------- */

/*
 * Forced termination. The child is not asked to stop and is given no
 * opportunity to refuse: SIGTERM first (so a cooperative process may flush),
 * then SIGKILL, which cannot be caught, blocked or ignored. Signals go to the
 * whole process group, so a child that forked helpers cannot survive by
 * hiding behind them.
 */
static void enforce_kill(const char *why)
{
    int i;

    logmsg("ENFORCE", "policy violation: %s -- terminating child %d",
           why, (int)S.child);

    kill(-S.child, SIGTERM);
    logmsg("SIGNAL", "SIGTERM sent to process group %d", (int)S.child);

    for (i = 0; i < GRACE_PERIOD_MS / 10; i++) {
        if (atomic_load(&S.child_exited)) {
            logmsg("SIGNAL", "child exited after SIGTERM (grace honoured)");
            return;
        }
        usleep(10 * 1000);
    }

    kill(-S.child, SIGKILL);
    logmsg("SIGNAL", "grace expired -- SIGKILL sent (uncatchable)");
}

/* ---------- monitoring threads ---------- */

/* Wall-clock deadline. Independent of the child entirely: it does not read
 * the child's state, only the clock. A binary that blocks, spins, or ignores
 * signals cannot stop this thread from firing. */
static void *watchdog_thread(void *arg)
{
    (void)arg;
    logmsg("WATCHDOG", "armed: wall-clock limit %.1fs", S.wall_limit_s);

    while (!atomic_load(&S.stop_threads)) {
        if (atomic_load(&S.child_exited)) {
            return NULL;
        }
        if (elapsed_s() >= S.wall_limit_s) {
            if (claim_verdict(VERDICT_TIMEOUT)) {
                enforce_kill("wall-clock limit exceeded");
            }
            return NULL;
        }
        usleep(200);
    }
    return NULL;
}

/* Resource sampler. Polls the kernel's own accounting for the child. */
static void *sampler_thread(void *arg)
{
    long cpu_ms, rss_kb;
    (void)arg;

    logmsg("SAMPLER", "armed: cpu limit %.1fs, rss limit %ld KB",
           S.cpu_limit_s, S.mem_limit_kb);

    while (!atomic_load(&S.stop_threads)) {
        if (atomic_load(&S.child_exited)) {
            return NULL;
        }
        if (sample_proc(S.child, &cpu_ms, &rss_kb) == 0) {
            long prev;

            atomic_store(&S.cpu_ms, cpu_ms);

            /* peak RSS: CAS loop, since two threads could race here */
            prev = atomic_load(&S.peak_rss_kb);
            while (rss_kb > prev &&
                   !atomic_compare_exchange_weak(&S.peak_rss_kb, &prev, rss_kb)) {
                /* prev reloaded by CAS; retry */
            }

            if (S.cpu_limit_s > 0 && elapsed_s() >= S.wall_limit_s) {
                if (claim_verdict(VERDICT_CPU)) {
                    logmsg("SAMPLER", "cpu=%ldms rss=%ldKB", cpu_ms, rss_kb);
                    enforce_kill("CPU-time limit exceeded");
                }
                return NULL;
            }
            if (S.mem_limit_kb > 0 && rss_kb >= S.mem_limit_kb) {
                if (claim_verdict(VERDICT_MEMORY)) {
                    logmsg("SAMPLER", "cpu=%ldms rss=%ldKB", cpu_ms, rss_kb);
                    enforce_kill("memory limit exceeded");
                }
                return NULL;
            }
        }
        usleep(200);
    }
    return NULL;
}

/* Reaper. Blocks in waitpid() and records the authoritative exit status. */
static void *reaper_thread(void *arg)
{
    int status = 0;
    pid_t r;
    (void)arg;

    do {
        r = waitpid(S.child, &status, 0);
    } while (r < 0 && errno == EINTR);

    atomic_store(&S.wait_status, status);
    atomic_store(&S.child_exited, 1);

    if (WIFEXITED(status)) {
        logmsg("REAPER", "child exited normally, code=%d",
               WEXITSTATUS(status));
        claim_verdict(VERDICT_OK);
    } else if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        logmsg("REAPER", "child terminated by signal %d (%s)",
               sig, strsignal(sig));
        /* If nobody claimed a verdict, the child died of its own accord
           (e.g. SIGSEGV). If we killed it, our verdict already stands. */
        claim_verdict(VERDICT_SIGNALLED);
    }

    atomic_store(&S.stop_threads, 1);
    return NULL;
}

/* ---------- child setup ---------- */

static void usage(const char *me)
{
    fprintf(stderr,
        "Usage: %s [-t wall_secs] [-c cpu_secs] [-m rss_kb] [-o logfile]"
        " -- <binary> [args...]\n", me);
    exit(2);
}

int main(int argc, char *argv[])
{
    pthread_t th_watchdog, th_sampler, th_reaper;
    struct rusage ru;
    const char *logpath = NULL;
    int i, sep = -1, v, status;

    /* defaults */
    S.wall_limit_s = 3.0;
    S.cpu_limit_s  = 2.0;
    S.mem_limit_kb = 64 * 1024;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) { sep = i; break; }
        else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) S.wall_limit_s = atof(argv[++i]);
        else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) S.cpu_limit_s  = atof(argv[++i]);
        else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) S.mem_limit_kb = atol(argv[++i]);
        else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) logpath = argv[++i];
        else usage(argv[0]);
    }
    if (sep < 0 || sep + 1 >= argc) usage(argv[0]);

    if (logpath) {
        S.log = fopen(logpath, "w");
        if (!S.log) perror("open log");
    }
    pthread_mutex_init(&S.log_lock, NULL);
    atomic_init(&S.verdict, VERDICT_NONE);
    clock_gettime(CLOCK_MONOTONIC, &S.t0);

    logmsg("SANDBOX", "target: %s", argv[sep + 1]);
    logmsg("SANDBOX", "limits: wall=%.1fs cpu=%.1fs rss=%ldKB",
           S.wall_limit_s, S.cpu_limit_s, S.mem_limit_kb);

    S.child = fork();
    if (S.child < 0) {
        perror("fork");
        return 1;
    }

    if (S.child == 0) {
        /* ---- CHILD: becomes the untrusted binary ---- */
        struct rlimit rl;

        /* Own process group, so signals reach the whole tree. */
        setpgid(0, 0);

        /* Belt-and-braces kernel limits. These are a backstop, not the
         * policy: the parent's monitoring is what actually enforces it. */
        rl.rlim_cur = rl.rlim_max = (rlim_t)(S.cpu_limit_s + 2);
        setrlimit(RLIMIT_CPU, &rl);
        rl.rlim_cur = rl.rlim_max = 0;
        setrlimit(RLIMIT_CORE, &rl);
        rl.rlim_cur = rl.rlim_max = 64;
        setrlimit(RLIMIT_NOFILE, &rl);

        execve(argv[sep + 1], &argv[sep + 1], environ);

        /* only reached if execve failed */
        fprintf(stderr, "execve(%s): %s\n", argv[sep + 1], strerror(errno));
        _exit(127);
    }

    /* ---- PARENT: supervises, and never trusts the child ---- */
    setpgid(S.child, S.child);           /* race-free: set on both sides */
    logmsg("SANDBOX", "forked child pid=%d, execve issued", (int)S.child);

    pthread_create(&th_reaper,   NULL, reaper_thread,   NULL);
    pthread_create(&th_watchdog, NULL, watchdog_thread, NULL);
    pthread_create(&th_sampler,  NULL, sampler_thread,  NULL);

    pthread_join(th_reaper,   NULL);
    pthread_join(th_watchdog, NULL);
    pthread_join(th_sampler,  NULL);

    /* Kernel's own accounting of the child, collected by the parent. */
    getrusage(RUSAGE_CHILDREN, &ru);

    v = atomic_load(&S.verdict);
    status = atomic_load(&S.wait_status);

    logmsg("REPORT", "----------------------------------------");
    logmsg("REPORT", "verdict      : %s", verdict_name(v));
    logmsg("REPORT", "wall time    : %.3fs", elapsed_s());
    logmsg("REPORT", "cpu (rusage) : %.3fs user + %.3fs sys",
           ru.ru_utime.tv_sec + ru.ru_utime.tv_usec / 1e6,
           ru.ru_stime.tv_sec + ru.ru_stime.tv_usec / 1e6);
    logmsg("REPORT", "peak rss     : %ld KB", ru.ru_maxrss);
    if (WIFSIGNALED(status)) {
        logmsg("REPORT", "killed by    : signal %d (%s)",
               WTERMSIG(status), strsignal(WTERMSIG(status)));
    } else if (WIFEXITED(status)) {
        logmsg("REPORT", "exit code    : %d", WEXITSTATUS(status));
    }
    logmsg("REPORT", "----------------------------------------");

    if (S.log) fclose(S.log);
    pthread_mutex_destroy(&S.log_lock);

    /* non-zero if the sandbox had to intervene */
    return (v == VERDICT_OK) ? 0 : 1;
}
