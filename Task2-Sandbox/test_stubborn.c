/* test_stubborn.c -- catches SIGTERM and refuses to die.
 * This is the important one: it proves that termination cannot depend on
 * the monitored process cooperating. Only SIGKILL can stop it. */
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

static void ignore_it(int sig)
{
    (void)sig;
    printf("[stubborn] caught SIGTERM -- ignoring it, you cannot stop me\n");
    fflush(stdout);
}

int main(void)
{
    signal(SIGTERM, ignore_it);
    signal(SIGINT,  ignore_it);
    signal(SIGHUP,  ignore_it);

    printf("[stubborn] SIGTERM handler installed, looping forever\n");
    fflush(stdout);
    for (;;) {
        pause();
    }
    return 0;
}
