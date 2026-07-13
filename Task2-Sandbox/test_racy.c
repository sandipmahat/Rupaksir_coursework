/* test_racy.c -- spins hard so that the CPU cap and the wall-clock deadline
 * fall due at almost the same moment. Used to show that the sampler and the
 * watchdog really do race to decide the verdict, and that the compare-exchange
 * lets exactly one of them win. */
#include <stdio.h>

int main(void)
{
    volatile unsigned long x = 0;
    printf("[racy] spinning; cpu and wall limits will expire together\n");
    fflush(stdout);
    for (;;) x++;
    return 0;
}
