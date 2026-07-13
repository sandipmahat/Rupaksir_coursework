/* test_cpu.c -- burns CPU as fast as it can. Tests the CPU-time policy. */
#include <stdio.h>

int main(void)
{
    volatile unsigned long x = 0;

    printf("[cpu] spinning to burn CPU\n");
    fflush(stdout);
    for (;;) {
        x++;
    }
    return 0;
}
