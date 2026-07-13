/* test_normal.c -- a well-behaved binary. Should be allowed to finish. */
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    printf("[normal] starting, will do a little work then exit\n");
    fflush(stdout);
    sleep(1);
    printf("[normal] done\n");
    return 0;
}
