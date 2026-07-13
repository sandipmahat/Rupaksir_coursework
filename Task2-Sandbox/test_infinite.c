/* test_infinite.c -- never terminates. The sandbox must stop it. */
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    printf("[infinite] looping forever, I will never exit\n");
    fflush(stdout);
    for (;;) {
        sleep(1);
    }
    return 0;
}
