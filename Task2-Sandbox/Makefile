CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -std=c11
LDFLAGS = -pthread

TESTS = test_normal test_infinite test_cpu test_stubborn test_racy

all: sandbox sandbox_racy $(TESTS)

sandbox: Sandbox.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

test_%: test_%.c
	$(CC) $(CFLAGS) -o $@ $<

sandbox_racy: Sandbox_racy.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

test: all
	./run_tests.sh

race: all
	./race_demo.sh

clean:
	rm -f sandbox sandbox_racy $(TESTS)
	rm -rf logs

.PHONY: all test race clean
