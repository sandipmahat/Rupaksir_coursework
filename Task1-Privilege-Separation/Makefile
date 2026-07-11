# Makefile -- Privilege-Separated Password Validation (Task 1)
#
#   make            build backend and frontend
#   make test       build, then run the automated test suite (needs root)
#   make disassembly show that secure_wipe / explicit_bzero survives -O2
#   make evidence   list the privilege-management syscalls linked in
#   make clean      remove build artefacts

CC      := gcc
CFLAGS  := -O2 -Wall -Wextra -Wformat=2 -Wshadow -std=gnu11
LDLIBS  := -lrt
TARGETS := backend frontend

.PHONY: all test disassembly evidence clean

all: $(TARGETS)

backend: Backend.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

frontend: Frontend.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

# Run the automated harness. Root is needed so the backend can start as root
# and then drop; without root the drop step is skipped but the rest still runs.
test: all
	./run_tests.sh

# Show that the compiler did NOT delete the secret-scrubbing store at -O2.
disassembly: backend
	@echo "== secure_wipe() in the optimized backend =="
	@objdump -d backend | grep -A6 '<secure_wipe>:'
	@echo
	@echo "If you see a call/jmp to explicit_bzero above, the wipe was preserved."

# List the privilege-dropping syscalls actually linked into the binary.
evidence: backend
	@echo "== privilege-management syscalls linked into backend =="
	@objdump -d backend | grep -oE 'setresuid@plt|setresgid@plt|setgroups@plt|seteuid@plt' | sort -u

clean:
	rm -f $(TARGETS)
	rm -f /tmp/privsep_auth.sock
