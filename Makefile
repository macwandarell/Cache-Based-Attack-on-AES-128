CC      = gcc
CFLAGS  = -O2 -Wall -Wextra
LDLIBS  = -lrt

AES_SRC      = aes_shared.c
AES_HDR      = aes_shared.h
CONTROL_HDR  = control_shared.h

VICTIM_SRC   = victim_runner.c
ATTACK_SRC   = attacker_phased.c

LIBAES       = libaes.so
LIBAES_SLEEP = libaes_sleep.so
VICTIM       = victim_runner
ATTACKER     = attacker_phased

ATTACKER_CPU = 2
VICTIM_CPU   = 4

PHASE1_TRACES       = 4000
PHASE2_REPEATS      = 300
PHASE3_TRACES       = 6000
PRIMITIVE_SAMPLES   = 200
OPERATION_PERCENTILE = 75
ROUND2_PERCENTILE    = 95

OUTPUT_KEY = recovered_key.txt

.PHONY: all sleep run run-sleep clean rebuild

all: $(LIBAES) $(VICTIM) $(ATTACKER)

$(LIBAES): $(AES_SRC) $(AES_HDR)
	$(CC) $(CFLAGS) -shared -fPIC $(AES_SRC) -o $@ $(LDLIBS)

$(LIBAES_SLEEP): $(AES_SRC) $(AES_HDR)
	$(CC) $(CFLAGS) -shared -fPIC -DAES_SLEEP_MODE $(AES_SRC) -o $@ $(LDLIBS)

$(VICTIM): $(VICTIM_SRC) $(CONTROL_HDR) $(AES_HDR)
	$(CC) $(CFLAGS) $(VICTIM_SRC) -o $@ -ldl $(LDLIBS)

$(ATTACKER): $(ATTACK_SRC) $(CONTROL_HDR)
	$(CC) $(CFLAGS) $(ATTACK_SRC) -o $@ $(LDLIBS)

# Build the sleeplibrary
sleep: $(LIBAES_SLEEP) $(VICTIM) $(ATTACKER)

# The normal version
run: $(LIBAES) $(VICTIM) $(ATTACKER)
	./$(ATTACKER) ./$(VICTIM) ./$(LIBAES) $(ATTACKER_CPU) $(VICTIM_CPU) $(OUTPUT_KEY) $(PHASE1_TRACES) $(PHASE2_REPEATS) $(PHASE3_TRACES) $(PRIMITIVE_SAMPLES) $(OPERATION_PERCENTILE) $(ROUND2_PERCENTILE)

# The sleep version
run-sleep: $(LIBAES_SLEEP) $(VICTIM) $(ATTACKER)
	./$(ATTACKER) ./$(VICTIM) ./$(LIBAES_SLEEP) $(ATTACKER_CPU) $(VICTIM_CPU) $(OUTPUT_KEY) $(PHASE1_TRACES) $(PHASE2_REPEATS) $(PHASE3_TRACES) $(PRIMITIVE_SAMPLES) $(OPERATION_PERCENTILE) $(ROUND2_PERCENTILE)

rebuild: clean all

clean:
	rm -f $(LIBAES) $(LIBAES_SLEEP) $(VICTIM) $(ATTACKER)
	rm -f recovered_key.txt recovered_key_phased.txt