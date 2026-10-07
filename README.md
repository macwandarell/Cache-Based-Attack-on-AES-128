# Cache-Based-Attack-on-AES-128

## Description

A local cache-timing side-channel lab targeting a T-table based AES-128 implementation. A victim process loads the AES library and serves two-round encryption requests over shared memory, while an attacker process recovers the round key using Flush+Reload - without ever pausing the victim at a round boundary. Timing windows are not hardcoded; they are measured at runtime from the victim's own execution and the attacker's own Flush+Reload operation cost, then used to automatically pick safe observation points.

## Dependencies

* x86_64 CPU with `clflush`/`rdtscp` support

* POSIX shared memory (`librt`)

* gcc with `immintrin.h` intrinsics support

* Tested on: Intel Alder Lake i5-1240P (12th Gen Intel(R) Core(TM))

## Files

* `aes_shared.h` / `aes_shared.c` - the AES T-table library (compiled to `libaes.so`), loaded by the victim at runtime. Exposes `get_ttable_address`, `aes_round1`, `aes_round2`, `aes_round2_windowed`, `aes_sleep_mode_enabled`
* `control_shared.h` - shared control-block struct used for victim/attacker synchronization over shared memory
* `victim_runner.c` - the victim process; `dlopen`s the AES library and serves requests from a persistent loop, with no attacker-controlled pauses
* `attacker_phased.c` - the attacker process; forks/execs the victim and runs the three-phase key recovery

## Instructions

* Build the AES library (victim-side):

  * `gcc -shared -fPIC -O2 aes_shared.c -o libaes.so -lrt`
  * Add `-DAES_SLEEP_MODE` for the lab-assisted, easier-to-attack comparison build
* Build the victim: `gcc -O2 victim_runner.c -o victim_runner -ldl -lrt`
* Build the attacker: `gcc -O2 attacker_phased.c -o attacker_phased -lrt`
* Picking `attacker_cpu` / `victim_cpu`:

  * Flush+Reload needs the two processes to share the *last-level cache* (L3), but they should **not** be pinned to the same physical core or to sibling hyperthreads of the same core - that adds L1/L2 contention and scheduler noise that isn't part of the actual side channel.
  * Check your topology first: `lscpu -e` (columns `CPU CORE` tell you which logical CPUs share a physical core) or `cat /sys/devices/system/cpu/cpu*/topology/thread_siblings_list` to see sibling pairs directly.
  * Pick two logical CPUs that: (a) are on the same physical package (so they share L3), and (b) belong to *different* physical cores (so they don't share L1/L2 or a hyperthread pair). On a typical non-hyperthreaded or where core 0/1 aren't SMT siblings of each other, CPU 2 and CPU 4 (for example) are usually a safe pair - hence the defaults (`ATTACKER_CPU_DEFAULT 2`, `VICTIM_CPU_DEFAULT 4`) in the code. Always verify against `lscpu -e` on your own machine instead of assuming the same numbers apply.
  * Also leave CPU 0 free when possible - it tends to field more interrupts/kernel work and adds timing noise.
* Run the attacker (it starts the victim itself):

  * `./attacker_phased [victim_program] [aes_library] [attacker_cpu] [victim_cpu] [out_key_path] [phase1_traces] [phase2_repeats] [phase3_traces] [primitive_samples] [operation_percentile] [round2_reload_percentile]`
  * All arguments are optional and fall back to sane defaults
  * Example: `./attacker_phased ./victim_runner ./libaes.so 2 4 recovered_key.txt 4000 300 6000 200 75 95`
* The recovered key is written to `recovered_key_phased.txt` (or the path given by `out_key_path`)
* The victim's key is fixed lab configuration inside `victim_runner.c` and is never read by the attacker except for post-recovery verification

## Features

* **Phase 1 - Calibration:** measures the victim's natural round-1/round-2/gap timing distribution and the attacker's own Flush+Reload operation costs, then automatically derives the safest fixed observation windows instead of using machine-specific hardcoded multipliers
* **Phase 2 - Round-1 recovery:** windowed Flush+Reload against the T-tables to recover the high nibble of each key byte, letting the victim finish naturally afterward
* **Phase 3 - Round-2 recovery:** attacker-side eviction between rounds, followed by a windowed reload after round 2, feeding a per-group 16-bit exhaustive search over the round-2 equations to recover the remaining low nibbles
* CPU-affinity pinning for both attacker and victim to reduce scheduling noise
* Automatic abort with a clear message when calibration finds no usable timing window, rather than silently returning a garbage trace
* Ground-truth key comparison exists purely for experimental verification and is not consulted anywhere in the recovery path

## Experimental Results

* **Sleep mode:** 100% exact 128-bit key recovery across 100 test runs.
* **No-sleep mode:** 10,000 total attack attempts.

  * Exact 128-bit recoveries: 7
  * Exact 128-bit recovery rate: 0.07%
  * Partial key recoveries: 102
  * Usable timing windows: 109 (1.09%)
  * No usable timing windows: 9,891 (98.91%)
  * Mean matching bytes among recoveries: 5.61 / 16
  * Median matching bytes among recoveries: 4 / 16
  * Maximum matching bytes: 16 / 16
  * Mean phase-2 reload window: 441.2 cycles
  * Mean phase-3 eviction window: 441.2 cycles
  * Mean phase-3 reload window: 601.8 cycles
  * Phase-3 reload window coverage: 95.27%

## Future additions

Next up is implementing Prime+Probe as an attacker technique instead of Flush+Reload, and working through the extra difficulty it brings: no shared memory to flush directly, so eviction sets have to be built instead of using `clflush`; noisier timing due to set-associativity and address-to-set mapping; and no free "miss baseline," since eviction coverage itself has to be calibrated rather than assumed.
