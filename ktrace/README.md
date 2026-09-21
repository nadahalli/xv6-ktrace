# ktrace: tracing kernel memory objects in xv6

ktrace records every read and write the xv6 kernel makes to a chosen
piece of its own data: which CPU, which process, which instruction,
what value, and when. It is the idea of the OSDI '26 paper "Ichnaea: A
Framework for Precise Tracking of Memory Objects" moved from user space
into a kernel, on hardware (RISC-V) that has no memory protection keys.

The claim is that the trace is lossless. The claim is checked, not
asserted: a QEMU plugin records the same accesses from outside the
machine, and the two logs must be identical.

## Result

Whole process table (23,040 bytes, 6 pages) watched on 4 CPUs while
`forktest` runs:

    $ ktrace/check.py --watch proc -- forktest
    kernel log: 308405 events from 135 instructions on cpus [0, 1, 2, 3]
    oracle log: 308405 events in the armed window
    faults: 492635 taken, 0 retried
    PASS: kernel log and oracle agree on every access, in order

"Agree" means the same sequence of (CPU, read or write, address, size,
value), across all CPUs, with no event missing, extra or reordered.

Two more results back this up.

The checker fails when it should. `make KTRACE_INJECT=NO_QUIESCE`
builds a tracer that arms a watch without waiting for other CPUs to
flush their TLBs. Twelve arm and stop cycles with `forktest` running on
the other CPUs:

    $ ktrace/check.py --cycles 12 --before "forktest &" --watch proc:4096 -- "echo hi"
    broken:  FAIL: 809 accesses reached the object untraced,
             first: 3 R 814169c0 8 3000 80001cc2
    correct: PASS, 285953 events, 1700026 faults

The race is narrow. A single arming under load passed the broken
kernel twice, which is why `--cycles` exists.

The kernel stays correct while traced. `usertests -q` with the whole
process table watched: ALL TESTS PASSED, with 399,233,674 faulting
instructions emulated. (The log overflows in that run. It tests the
emulation, not the log.)

## Using it

Inside xv6 the tracer is a device file:

    $ echo watch 8050d020 4 > ktrace     trace 4 bytes at that address
    $ forktest                           run anything
    $ echo stop > ktrace
    $ cat ktrace
    kt 0 R 8050d020 4 3 8000258c 0 1ad2584
    kt 0 W 8050d020 4 4 80002590 0 1ad307c

Columns: CPU, kind, address, size, value, pc of the accessing
instruction, pid (0 for the scheduler), time. Reading consumes events.
Addresses come from `riscv64-linux-gnu-nm -S kernel/kernel`.

From the host:

    make -C ktrace/plugin                 build the oracle
    ktrace/test_decode.py                 decoder vs objdump
    ktrace/check.py --watch ticks -- forktest
    ktrace/check.py --watch proc:360 -- forktest      first struct proc
    ktrace/check.py --watch proc -- forktest          whole table, ~7 min

`--watch` takes `SYMBOL[+OFFSET][:LENGTH]`. `--before CMD` runs a
command before arming and `--cycles N` repeats the whole sequence.
A second QEMU needs its own disk image: `KTRACE_FS=copy.img`.

## How it works

1. `watch` clears the valid bit on every page the range touches, in the
   kernel page table. Any access now page-faults.
2. `ktrace_fault()` decodes the faulting instruction, performs the load
   or store itself through a second mapping of the same physical page,
   logs it, and resumes at the next instruction.
3. The page is never made accessible while a watch is active. Tools
   that unprotect, single-step and re-protect leave a window in which
   other CPUs get through unseen. Emulating the access leaves none.

RISC-V has no single-step flag and no per-thread page permissions, so
the usual tricks were not available anyway.

## What made it hard

**The kernel page table is shared and xv6 cannot interrupt another
CPU.** After a page is revoked, other CPUs may hold a stale TLB entry
and keep reaching it directly. A watch is therefore not armed until
every CPU has flushed, which each does on its next trap or scheduler
pass. `watch` blocks until then, at most one timer tick.

**Spinlocks inside traced objects.** `struct proc` starts with a lock,
taken with `amoswap`. While CPUs with stale TLB entries can still reach
the word directly, emulating the swap as a load then a store would let
two CPUs take the same lock. The handler emulates it with a real
`amoswap` on the alias.

**One global order.** Every emulated access holds `kt.lock`. Accesses
to a protected page are totally ordered, the log records that order,
and the oracle sees the same order because QEMU reports each access
while the lock is still held. That is why the check can demand
identical sequences rather than identical sets.

**xv6 assumed kernel data access never traps.** Three places broke once
it could:
- `usertrap()` read `sepc`, `scause` and `stval` after touching the
  process table. A traced access in between overwrites all three, and a
  timer interrupt then looks like a page fault and kills the process.
- `usertrap()` and `forkret()` read `p->pagetable` after
  `prepare_return()` had pointed `stvec` at the user-mode entry. A
  fault there vectors into the user trap path from kernel mode.
- `kernelvec` saved only caller-saved registers. Emulating an arbitrary
  load or store needs all of them, saved and restored.

**The handler must never fault.** It would deadlock on its own lock. Its
state lives in a linker section on pages of its own, it reads no kernel
globals (it has its own page-table walk), and `watch` refuses any range
that shares a page with a boot stack or with that section.

## What the check does and does not prove

Proves: no access to the watched range went unlogged (any access the
oracle saw from outside the emulation code fails the run), and the log
has the right CPU, kind, address, size, value and order.

The oracle cannot see the original pc, because the original instruction
faulted and never executed. So the checker verifies each logged pc
statically: the kernel binary must have, at that address, a load, store
or swap of the logged kind and size.

Does not prove that the emulated access is what the original
instruction would have done, since the oracle sees only the emulation.
That rests on `test_decode.py`, which compares the decoder with objdump
on all 49,152 16-bit encodings and about 290,000 32-bit ones, and on
xv6 continuing to work while hundreds of thousands of its instructions
are emulated.

## Limits

- Kernel static data only (`etext` to `end`). In xv6 that is nearly
  everything: process, file, inode and buffer tables are all static.
  Pages from `kalloc` (pipes, page tables, kernel stacks) are refused.
- Device DMA and accesses through a user page table bypass the kernel
  page table. Neither the tracer nor the oracle sees them.
- `lr`/`sc`, floating-point loads and the other AMOs are not emulated.
  The xv6 kernel contains none. The handler panics if it meets one.
- The log holds 524,288 events. Beyond that, events are dropped and
  counted, and `check.py` fails the run.
- Everything on a protected page pays for the fault, watched or not. In
  the run above 492,635 faults produced 308,405 events.
- Timing under QEMU's emulation says nothing about cost on hardware.
