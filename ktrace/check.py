#!/usr/bin/env python3
# Judge the in-kernel tracer against the QEMU plugin oracle.
#
#   ktrace/check.py [--cpus N] [--timeout S] [--before CMD] ... [--cycles N]
#                   --watch SYM[+OFF][:LEN] ... -- CMD ...
#
# Boots xv6 with the oracle attached, arms the watches, runs the
# workload commands, stops tracing, dumps the in-kernel log, and
# requires that:
#
#   1. The in-kernel log equals the oracle's log of the same ranges
#      between the arm and stop markers: same accesses, same order,
#      same CPU, kind, address, size and value.
#   2. Every oracle access in that window came from the tracer's
#      emulation code. One from anywhere else reached the object
#      without being traced.
#   3. Every pc in the in-kernel log is, in the kernel binary, a load,
#      store or swap of the logged kind and size.

import argparse, os, re, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from test_decode import MNEMONICS  # noqa: E402

KERNEL = os.path.join(ROOT, "kernel", "kernel")
EMULATOR = ("ktrace_fault", "ktload", "ktstore", "ktswap")


def symbols():
    out = subprocess.run(["riscv64-linux-gnu-nm", "-S", KERNEL], check=True,
                         capture_output=True, text=True).stdout
    syms = {}
    for line in out.splitlines():
        f = line.split()
        if len(f) == 4:
            syms[f[3]] = (int(f[0], 16), int(f[1], 16))
    return syms


def static_accesses():
    out = subprocess.run(["riscv64-linux-gnu-objdump", "-d", "-M",
                          "no-aliases", KERNEL], check=True,
                         capture_output=True, text=True).stdout
    table = {}
    for line in out.splitlines():
        f = line.split("\t")
        if len(f) >= 3 and f[0].strip().endswith(":"):
            mn = re.sub(r"\.(aq|rl|aqrl)$", "", f[2].strip())
            if mn in MNEMONICS:
                table[int(f[0].strip()[:-1], 16)] = MNEMONICS[mn]
    return table


def resolve(spec, syms):
    m = re.fullmatch(r"(\w+)(?:\+(\w+))?(?::(\w+))?", spec)
    if not m or m.group(1) not in syms:
        sys.exit("unknown symbol in --watch %s" % spec)
    addr, size = syms[m.group(1)]
    off = int(m.group(2), 0) if m.group(2) else 0
    length = int(m.group(3), 0) if m.group(3) else size - off
    return addr + off, length


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cpus", type=int, default=4)
    ap.add_argument("--timeout", type=float, default=600)
    ap.add_argument("--watch", action="append", required=True)
    ap.add_argument("--keep", help="directory to keep the raw logs in")
    ap.add_argument("--before", action="append", default=[],
                    help="command to run before arming, e.g. 'forktest &', "
                         "so that other CPUs are busy while the watch arms")
    ap.add_argument("--cycles", type=int, default=1,
                    help="repeat before, watch, workload, stop this many "
                         "times; arming is the delicate moment")
    ap.add_argument("cmds", nargs="+")
    args = ap.parse_args()

    syms = symbols()
    marker = syms["ktrace_marker"][0]
    watches = [resolve(w, syms) for w in args.watch]
    emulator = [syms[s] for s in EMULATOR if s in syms]

    keep = args.keep or tempfile.mkdtemp(prefix="ktrace-check.")
    os.makedirs(keep, exist_ok=True)
    oracle_path = os.path.join(keep, "oracle.log")
    ranges = ["range=%x:%x" % (a, a + n) for a, n in watches]
    ranges.append("marker=%x" % marker)
    plugin = "%s,out=%s,%s" % (os.path.join(HERE, "plugin", "oracle.so"),
                               oracle_path, ",".join(ranges))

    cycle = args.before + ["echo watch %x %d > ktrace" % w for w in watches]
    cycle += args.cmds + ["echo stop > ktrace"]
    cmds = cycle * args.cycles + ["cat ktrace"]
    run = subprocess.run([sys.executable, os.path.join(HERE, "run.py"),
                          "--cpus", str(args.cpus), "--timeout",
                          str(args.timeout), "--plugin", plugin] + cmds,
                         capture_output=True, text=True)
    console = run.stdout
    with open(os.path.join(keep, "console.log"), "w") as f:
        f.write(console)
    if run.returncode != 0:
        print(console[-2000:])
        sys.exit("FAIL: xv6 did not finish the workload (logs in %s)" % keep)

    # the kernel's view.
    slots = {}
    for m in re.finditer(r"ktrace: watch (\d+) armed: 0x(\w+) len (\d+)", console):
        a = int(m.group(2), 16)
        slots[int(m.group(1))] = (a, a + int(m.group(3)))
    # the counts are cumulative, so the last stop has the totals.
    stopped = re.findall(r"ktrace: stopped: (\d+) events logged, (\d+) dropped, "
                         r"(\d+) faults, (\d+) retried", console)
    if len(slots) != len(watches) or len(stopped) != args.cycles:
        print(console[-2000:])
        sys.exit("FAIL: watches were not armed and stopped (logs in %s)" % keep)
    logged, dropped, faults, retried = map(int, stopped[-1])

    ours = []
    for line in console.splitlines():
        f = line.split()
        if len(f) == 9 and f[0] == "kt":
            ours.append((int(f[1]), f[2], int(f[3], 16), int(f[4]),
                         int(f[5], 16), int(f[6], 16)))
    if len(ours) != logged:
        sys.exit("FAIL: kernel logged %d events, console shows %d (logs in %s)"
                 % (logged, len(ours), keep))

    # the oracle's view, cut down to the windows the markers delimit.
    armed = set()
    theirs = []
    bypass = []
    with open(oracle_path) as f:
        for line in f:
            if line.strip() == "truncated":
                sys.exit("FAIL: oracle log hit its line limit (logs in %s)"
                         % keep)
            cpu, kind, addr, size, val, pc = line.split()
            cpu, size = int(cpu), int(size)
            addr, val, pc = int(addr, 16), int(val, 16), int(pc, 16)
            if addr == marker:
                (armed.add if val & 1 else armed.discard)(val >> 1)
                continue
            if not any(addr < slots[s][1] and addr + size > slots[s][0]
                       for s in armed):
                continue
            theirs.append((cpu, kind, addr, size, val))
            if not any(lo <= pc < lo + n for lo, n in emulator):
                bypass.append(line.strip())

    failures = []

    n = min(len(ours), len(theirs)) if dropped else max(len(ours), len(theirs))
    for i in range(n):
        a = ours[i][:5] if i < len(ours) else None
        b = theirs[i] if i < len(theirs) else None
        if a != b:
            failures.append("logs diverge at event %d: kernel %s, oracle %s"
                            % (i, a, b))
            break
    if dropped:
        failures.append("kernel log overflowed and dropped %d events" % dropped)

    if bypass:
        failures.append("%d accesses reached the object untraced, first: %s"
                        % (len(bypass), bypass[0]))

    table = static_accesses()
    for cpu, kind, addr, size, val, pc in ours:
        want = table.get(pc)
        ok = want is not None and want[1] == size and (
            want[0] == "swap" or want[0] == ("load" if kind == "R" else "store"))
        if not ok:
            failures.append("pc %x logged as %s size %d, binary says %s"
                            % (pc, kind, size, want))
            break

    cpus = sorted(set(e[0] for e in ours))
    pcs = len(set(e[5] for e in ours))
    print("watched: %s" % ", ".join("%x+%d" % w for w in watches))
    print("kernel log: %d events from %d instructions on cpus %s"
          % (len(ours), pcs, cpus))
    print("oracle log: %d events in the armed window" % len(theirs))
    print("faults: %d taken, %d retried" % (faults, retried))
    print("raw logs: %s" % keep)
    for f in failures:
        print("FAIL: " + f)
    if not failures:
        print("PASS: kernel log and oracle agree on every access, in order")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
