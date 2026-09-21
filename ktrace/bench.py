#!/usr/bin/env python3
# Time forktest inside xv6, untraced and under three watches.
#
#   ktrace/bench.py [--cpus N] [--runs N]
#
# Wall-clock per forktest, measured on the host between shell prompts,
# under QEMU without the oracle plugin. The ratios say how tracing
# scales with how hot the watched page is. They say nothing about cost
# on hardware, where a trap is far more expensive relative to a load.

import argparse, os, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run  # noqa: E402
from check import symbols  # noqa: E402


def session(cpus, runs, setup):
    proc = subprocess.Popen(run.qemu_argv(cpus, ""), cwd=run.ROOT,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    deadline = time.time() + 1500
    out = run.read_until_prompt(proc, deadline)
    times = []
    try:
        for c in setup + ["forktest"] * runs + ["echo stop > ktrace"]:
            t0 = time.time()
            proc.stdin.write(c.encode() + b"\n")
            proc.stdin.flush()
            out += run.read_until_prompt(proc, deadline)
            if c == "forktest":
                times.append(time.time() - t0)
    finally:
        proc.kill()
        proc.wait()
    stats = [l for l in out.splitlines() if l.startswith("ktrace: stopped")]
    return times, stats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cpus", type=int, default=4)
    ap.add_argument("--runs", type=int, default=5)
    args = ap.parse_args()

    syms = symbols()
    cases = [
        ("untraced", []),
        ("ticks, 4 bytes on a quiet page",
         ["echo watch %x 4 > ktrace" % syms["ticks"][0]]),
        ("proc[0], 360 bytes",
         ["echo watch %x 360 > ktrace" % syms["proc"][0]]),
        ("whole process table",
         ["echo watch %x %d > ktrace" % syms["proc"]]),
    ]
    base = None
    for name, setup in cases:
        times, stats = session(args.cpus, args.runs, setup)
        median = sorted(times)[len(times) // 2]
        base = base or median
        print("%-32s median %.3fs  x%.1f" % (name, median, median / base))
        for s in stats:
            print("    " + s)


if __name__ == "__main__":
    main()
