#!/usr/bin/env python3
# Boot xv6 under QEMU, run shell commands on its console, print the output.
#
#   ktrace/run.py [--cpus N] [--plugin ARGS] [--timeout S] CMD [CMD ...]
#
# Each CMD is typed at the xv6 shell once the previous one has returned
# to the "$ " prompt.

import argparse, os, select, subprocess, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROMPT = b"$ "


def qemu_argv(cpus, plugin):
    argv = ["qemu-system-riscv64", "-machine", "virt", "-bios", "none",
            "-kernel", "kernel/kernel", "-m", "128M", "-smp", str(cpus),
            "-nographic",
            "-global", "virtio-mmio.force-legacy=false",
            "-drive", "file=fs.img,if=none,format=raw,id=x0",
            "-device", "virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0"]
    if plugin:
        argv += ["-plugin", plugin]
    return argv


def read_until_prompt(proc, deadline):
    buf = b""
    fd = proc.stdout.fileno()
    while not buf.endswith(PROMPT):
        left = deadline - time.time()
        if left <= 0:
            raise TimeoutError(buf.decode(errors="replace"))
        if select.select([fd], [], [], left)[0]:
            chunk = os.read(fd, 4096)
            if not chunk:
                raise EOFError(buf.decode(errors="replace"))
            buf += chunk
    return buf.decode(errors="replace")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cpus", type=int, default=4)
    ap.add_argument("--plugin", default="")
    ap.add_argument("--timeout", type=float, default=60)
    ap.add_argument("cmds", nargs="+")
    args = ap.parse_args()

    proc = subprocess.Popen(qemu_argv(args.cpus, args.plugin), cwd=ROOT,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    deadline = time.time() + args.timeout
    status = 0
    try:
        sys.stdout.write(read_until_prompt(proc, deadline))
        for c in args.cmds:
            proc.stdin.write(c.encode() + b"\n")
            proc.stdin.flush()
            sys.stdout.write(read_until_prompt(proc, deadline))
    except (TimeoutError, EOFError) as e:
        sys.stdout.write(str(e))
        sys.stdout.write("\n*** run.py: %s\n" % type(e).__name__)
        status = 1
    finally:
        # Ctrl-a x makes QEMU exit cleanly, so plugins flush their logs.
        try:
            proc.stdin.write(b"\x01x")
            proc.stdin.flush()
            proc.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            proc.kill()
            proc.wait()
    print()
    return status


if __name__ == "__main__":
    sys.exit(main())
