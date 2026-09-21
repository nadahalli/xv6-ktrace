#!/usr/bin/env python3
# Check kernel/ktdecode.c against GNU objdump.
#
# Every 16-bit instruction pattern, and a large random sample of 32-bit
# ones biased toward the load, store and atomic opcodes, goes through
# both decoders. They must agree on which words are supported memory
# accesses and on every decoded field.

import os, random, re, struct, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OBJDUMP = "riscv64-linux-gnu-objdump"

# mnemonic -> (op, size, sext)
MNEMONICS = {
    "lb": ("load", 1, 1), "lh": ("load", 2, 1), "lw": ("load", 4, 1),
    "ld": ("load", 8, 1), "lbu": ("load", 1, 0), "lhu": ("load", 2, 0),
    "lwu": ("load", 4, 0),
    "sb": ("store", 1, 0), "sh": ("store", 2, 0), "sw": ("store", 4, 0),
    "sd": ("store", 8, 0),
    "c.lw": ("load", 4, 1), "c.ld": ("load", 8, 1),
    "c.sw": ("store", 4, 0), "c.sd": ("store", 8, 0),
    "c.lwsp": ("load", 4, 1), "c.ldsp": ("load", 8, 1),
    "c.swsp": ("store", 4, 0), "c.sdsp": ("store", 8, 0),
    "amoswap.w": ("swap", 4, 1), "amoswap.d": ("swap", 8, 1),
}

MEM = re.compile(r"^x(\d+),(-?\d+)\(x(\d+)\)$")
AMO = re.compile(r"^x(\d+),x(\d+),\(x(\d+)\)$")


def expected(mnemonic, operands, length):
    # objdump spells the ordering-hint bits of an AMO as a suffix.
    mnemonic = re.sub(r"^(amoswap\.[wd])\.(aq|rl|aqrl)$", r"\1", mnemonic)
    if mnemonic not in MNEMONICS:
        return "none"
    op, size, sext = MNEMONICS[mnemonic]
    if op == "swap":
        m = AMO.match(operands)
        reg, rs2, rs1, imm = m.group(1), m.group(2), m.group(3), "0"
    else:
        m = MEM.match(operands)
        reg, imm, rs1, rs2 = m.group(1), m.group(2), m.group(3), "0"
    return "%s len=%d size=%d sext=%d reg=%s rs1=%s rs2=%s imm=%s" % (
        op, length, size, sext, reg, rs1, rs2, imm)


def objdump(words, width):
    with tempfile.NamedTemporaryFile(suffix=".bin") as f:
        fmt = "<H" if width == 2 else "<I"
        f.write(b"".join(struct.pack(fmt, w) for w in words))
        f.flush()
        out = subprocess.run(
            [OBJDUMP, "-D", "-b", "binary", "-m", "riscv:rv64",
             "-M", "numeric,no-aliases", f.name],
            check=True, capture_output=True, text=True).stdout
    rows = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 3 or not parts[0].strip().endswith(":"):
            continue
        mnemonic = parts[2].strip()
        operands = parts[3].strip() if len(parts) > 3 else ""
        rows.append((mnemonic, operands.split("#")[0].strip()))
    if len(rows) != len(words):
        sys.exit("objdump lost sync: %d words, %d rows" % (len(words), len(rows)))
    return rows


def ours(words):
    exe = os.path.join(tempfile.gettempdir(), "ktdecode_host.%d" % os.getpid())
    subprocess.run(["cc", "-O1", "-Wall", "-Werror", "-o", exe,
                    os.path.join(HERE, "decode_host.c"),
                    os.path.join(ROOT, "kernel", "ktdecode.c")], check=True)
    try:
        out = subprocess.run([exe], input="\n".join("%x" % w for w in words),
                             check=True, capture_output=True, text=True).stdout
    finally:
        os.unlink(exe)
    return out.splitlines()


def check(words, width):
    bad = 0
    hits = 0
    for w, (mn, operands), got in zip(words, objdump(words, width), ours(words)):
        want = expected(mn, operands, width)
        hits += want != "none"
        if want != got:
            bad += 1
            if bad <= 10:
                print("MISMATCH %0*x  objdump: %s %s\n   want %s\n   got  %s"
                      % (width * 2, w, mn, operands, want, got))
    print("%d-bit: %d words, %d memory accesses, %d mismatches"
          % (width * 8, len(words), hits, bad))
    return bad


def main():
    random.seed(1)
    short = [w for w in range(1 << 16) if w & 3 != 3]

    wide = []
    for _ in range(300000):
        w = random.getrandbits(32)
        if random.random() < 0.8:
            w = (w & ~0x7f) | random.choice([0x03, 0x23, 0x2f])
        w |= 3
        if w & 0x1f == 0x1f:  # longer-than-32-bit encoding
            continue
        wide.append(w)

    return 1 if check(short, 2) + check(wide, 4) else 0


if __name__ == "__main__":
    sys.exit(main())
