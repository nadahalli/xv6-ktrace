// Decoder for the RV64GC instructions that can take a load or store
// page fault: integer loads and stores, their compressed forms, and
// amoswap. No kernel dependencies, so ktrace/test_decode.py can
// compile it on the host and check it against the assembler.

#include "types.h"
#include "ktdecode.h"

#define BITS(x, hi, lo) (((x) >> (lo)) & ((1u << ((hi) - (lo) + 1)) - 1))

// returns 0 on success, -1 if insn is not a supported memory access.
// the caller passes at least the low 16 bits; if they announce a
// 32-bit instruction, the high 16 bits must be present too.
int
ktdecode(uint32 insn, struct ktinsn *d)
{
  d->sext = 0;
  d->rs2 = 0;

  if ((insn & 3) == 3) {
    int f3 = BITS(insn, 14, 12);

    d->len = 4;
    d->rs1 = BITS(insn, 19, 15);

    switch (insn & 0x7f) {
    case 0x03: // LB LH LW LD LBU LHU LWU
      if (f3 == 7)
        return -1;
      d->op = KT_LOAD;
      d->size = 1 << (f3 & 3);
      d->sext = (f3 & 4) == 0;
      d->reg = BITS(insn, 11, 7);
      d->imm = (int)insn >> 20;
      return 0;

    case 0x23: // SB SH SW SD
      if (f3 > 3)
        return -1;
      d->op = KT_STORE;
      d->size = 1 << f3;
      d->reg = BITS(insn, 24, 20);
      d->imm = ((int)insn >> 25) * 32 + (int)BITS(insn, 11, 7);
      return 0;

    case 0x2f: // AMOSWAP.W AMOSWAP.D
      if ((f3 != 2 && f3 != 3) || BITS(insn, 31, 27) != 1)
        return -1;
      d->op = KT_SWAP;
      d->size = 1 << f3;
      d->sext = 1;
      d->reg = BITS(insn, 11, 7);
      d->rs2 = BITS(insn, 24, 20);
      d->imm = 0;
      return 0;
    }
    return -1;
  }

  insn &= 0xffff;
  d->len = 2;
  int f3 = BITS(insn, 15, 13);
  int isload = (f3 == 2 || f3 == 3);

  if (f3 != 2 && f3 != 3 && f3 != 6 && f3 != 7)
    return -1; // floating point, or not a memory access
  d->op = isload ? KT_LOAD : KT_STORE;
  d->size = (f3 & 1) ? 8 : 4;
  d->sext = isload;

  switch (insn & 3) {
  case 0: // C.LW C.LD C.SW C.SD
    d->rs1 = 8 + BITS(insn, 9, 7);
    d->reg = 8 + BITS(insn, 4, 2);
    if (d->size == 4)
      d->imm = BITS(insn, 12, 10) << 3 | BITS(insn, 6, 6) << 2 |
               BITS(insn, 5, 5) << 6;
    else
      d->imm = BITS(insn, 12, 10) << 3 | BITS(insn, 6, 5) << 6;
    return 0;

  case 2: // C.LWSP C.LDSP C.SWSP C.SDSP
    d->rs1 = 2;
    if (isload) {
      d->reg = BITS(insn, 11, 7);
      if (d->reg == 0)
        return -1; // reserved encoding
      if (d->size == 4)
        d->imm = BITS(insn, 12, 12) << 5 | BITS(insn, 6, 4) << 2 |
                 BITS(insn, 3, 2) << 6;
      else
        d->imm = BITS(insn, 12, 12) << 5 | BITS(insn, 6, 5) << 3 |
                 BITS(insn, 4, 2) << 6;
    } else {
      d->reg = BITS(insn, 6, 2);
      if (d->size == 4)
        d->imm = BITS(insn, 12, 9) << 2 | BITS(insn, 8, 7) << 6;
      else
        d->imm = BITS(insn, 12, 10) << 3 | BITS(insn, 9, 7) << 6;
    }
    return 0;
  }
  return -1;
}
