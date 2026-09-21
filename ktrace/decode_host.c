// Host harness for test_decode.py: run kernel/ktdecode.c over
// instruction words given in hex on stdin, one per line.

#include <stdio.h>

#include "../kernel/types.h"
#include "../kernel/ktdecode.h"

int
main(void)
{
  static const char *ops[] = { "load", "store", "swap" };
  unsigned int insn;
  struct ktinsn d;

  while (scanf("%x", &insn) == 1) {
    if (ktdecode(insn, &d) < 0)
      printf("none\n");
    else
      printf("%s len=%d size=%d sext=%d reg=%d rs1=%d rs2=%d imm=%ld\n",
             ops[d.op], d.len, d.size, d.sext, d.reg, d.rs1, d.rs2, d.imm);
  }
  return 0;
}
