// Decoded form of a RISC-V instruction that accesses memory.

enum ktop {
  KT_LOAD,  // x[reg] = mem[x[rs1] + imm]
  KT_STORE, // mem[x[rs1] + imm] = x[reg]
  KT_SWAP,  // x[reg] = mem[x[rs1]]; mem[x[rs1]] = x[rs2], atomically
};

struct ktinsn {
  enum ktop op;
  int len;  // instruction length in bytes, 2 or 4
  int size; // access size in bytes, 1, 2, 4 or 8
  int sext; // loads and swaps: sign-extend the value into x[reg]
  int reg;  // destination of a load or swap, source of a store
  int rs1;  // base address register
  int rs2;  // swaps: source register
  long imm; // offset added to x[rs1]
};

int ktdecode(uint32 insn, struct ktinsn *d);
