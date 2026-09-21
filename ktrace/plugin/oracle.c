// QEMU TCG plugin: ground-truth log of every guest access to chosen
// physical address ranges. The in-kernel tracer is checked against this.
//
//   -plugin ktrace/plugin/oracle.so,out=FILE,range=LO:HI[,range=LO:HI...]
//           [,marker=ADDR][,max=LINES]
//
// LO inclusive, HI exclusive, both hex physical addresses.
// One line per access:  cpu R|W paddr size value pc
//
// With marker=ADDR, the ranges are logged only while the guest says a
// watch is armed. The guest stores (watch << 1) | armed at ADDR, see
// ktrace_marker in kernel/ktrace.c, and those stores are logged too.
// Without it, a busy range is logged from boot to exit, which for the
// xv6 process table is gigabytes.
//
// After max lines (default 20 million) the log ends with "truncated".

#include <glib.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "qemu-plugin.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define MAXRANGES 16

static struct { uint64_t lo, hi; } ranges[MAXRANGES];
static int nranges;
static uint64_t marker;     // 0 if none
static uint64_t armed = ~0; // bitmask of armed watches
static uint64_t lines, maxlines = 20000000;
static FILE *out;
static GMutex lock;

static uint64_t
value_of(qemu_plugin_meminfo_t info)
{
  qemu_plugin_mem_value v = qemu_plugin_mem_get_value(info);
  switch (v.type) {
  case QEMU_PLUGIN_MEM_VALUE_U8:  return v.data.u8;
  case QEMU_PLUGIN_MEM_VALUE_U16: return v.data.u16;
  case QEMU_PLUGIN_MEM_VALUE_U32: return v.data.u32;
  case QEMU_PLUGIN_MEM_VALUE_U64: return v.data.u64;
  default:                        return v.data.u128.low;
  }
}

// call with the lock held.
static void
emit(unsigned cpu, qemu_plugin_meminfo_t info, uint64_t pa, unsigned size,
     void *pc)
{
  if (out == NULL || lines > maxlines)
    return;
  if (lines++ == maxlines) {
    fprintf(out, "truncated\n");
    return;
  }
  fprintf(out, "%u %c %" PRIx64 " %u %" PRIx64 " %" PRIx64 "\n",
          cpu, qemu_plugin_mem_is_store(info) ? 'W' : 'R',
          pa, size, value_of(info), (uint64_t)(uintptr_t)pc);
}

static void
mem_cb(unsigned int cpu, qemu_plugin_meminfo_t info, uint64_t vaddr, void *pc)
{
  struct qemu_plugin_hwaddr *hw = qemu_plugin_get_hwaddr(info, vaddr);
  if (hw == NULL || qemu_plugin_hwaddr_is_io(hw))
    return;
  uint64_t pa = qemu_plugin_hwaddr_phys_addr(hw);
  unsigned size = 1u << qemu_plugin_mem_size_shift(info);

  if (marker != 0 && pa == marker) {
    if (qemu_plugin_mem_is_store(info)) {
      uint64_t v = value_of(info);
      g_mutex_lock(&lock);
      if (v & 1)
        armed |= 1ull << (v >> 1);
      else
        armed &= ~(1ull << (v >> 1));
      emit(cpu, info, pa, size, pc);
      g_mutex_unlock(&lock);
    }
    return;
  }

  for (int i = 0; i < nranges; i++) {
    if (pa + size > ranges[i].lo && pa < ranges[i].hi) {
      g_mutex_lock(&lock);
      if (armed != 0)
        emit(cpu, info, pa, size, pc);
      g_mutex_unlock(&lock);
      return;
    }
  }
}

static void
tb_trans_cb(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
  size_t n = qemu_plugin_tb_n_insns(tb);
  for (size_t i = 0; i < n; i++) {
    struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
    void *pc = (void *)(uintptr_t)qemu_plugin_insn_vaddr(insn);
    qemu_plugin_register_vcpu_mem_cb(insn, mem_cb, QEMU_PLUGIN_CB_NO_REGS,
                                     QEMU_PLUGIN_MEM_RW, pc);
  }
}

static void
exit_cb(qemu_plugin_id_t id, void *p)
{
  g_mutex_lock(&lock);
  fclose(out);
  out = NULL;
  g_mutex_unlock(&lock);
}

QEMU_PLUGIN_EXPORT int
qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                    int argc, char **argv)
{
  const char *path = NULL;

  for (int i = 0; i < argc; i++) {
    if (strncmp(argv[i], "out=", 4) == 0) {
      path = argv[i] + 4;
    } else if (strncmp(argv[i], "marker=", 7) == 0) {
      marker = strtoull(argv[i] + 7, NULL, 16);
      armed = 0;
    } else if (strncmp(argv[i], "max=", 4) == 0) {
      maxlines = strtoull(argv[i] + 4, NULL, 10);
    } else if (strncmp(argv[i], "range=", 6) == 0 && nranges < MAXRANGES) {
      char *end;
      ranges[nranges].lo = strtoull(argv[i] + 6, &end, 16);
      if (*end != ':') {
        fprintf(stderr, "oracle: bad range %s\n", argv[i]);
        return -1;
      }
      ranges[nranges].hi = strtoull(end + 1, NULL, 16);
      nranges++;
    } else {
      fprintf(stderr, "oracle: bad argument %s\n", argv[i]);
      return -1;
    }
  }
  if (path == NULL || nranges == 0) {
    fprintf(stderr, "oracle: need out=FILE and at least one range=LO:HI\n");
    return -1;
  }
  if ((out = fopen(path, "w")) == NULL) {
    perror(path);
    return -1;
  }

  qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans_cb);
  qemu_plugin_register_atexit_cb(id, exit_cb, NULL);
  return 0;
}
