//
// In-kernel memory object tracer.
//
// A watch names a byte range of kernel data. Every page the range
// touches loses its valid bit in the kernel page table, so each load
// or store to it takes a page fault. ktrace_fault() decodes the
// faulting instruction, performs the access itself through an alias
// mapping of the same physical page, logs it, and resumes after the
// instruction. The page is never made accessible while a watch is
// active, so no CPU gets a window in which an access goes unseen.
//
// The rules that make this safe:
//
// 1. Everything ktrace_fault() reads or writes, other than the traced
//    object itself, lives in the .bss.ktrace section or on the kernel
//    stack. Neither can be watched. A fault inside the handler would
//    deadlock on kt.lock, so the handler calls nothing outside this
//    file except panic().
//
// 2. kt.lock is held for the whole of each emulated access, by every
//    CPU. Accesses to a protected page are therefore totally ordered,
//    and the log records that order.
//
// 3. All CPUs share one kernel page table and xv6 has no way to
//    interrupt another CPU. After revoking a page, a watch is not
//    armed until every CPU has flushed its TLB, which each does on its
//    next trap or scheduler pass (ktrace_quiesce). Until then another
//    CPU may still reach the page directly. amoswap is therefore
//    emulated with a real amoswap, never as a load then a store.
//
// 4. Only kernel data between etext and end can be watched. That
//    excludes page-table pages, kernel stacks and trapframes, which
//    the trap path itself depends on.
//
// Writes by devices (DMA) and accesses through a user page table do
// not go through the kernel page table and are not seen.
//
// User interface, a device file:
//   echo watch ADDR LEN > ktrace   start tracing a range
//   echo stop > ktrace             stop all watches, keep the log
//   echo clear > ktrace            discard the log
//   cat ktrace                     read and consume the log
//

#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "proc.h"
#include "fs.h"
#include "file.h"
#include "defs.h"
#include "ktrace.h"
#include "ktdecode.h"

#define KTDATA __attribute__((section(".bss.ktrace")))

struct ktevent {
  uint64 addr;
  uint64 val;
  uint64 pc;
  uint64 time;
  int pid;
  uchar cpu;
  uchar kind; // 'R' or 'W'
  uchar size;
};

struct ktwatch {
  int used;
  int armed; // every CPU has flushed; accesses are being logged
  uint64 lo;
  uint64 hi;
};

struct ktpage {
  uint64 pa;
  pte_t *pte;
  int refs; // watches touching this page; 0 means the slot is free
};

static KTDATA struct {
  uint lock; // raw test-and-set lock. hold only with interrupts off.
  pagetable_t kpgtbl;
  volatile uint64 gen;            // bumped whenever a page is revoked
  volatile uint64 hartgen[NCPU];  // last gen each CPU flushed for
  volatile uint online;           // bitmask of running CPUs
  int pid[NCPU];                  // process running on each CPU, or 0
  int busy[NCPU];                 // CPU is inside ktrace_fault()
  struct ktwatch watch[KTRACE_NWATCH];
  struct ktpage page[KTRACE_NPAGE];
  uint64 head; // events ever logged
  uint64 tail; // events ever read or cleared
  uint64 dropped;
  uint64 nfault;
  uint64 nretry;
} kt;

static KTDATA struct ktevent ktlog[KTRACE_NEVENT];

// written under kt.lock as (watch << 1) | armed, at the instant a
// watch starts or stops logging. ktrace/plugin/oracle.c watches this
// address to find the same instants in its own log.
volatile uint64 ktrace_marker KTDATA;

extern char etext[], end[], stack0[];
extern char ktrace_start[], ktrace_end[]; // kernel.ld

// command side. ordinary kernel data, used only in process context.
static struct sleeplock cmdlock;
static char cmdbuf[64];
static int cmdlen;

static void
ktlock(void)
{
  while (__sync_lock_test_and_set(&kt.lock, 1) != 0)
    ;
}

static void
ktunlock(void)
{
  __sync_lock_release(&kt.lock);
}

// leaf PTE for va in the kernel page table, or 0.
// like walk(), but reads no kernel globals, see rule 1.
static pte_t *
ktwalk(uint64 va)
{
  pagetable_t pt = kt.kpgtbl;

  for (int level = 2; level > 0; level--) {
    pte_t pte = pt[PX(level, va)];
    if ((pte & PTE_V) == 0)
      return 0;
    pt = (pagetable_t)PTE2PA(pte);
  }
  return &pt[PX(0, va)];
}

static struct ktpage *
ktfindpage(uint64 pa)
{
  for (struct ktpage *pg = kt.page; pg < &kt.page[KTRACE_NPAGE]; pg++)
    if (pg->refs > 0 && pg->pa == pa)
      return pg;
  return 0;
}

static void
ktlogevent(int cpu, int kind, uint64 addr, int size, uint64 val, uint64 pc)
{
  struct ktwatch *w;

  for (w = kt.watch; w < &kt.watch[KTRACE_NWATCH]; w++)
    if (w->armed && addr < w->hi && addr + size > w->lo)
      break;
  if (w == &kt.watch[KTRACE_NWATCH])
    return; // an unwatched neighbour on a protected page

  if (kt.head - kt.tail == KTRACE_NEVENT) {
    kt.dropped++;
    return;
  }
  struct ktevent *e = &ktlog[kt.head++ % KTRACE_NEVENT];
  e->addr = addr;
  e->val = val;
  e->pc = pc;
  e->time = r_time();
  e->pid = kt.pid[cpu];
  e->cpu = cpu;
  e->kind = kind;
  e->size = size;
}

static uint64
ktsext(uint64 v, int size)
{
  int shift = 64 - 8 * size;
  return (uint64)((long)(v << shift) >> shift);
}

static uint64
ktload(uint64 a, int size)
{
  switch (size) {
  case 1:
    return *(volatile uchar *)a;
  case 2:
    return *(volatile ushort *)a;
  case 4:
    return *(volatile uint *)a;
  default:
    return *(volatile uint64 *)a;
  }
}

static void
ktstore(uint64 a, int size, uint64 v)
{
  switch (size) {
  case 1:
    *(volatile uchar *)a = v;
    break;
  case 2:
    *(volatile ushort *)a = v;
    break;
  case 4:
    *(volatile uint *)a = v;
    break;
  default:
    *(volatile uint64 *)a = v;
    break;
  }
}

static uint64
ktswap(uint64 a, int size, uint64 v)
{
  if (size == 4)
    return __atomic_exchange_n((uint *)a, (uint)v, __ATOMIC_SEQ_CST);
  return __atomic_exchange_n((uint64 *)a, v, __ATOMIC_SEQ_CST);
}

// regs points at the frame kernelvec.S saved: x1 at regs[0], x31 at
// regs[30]. kernelvec restores every register from it except tp.
static uint64
ktgetreg(uint64 *regs, int r)
{
  return r == 0 ? 0 : regs[r - 1];
}

static void
ktsetreg(uint64 *regs, int r, uint64 v)
{
  if (r == 4)
    panic("ktrace: load into tp");
  if (r != 0)
    regs[r - 1] = v;
}

// called by kerneltrap() for a load or store page fault in the kernel.
// returns the pc to resume at, or 0 if the fault is not ours.
uint64
ktrace_fault(uint64 *regs, uint64 scause, uint64 sepc, uint64 stval)
{
  int cpu = r_tp();
  struct ktinsn d;

  if (stval < (uint64)etext || stval >= (uint64)end)
    return 0;
  if (kt.busy[cpu])
    panic("ktrace: fault inside fault handler");
  kt.busy[cpu] = 1;
  ktlock();
  kt.nfault++;

  if (ktfindpage(PGROUNDDOWN(stval)) == 0) {
    // the page is not protected. if the PTE allows the access, the
    // page was released while this CPU waited for kt.lock, or the TLB
    // held a stale entry: flush and run the instruction again.
    pte_t *pte = ktwalk(stval);
    int need = PTE_V | (scause == 13 ? PTE_R : PTE_W);
    int ok = pte != 0 && (*pte & need) == need;
    if (ok)
      kt.nretry++;
    ktunlock();
    kt.busy[cpu] = 0;
    if (!ok)
      return 0;
    sfence_vma();
    return sepc;
  }

  uint32 insn = *(ushort *)sepc;
  if ((insn & 3) == 3)
    insn |= (uint32) * (ushort *)(sepc + 2) << 16;
  if (ktdecode(insn, &d) < 0) {
    printk("ktrace: sepc=0x%lx insn=0x%x\n", sepc, insn);
    panic("ktrace: cannot emulate instruction");
  }

  uint64 addr = ktgetreg(regs, d.rs1) + d.imm;
  if (stval < addr || stval >= addr + d.size || addr < (uint64)etext ||
      addr + d.size > PHYSTOP) {
    printk("ktrace: sepc=0x%lx stval=0x%lx addr=0x%lx\n", sepc, stval, addr);
    panic("ktrace: decoded address does not match fault");
  }
  uint64 alias = addr + KTRACE_ALIAS;
  uint64 v, old;

  switch (d.op) {
  case KT_LOAD:
    v = ktload(alias, d.size);
    ktlogevent(cpu, 'R', addr, d.size, v, sepc);
    ktsetreg(regs, d.reg, d.sext ? ktsext(v, d.size) : v);
    break;
  case KT_STORE:
    v = ktgetreg(regs, d.reg);
    if (d.size < 8)
      v &= (1UL << (8 * d.size)) - 1;
    ktstore(alias, d.size, v);
    ktlogevent(cpu, 'W', addr, d.size, v, sepc);
    break;
  case KT_SWAP:
    v = ktgetreg(regs, d.rs2);
    if (d.size < 8)
      v &= (1UL << (8 * d.size)) - 1;
    old = ktswap(alias, d.size, v);
    ktlogevent(cpu, 'R', addr, d.size, old, sepc);
    ktlogevent(cpu, 'W', addr, d.size, v, sepc);
    ktsetreg(regs, d.reg, ktsext(old, d.size));
    break;
  }

  ktunlock();
  kt.busy[cpu] = 0;
  return sepc + d.len;
}

// flush this CPU's TLB if a page has been revoked since it last did.
// interrupts must be off, so that the CPU that flushes is the CPU
// that gets the credit.
void
ktrace_quiesce(void)
{
  int cpu = r_tp();
  uint64 gen = kt.gen; // read before flushing, not after

  if (kt.hartgen[cpu] != gen) {
    sfence_vma();
    kt.hartgen[cpu] = gen;
  }
}

// the scheduler reports which process this CPU is about to run.
void
ktrace_setpid(int pid)
{
  kt.pid[r_tp()] = pid;
}

void
ktraceinithart(void)
{
  push_off();
  ktlock();
  kt.online |= 1 << r_tp();
  ktunlock();
  pop_off();
}

static int
ktoverlap(uint64 lo, uint64 hi, char *flo, char *fhi)
{
  return PGROUNDDOWN(lo) < PGROUNDUP((uint64)fhi) &&
         PGROUNDUP(hi) > PGROUNDDOWN((uint64)flo);
}

static void
ktwatch(uint64 lo, uint64 len)
{
  uint64 hi = lo + len;
  uint64 gen;
  int slot = -1;
  int nfree = 0;
  int npage = 0;

  if (len == 0 || hi < lo || lo < (uint64)etext || hi > (uint64)end) {
    printk("ktrace: can only watch kernel data, 0x%lx to 0x%lx\n",
           (uint64)etext, (uint64)end);
    return;
  }
  if (ktoverlap(lo, hi, stack0, stack0 + 4096 * NCPU) ||
      ktoverlap(lo, hi, ktrace_start, ktrace_end)) {
    printk("ktrace: range shares a page with a boot stack or the tracer\n");
    return;
  }

  push_off();
  ktlock();
  for (int i = KTRACE_NWATCH - 1; i >= 0; i--)
    if (!kt.watch[i].used)
      slot = i;
  for (uint64 pa = PGROUNDDOWN(lo); pa < hi; pa += PGSIZE)
    if (ktfindpage(pa) == 0)
      npage++;
  for (struct ktpage *pg = kt.page; pg < &kt.page[KTRACE_NPAGE]; pg++)
    if (pg->refs == 0)
      nfree++;
  if (slot < 0 || npage > nfree) {
    ktunlock();
    pop_off();
    printk("ktrace: out of watch or page slots\n");
    return;
  }

  for (uint64 pa = PGROUNDDOWN(lo); pa < hi; pa += PGSIZE) {
    struct ktpage *pg = ktfindpage(pa);
    if (pg == 0) {
      for (pg = kt.page; pg->refs != 0; pg++)
        ;
      pg->pa = pa;
      pg->pte = ktwalk(pa);
      if (pg->pte == 0 || (*pg->pte & PTE_V) == 0)
        panic("ktrace: kernel data not mapped");
      *pg->pte &= ~PTE_V;
    }
    pg->refs++;
  }
  kt.watch[slot].used = 1;
  kt.watch[slot].armed = 0;
  kt.watch[slot].lo = lo;
  kt.watch[slot].hi = hi;
  gen = ++kt.gen;
  ktunlock();
  pop_off();

  // rule 3: wait until no CPU can still reach the pages directly.
  for (;;) {
    int waiting = 0;
    push_off();
    ktrace_quiesce();
    pop_off();
    for (int i = 0; i < NCPU; i++)
      if ((kt.online & (1 << i)) && kt.hartgen[i] < gen)
        waiting = 1;
    if (!waiting)
      break;
    yield();
  }

  push_off();
  ktlock();
  kt.watch[slot].armed = 1;
  ktrace_marker = (slot << 1) | 1;
  ktunlock();
  pop_off();
  printk("ktrace: watch %d armed: 0x%lx len %ld\n", slot, lo, len);
}

static void
ktstop(void)
{
  push_off();
  ktlock();
  for (int i = 0; i < KTRACE_NWATCH; i++) {
    struct ktwatch *w = &kt.watch[i];
    if (!w->used)
      continue;
    w->armed = 0;
    ktrace_marker = i << 1;
    for (uint64 pa = PGROUNDDOWN(w->lo); pa < w->hi; pa += PGSIZE) {
      struct ktpage *pg = ktfindpage(pa);
      if (--pg->refs == 0)
        *pg->pte |= PTE_V;
    }
    w->used = 0;
  }
  uint64 logged = kt.head - kt.tail, dropped = kt.dropped;
  uint64 nfault = kt.nfault, nretry = kt.nretry;
  ktunlock();
  pop_off();
  printk("ktrace: stopped: %ld events logged, %ld dropped, "
         "%ld faults, %ld retried\n", logged, dropped, nfault, nretry);
}

static void
ktclear(void)
{
  push_off();
  ktlock();
  kt.tail = kt.head;
  kt.dropped = 0;
  ktunlock();
  pop_off();
}

// parse a number in the given base; a 0x prefix forces hex.
// returns the first unparsed character, or 0 if there was no number.
static char *
ktnumber(char *s, int base, uint64 *v)
{
  int digits = 0;

  while (*s == ' ')
    s++;
  if (s[0] == '0' && s[1] == 'x') {
    base = 16;
    s += 2;
  }
  *v = 0;
  for (; *s && *s != ' '; s++, digits++) {
    int c = *s;
    if (c >= '0' && c <= '9')
      c -= '0';
    else if (base == 16 && c >= 'a' && c <= 'f')
      c -= 'a' - 10;
    else if (base == 16 && c >= 'A' && c <= 'F')
      c -= 'A' - 10;
    else
      return 0;
    *v = *v * base + c;
  }
  return digits ? s : 0;
}

static void
ktcommand(char *s)
{
  uint64 addr, len;
  char *p;

  if (strncmp(s, "watch ", 6) == 0) {
    // the address is hex, with or without 0x. the length is decimal.
    if ((p = ktnumber(s + 6, 16, &addr)) != 0 &&
        (p = ktnumber(p, 10, &len)) != 0 && *p == 0) {
      ktwatch(addr, len);
      return;
    }
  } else if (strncmp(s, "stop", 5) == 0) {
    ktstop();
    return;
  } else if (strncmp(s, "clear", 6) == 0) {
    ktclear();
    return;
  }
  printk("ktrace: commands are: watch ADDR LEN, stop, clear\n");
}

// commands arrive a few bytes per write(), echo sends one word at a
// time, so collect a line before acting on it.
int
ktracewrite(int user_src, uint64 src, int n)
{
  acquiresleep(&cmdlock);
  for (int i = 0; i < n; i++) {
    char c;
    if (either_copyin(&c, user_src, src + i, 1) == -1) {
      releasesleep(&cmdlock);
      return -1;
    }
    if (c == '\n') {
      cmdbuf[cmdlen] = 0;
      cmdlen = 0;
      ktcommand(cmdbuf);
    } else if (cmdlen < sizeof(cmdbuf) - 1) {
      cmdbuf[cmdlen++] = c;
    }
  }
  releasesleep(&cmdlock);
  return n;
}

static char *
ktfmt(char *p, uint64 v, int base)
{
  char buf[20];
  int i = 0;

  do {
    buf[i++] = "0123456789abcdef"[v % base];
    v /= base;
  } while (v != 0);
  while (i > 0)
    *p++ = buf[--i];
  *p++ = ' ';
  return p;
}

// one line per event:  kt cpu R|W addr size value pc pid time
// all hex except cpu, size and pid. reading consumes events.
int
ktraceread(int user_dst, uint64 dst, int n)
{
  char line[128];
  int total = 0;

  acquiresleep(&cmdlock);
  while (n - total >= sizeof(line)) {
    struct ktevent e;
    int have;

    push_off();
    ktlock();
    have = kt.head != kt.tail;
    if (have)
      e = ktlog[kt.tail++ % KTRACE_NEVENT];
    ktunlock();
    pop_off();
    if (!have)
      break;

    char *p = line;
    *p++ = 'k';
    *p++ = 't';
    *p++ = ' ';
    p = ktfmt(p, e.cpu, 10);
    *p++ = e.kind;
    *p++ = ' ';
    p = ktfmt(p, e.addr, 16);
    p = ktfmt(p, e.size, 10);
    p = ktfmt(p, e.val, 16);
    p = ktfmt(p, e.pc, 16);
    p = ktfmt(p, e.pid, 10);
    p = ktfmt(p, e.time, 16);
    p[-1] = '\n';

    if (either_copyout(user_dst, dst + total, line, p - line) == -1) {
      releasesleep(&cmdlock);
      return -1;
    }
    total += p - line;
  }
  releasesleep(&cmdlock);
  return total;
}

void
ktraceinit(void)
{
  extern pagetable_t kernel_pagetable;

  kt.kpgtbl = kernel_pagetable;
  initsleeplock(&cmdlock, "ktrace");
  devsw[KTRACE].read = ktraceread;
  devsw[KTRACE].write = ktracewrite;
}
