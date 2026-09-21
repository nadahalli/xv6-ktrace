#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"

struct spinlock tickslock;
uint ticks;

extern char trampoline[], uservec[];

// in kernelvec.S, calls kerneltrap().
void kernelvec();

static void set_user_return(struct trapframe *tf, uint64 kstack);

extern int devintr(uint64 scause);

void
trapinit(void)
{
  initlock(&tickslock, "time");
}

// set up to take exceptions and traps while in the kernel.
void
trapinithart(void)
{
  w_stvec((uint64)kernelvec);
}

//
// handle an interrupt, exception, or system call from user space.
// called from, and returns to, trampoline.S
// return value is user satp for trampoline.S to switch to.
//
uint64
usertrap(void)
{
  int which_dev = 0;

  // read these before touching kernel data. an access to a traced
  // object traps to kerneltrap(), which overwrites all three.
  uint64 sepc = r_sepc();
  uint64 scause = r_scause();
  uint64 stval = r_stval();

  if ((r_sstatus() & SSTATUS_SPP) != 0)
    panic("usertrap: not from user mode");

  // send interrupts and exceptions to kerneltrap(),
  // since we're now in the kernel.
  w_stvec((uint64)kernelvec); //DOC: kernelvec

  ktrace_quiesce();

  struct proc *p = myproc();

  // save user program counter.
  p->trapframe->epc = sepc;

  if (scause == 8) {
    // system call

    if (killed(p))
      kexit(-1);

    // sepc points to the ecall instruction,
    // but we want to return to the next instruction.
    p->trapframe->epc += 4;

    // an interrupt will change sepc, scause, and sstatus,
    // so enable only now that we're done with those registers.
    intr_on();

    syscall();
  } else if ((which_dev = devintr(scause)) != 0) {
    // ok
  } else if ((scause == 15 || scause == 13) &&
             vmfault(p->pagetable, p->sz, stval, (scause == 13) ? 1 : 0) !=
                 0) {
    // page fault on lazily-allocated page
  } else {
    printk("usertrap(): unexpected scause 0x%lx pid=%d\n", scause, p->pid);
    printk("            sepc=0x%lx stval=0x%lx\n", sepc, stval);
    setkilled(p);
  }

  if (killed(p))
    kexit(-1);

  // give up the CPU if this is a timer interrupt.
  if (which_dev == 2)
    yield();

  // the user page table to switch to, for trampoline.S.
  // read it before prepare_return(), see there.
  uint64 satp = MAKE_SATP(p->pagetable);

  prepare_return();

  // return to trampoline.S; satp value in a0.
  return satp;
}

//
// set up trapframe and control registers for a return to user space.
//
// once this returns, stvec points at uservec, and stays there until
// the sret in trampoline.S. a page fault on a traced object in that
// window would go to uservec, so the caller must touch nothing but
// its kernel stack and the trapframe from here on.
//
void
prepare_return(void)
{
  struct proc *p = myproc();
  struct trapframe *tf = p->trapframe;
  uint64 kstack = p->kstack;

  set_user_return(tf, kstack);
}

// the part of prepare_return() that runs with stvec at uservec.
// noipa, so that the compiler cannot move the caller's reads of
// struct proc into here.
static void __attribute__((noipa))
set_user_return(struct trapframe *tf, uint64 kstack)
{
  // we're about to switch the destination of traps from
  // kerneltrap() to usertrap(). because a trap from kernel
  // code to usertrap would be a disaster, turn off interrupts.
  intr_off();

  // send syscalls, interrupts, and exceptions to uservec in trampoline.S
  uint64 trampoline_uservec = TRAMPOLINE + (uservec - trampoline);
  w_stvec(trampoline_uservec);

  // set up trapframe values that uservec will need when
  // the process next traps into the kernel.
  tf->kernel_satp = r_satp();      // kernel page table
  tf->kernel_sp = kstack + PGSIZE; // process's kernel stack
  tf->kernel_trap = (uint64)usertrap;
  tf->kernel_hartid = r_tp(); // hartid for cpuid()

  // set up the registers that trampoline.S's sret will use
  // to get to user space.

  // set S Previous Privilege mode to User.
  unsigned long x = r_sstatus();
  x &= ~SSTATUS_SPP; // clear SPP to 0 for user mode
  x |= SSTATUS_SPIE; // enable interrupts in user mode
  w_sstatus(x);

  // set S Exception Program Counter to the saved user pc.
  w_sepc(tf->epc);
}

// interrupts and exceptions from kernel code go here via kernelvec,
// on whatever the current kernel stack is.
// regs is the register frame that kernelvec saved and will restore.
void
kerneltrap(uint64 *regs)
{
  int which_dev = 0;
  uint64 sepc = r_sepc();
  uint64 sstatus = r_sstatus();
  uint64 scause = r_scause();
  uint64 stval = r_stval();

  if ((sstatus & SSTATUS_SPP) == 0)
    panic("kerneltrap: not from supervisor mode");
  if (intr_get() != 0)
    panic("kerneltrap: interrupts enabled");

  ktrace_quiesce();

  if (scause == 13 || scause == 15) {
    // load or store page fault: an access to a traced object?
    uint64 resume = ktrace_fault(regs, scause, sepc, stval);
    if (resume != 0) {
      w_sepc(resume);
      w_sstatus(sstatus);
      return;
    }
  }

  if ((which_dev = devintr(scause)) == 0) {
    // interrupt or trap from an unknown source
    printk("scause=0x%lx sepc=0x%lx stval=0x%lx\n", scause, sepc, stval);
    panic("kerneltrap");
  }

  // give up the CPU if this is a timer interrupt.
  if (which_dev == 2 && myproc() != 0)
    yield();

  // the yield() may have caused some traps to occur,
  // so restore trap registers for use by kernelvec.S's sepc instruction.
  w_sepc(sepc);
  w_sstatus(sstatus);
}

void
clockintr()
{
  if (cpuid() == 0) {
    acquire(&tickslock);
    ticks++;
    wakeup(&ticks);
    release(&tickslock);
  }

  // ask for the next timer interrupt. this also clears
  // the interrupt request. 1000000 is about a tenth
  // of a second.
  w_stimecmp(r_time() + 1000000);
}

// check if it's an external interrupt or software interrupt,
// and handle it.
// returns 2 if timer interrupt,
// 1 if other device,
// 0 if not recognized.
int
devintr(uint64 scause)
{
  if (scause == 0x8000000000000009L) {
    // this is a supervisor external interrupt, via PLIC.

    // irq indicates which device interrupted.
    int irq = plic_claim();

    if (irq == UART0_IRQ) {
      uartintr();
    } else if (irq == VIRTIO0_IRQ) {
      virtio_disk_intr();
    } else if (irq) {
      printk("unexpected interrupt irq=%d\n", irq);
    }

    // the PLIC allows each device to raise at most one
    // interrupt at a time; tell the PLIC the device is
    // now allowed to interrupt again.
    if (irq)
      plic_complete(irq);

    return 1;
  } else if (scause == 0x8000000000000005L) {
    // timer interrupt.
    clockintr();
    return 2;
  } else {
    return 0;
  }
}
