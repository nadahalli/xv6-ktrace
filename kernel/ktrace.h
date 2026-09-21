// In-kernel memory object tracer. See ktrace.c.

// every page of RAM from etext to PHYSTOP is mapped a second time at
// pa + KTRACE_ALIAS. the fault handler reaches traced objects through
// this alias, whose mapping is never revoked.
#define KTRACE_ALIAS 0x1000000000L

#define KTRACE_NWATCH 8      // simultaneous watches
#define KTRACE_NPAGE  64     // protected pages, over all watches
#define KTRACE_NEVENT 131072 // log capacity, in events
