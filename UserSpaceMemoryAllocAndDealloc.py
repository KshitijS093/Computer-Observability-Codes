#!/usr/bin/python
from bcc import BPF

# eBPF program definition
bpf_text = """
#include <uapi/linux/ptrace.h>

BPF_HASH(allocs, u64, u64);
BPF_HASH(frees, u64, u64);

int trace_alloc(struct pt_regs *ctx) {
    u64 addr = PT_REGS_RC(ctx);
    u64 *count = allocs.lookup(&addr);
    if (count) {
        (*count)++;
    } else {
        u64 one = 1;
        allocs.update(&addr, &one);
    }
    return 0;
}

int trace_free(struct pt_regs *ctx) {
    u64 addr = PT_REGS_PARM1(ctx);
    u64 *count = frees.lookup(&addr);
    if (count) {
        (*count)++;
    } else {
        u64 one = 1;
        frees.update(&addr, &one);
    }
    return 0;
}
"""

# Load the eBPF program
b = BPF(text=bpf_text)

# Attach eBPF program to malloc and free functions
b.attach_uprobe(name="/usr/lib/x86_64-linux-gnu/libc.so.6", sym="malloc", fn_name="trace_alloc")
b.attach_uprobe(name="/usr/lib/x86_64-linux-gnu/libc.so.6", sym="free", fn_name="trace_free")

print("Tracing memory allocations and deallocations...")

# Data structures for tracking allocations and deallocations
allocs = b.get_table("allocs")
frees = b.get_table("frees")

try:
    while True:
        print("Allocations:")
        for addr, count in allocs.items():
            address = int.from_bytes(addr, byteorder='little') # Convert bytes to int
            print("Address: 0x%x, Count: %d" % (address, count.value))
        print("\nDeallocations:")
        for addr, count in frees.items():
            address = int.from_bytes(addr, byteorder='little') # Convert bytes to int
            print("Address: 0x%x, Count: %d" % (address, count.value))
        print("------------------------------------------------------------")
        allocs.clear()
        frees.clear()
        b.perf_buffer_poll()

except KeyboardInterrupt:
    print("Tracing stopped.")

