from bcc import BPF

# eBPF program
prog = """
#include <uapi/linux/ptrace.h>
#include <linux/mm.h>

BPF_HASH(allocs, u64, u64);
BPF_HASH(frees, u64, u64);

TRACEPOINT_PROBE(kmem, mm_page_alloc) {
    u64 size = (1 << args->order) * PAGE_SIZE;
    u64 *count, zero = 0;
    count = allocs.lookup_or_try_init(&size, &zero);
    if (count) {
        (*count)++;
    }
    return 0;
}

TRACEPOINT_PROBE(kmem, mm_page_free) {
    u64 size = (1 << args->order) * PAGE_SIZE;
    u64 *count, zero = 0;
    count = frees.lookup_or_try_init(&size, &zero);
    if (count) {
        (*count)++;
    }
    return 0;
}
"""

# Load and attach the BPF program to kmem tracepoints
b = BPF(text=prog)
print("Monitoring memory allocations and deallocations... Press Ctrl+C to stop.")

try:
    while True:
        pass
except KeyboardInterrupt:
    net_allocs_bytes = 0
    net_frees_bytes = 0

    # Calculate total allocated and deallocated bytes
    alloc_counts = b["allocs"]
    for size, count in alloc_counts.items():
        net_allocs_bytes += size.value * count.value

    free_counts = b["frees"]
    for size, count in free_counts.items():
        net_frees_bytes += size.value * count.value
    
    initial_free_memory = 11 * 1024 * 1024 * 1024  # e.g., 2GB free initially
    initial_available_memory = 12 * 1024 * 1024 * 1024  # e.g., 3GB available initially
    
    # Correct the net calculation
    net_memory_change = net_frees_bytes - net_allocs_bytes

    # Apply the net change to the initial estimates
    estimated_free_memory = initial_free_memory + net_memory_change
    estimated_available_memory = initial_available_memory + net_memory_change

    print(f"\nEstimated Free Memory: {estimated_free_memory / (1024 * 1024 * 1024)} GB")
    print(f"Estimated Available Memory: {estimated_available_memory / (1024 * 1024 * 1024)} GB")
