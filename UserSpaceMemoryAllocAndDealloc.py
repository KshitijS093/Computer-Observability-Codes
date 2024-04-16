#!/usr/bin/python
from bcc import BPF

import mysql.connector
from mysql.connector import Error

db_config = {
    'host': 'localhost',
    'user': 'grafana',
    'password': 'bmscecollege',
    'database': 'grafanadb'
}

def insert_into_mysql(address, alloc_count, free_count):
    conn = None  # Initialize conn to None before the try block
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        insert_query = """
        INSERT INTO User_Space_Memory_Alloc_And_Dealloc (address, alloc_count, free_count)
        VALUES (%s, %s, %s)
        """
        cursor.execute(insert_query, (address, alloc_count, free_count))
        conn.commit()
    except Error as e:
        print(f"Error: {e}")
    finally:
        if conn and conn.is_connected():  # Check if conn is not None and is connected before closing
            cursor.close()
            conn.close()

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
            address = int.from_bytes(addr, byteorder='little')  # Convert bytes to int
            alloc_count = count.value
            print("Address: 0x%x, Count: %d" % (address, alloc_count))
            # Initialize free_count to 0, update later if applicable
            insert_into_mysql(address, alloc_count, 0)
        
        print("\nDeallocations:")
        for addr, count in frees.items():
            address = int.from_bytes(addr, byteorder='little')  # Convert bytes to int
            free_count = count.value
            print("Address: 0x%x, Count: %d" % (address, free_count))
            # Attempt to update existing records with free_count
            insert_into_mysql(address, 0, free_count)
        
        print("------------------------------------------------------------")
        allocs.clear()
        frees.clear()
        # b.perf_buffer_poll() is not needed here unless you're using perf buffers

except KeyboardInterrupt:
    print("Tracing stopped.")

