#!/usr/bin/env python

from bcc import BPF

# BPF program
bpf_prog = """
#include <uapi/linux/ptrace.h>
#include <linux/oom.h>

// Memory compaction events (related to kcompactd activity)
TRACEPOINT_PROBE(compaction, mm_compaction_begin) {
    bpf_trace_printk("Memory compaction started\\n");
    return 0;
}

TRACEPOINT_PROBE(compaction, mm_compaction_end) {
    bpf_trace_printk("Memory compaction ended\\n");
    return 0;
}

// vmscan events (indicating kswapd activity)
TRACEPOINT_PROBE(vmscan, mm_vmscan_kswapd_wake) {
    bpf_trace_printk("kswapd wake up\\n");
    return 0;
}

TRACEPOINT_PROBE(vmscan, mm_vmscan_kswapd_sleep) {
    bpf_trace_printk("kswapd going to sleep\\n");
    return 0;
}

// OOM kill events
struct data_t {
    u32 fpid;
    char fcomm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(oom_events);

void kprobe__oom_kill_process(struct pt_regs *ctx, struct oom_control *oc, const char *message) {
    struct task_struct *p = oc->chosen;
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    data.fpid = pid;
    bpf_get_current_comm(&data.fcomm, sizeof(data.fcomm));
    oom_events.perf_submit(ctx, &data, sizeof(data));
}

"""

# Load BPF program
b = BPF(text=bpf_prog)

# Define processing function for OOM events
def print_oom_event(cpu, data, size):
    event = b["oom_events"].event(data)
    print(f"OOM Kill: PID {event.fpid} ({event.fcomm.decode('utf-8', 'replace')})")

# Attach perf buffer for OOM events
b["oom_events"].open_perf_buffer(print_oom_event)

print("Monitoring kswapd, kcompactd activities, and OOM kills... Press CTRL+C to stop.")

# Print output
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

