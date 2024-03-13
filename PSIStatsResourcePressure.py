from bcc import BPF
import ctypes
from time import sleep

# Add this function to the script
def calculate_cpu_pressure(wakeup, wakeup_new, context_switches, forks, cpu_idle, cpu_frequency_changes):
    # Define weights
    wakeup_weight = 1.0
    context_switch_weight = 0.5
    fork_weight = 0.3
    idle_weight = -0.5  # Negative because more idles mean less pressure
    frequency_change_weight = 0.2  # New weight for frequency changes
    
    # Calculate the raw pressure
    raw_pressure = (wakeup_weight * (wakeup + wakeup_new) +
                    context_switch_weight * context_switches +
                    fork_weight * forks +
                    idle_weight * cpu_idle +
                    frequency_change_weight * cpu_frequency_changes)  # Include frequency changes

    # Example maximum expected pressure for demonstration
    #max_expected_pressure = 100000.0  # Adjust if necessary
    
    # Normalize to a percentage
    #pressure_percentage = (raw_pressure / max_expected_pressure) * 100
    #pressure_percentage = min(max(pressure_percentage, 0), 100)  # Clamp to 0-100%
    
    return raw_pressure

# Define eBPF program
bpf_program = """
BPF_HASH(sched_switch_count, u32, u64);
BPF_HASH(sched_wakeup_count, u32, u64);
BPF_HASH(sched_wakeup_new_count, u32, u64);
BPF_HASH(sched_fork_count, u32, u64);
BPF_HASH(last_freq_per_cpu, u32, u64);
BPF_HASH(freq_increases_count, u32, u64);
BPF_HASH(cpu_idle_count, u32, u64);

TRACEPOINT_PROBE(sched, sched_switch) {
    u32 key = 0;
    u64 zero = 0, *val;
    val = sched_switch_count.lookup_or_init(&key, &zero);
    (*val)++;
    return 0;
}

TRACEPOINT_PROBE(sched, sched_wakeup) {
    u32 key = 1;
    u64 zero = 0, *val;
    val = sched_wakeup_count.lookup_or_init(&key, &zero);
    (*val)++;
    return 0;
}

TRACEPOINT_PROBE(sched, sched_wakeup_new) {
    u32 key = 2;
    u64 zero = 0, *val;
    val = sched_wakeup_new_count.lookup_or_init(&key, &zero);
    (*val)++;
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_fork) {
    u32 key = 3;
    u64 zero = 0, *val;
    val = sched_fork_count.lookup_or_init(&key, &zero);
    (*val)++;
    return 0;
}

TRACEPOINT_PROBE(power, cpu_frequency) {
    u32 cpu_id = bpf_get_smp_processor_id(); // Get CPU ID
    u64 new_freq = args->state; // Assuming 'state' holds the new frequency
    u64 *last_freq = last_freq_per_cpu.lookup(&cpu_id);
    u64 zero = 0, *val;
    
    if (last_freq != NULL && new_freq > *last_freq) {
        // Frequency increased, increment the count for this CPU
        val = freq_increases_count.lookup_or_init(&cpu_id, &zero);
        (*val)++;
    }
    
    // Update the last known frequency for this CPU
    last_freq_per_cpu.update(&cpu_id, &new_freq);
    
    return 0;
}

TRACEPOINT_PROBE(power, cpu_idle) {
    u32 key = 5;
    u64 zero = 0, *val;
    val = cpu_idle_count.lookup_or_init(&key, &zero);
    (*val)++;
    return 0;
}
"""

# Load eBPF program
b = BPF(text=bpf_program)

key = ctypes.c_uint32(0)

def read_and_reset_counter(bpf_map, key):
    val = bpf_map.get(key)
    count = val.value if val is not None else 0
    # Properly reset the counter by setting the value to zero using the correct syntax
    if val is not None:
        bpf_map[key] = ctypes.c_ulonglong(0)
    return count


try:
    while True:
        # Use the function to read and reset counters
        wakeup = read_and_reset_counter(b["sched_wakeup_count"], key)
        wakeup_new = read_and_reset_counter(b["sched_wakeup_new_count"], key)
        context_switches = read_and_reset_counter(b["sched_switch_count"], key)
        forks = read_and_reset_counter(b["sched_fork_count"], key)
        cpu_idle = read_and_reset_counter(b["cpu_idle_count"], key)
        # Assuming freq_increases_count is the correct counter for frequency increases
        cpu_frequency_changes = read_and_reset_counter(b["freq_increases_count"], key)

        cpu_pressure = calculate_cpu_pressure(wakeup, wakeup_new, context_switches, forks, cpu_idle, cpu_frequency_changes)

        #print(f"Calculated CPU Pressure in percentage considering max pressure as 100000: {cpu_pressure}")
        print(f"Calculated CPU Pressure: {cpu_pressure}")
        sleep(10)

except KeyboardInterrupt:
    pass
