//go:build ignore

#include <stddef.h>

#include "common.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

#define MAX_ENTRIES 10240
#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define RING_BUFFER_SIZE (8 * 1024 * 1024) // 8 MiB
#define MAX_BUF_SIZE (128 * 1024) // 128 KiB

char __license[] SEC("license") = "Dual MIT/GPL";

// ref: /sys/kernel/debug/tracing/events/sched/sched_process_exec/format
struct sched_process_ctx {
    // pad the first 8 bytes
    long common;
    u32 filename; // __data_loc char * (lower 16 bits: offset, upper 16 bits: size)
    s32 pid;
    s32 old_pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RING_BUFFER_SIZE);
} events SEC(".maps");

struct event {
    u64 timestamp_ns;
    u64 cgroup_id;
    s32 pid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

SEC("tracepoint/sched/sched_process_exec")
int tracepoint_sched_process_exec(struct sched_process_ctx *ctx) {
    struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid          = evt->pid;
    evt->cgroup_id    = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&evt->comm, TASK_COMM_LEN);

    u32 length = ctx->filename >> 16;
    if (length > MAX_FILENAME_LEN)
        length = MAX_FILENAME_LEN;
    char *filename_ptr = (char *)((void *)ctx + (ctx->filename & 0xFFFF));
    bpf_probe_read_str(&evt->filename, length, filename_ptr);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}
