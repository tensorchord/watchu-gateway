//go:build ignore

#include <stddef.h>

#include "common.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

#define LIBSSL_LEN 6
#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define MAX_ENTRIES 10240
#define RING_BUFFER_SIZE (4 * 1024 * 1024) // 4 MiB

char __license[] SEC("license") = "Dual MIT/GPL";

// ref: /sys/kernel/debug/tracing/events/sched/sched_process_exec/format
struct sched_process_ctx {
    // pad the first 8 bytes
    long common;
    u32 filename; // __data_loc char * (lower 16 bits: offset, upper 16 bits: size)
    s32 pid;
    s32 old_pid;
};

// ref: /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
// ref: /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat2/format
struct openat_ctx {
    // pad the first 8 bytes
    long common;
    long __syscall_nr;
    u64 _dfd;
    u64 filename;
    u64 _flags; // or `how` in openat2
    u64 _mode; // or `usize` in openat2
};

// ref: /sys/kernel/debug/tracing/events/syscalls/sys_enter_mmap/format
struct mmap_ctx {
    // pad the first 8 bytes
    long common;
    long __syscall_nr;
    u64 addr;
    u64 length;
    u64 prot;
    u64 flags;
    u64 fd;
    u64 offset;
};

struct inflight_load {
    char filename[MAX_FILENAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, struct inflight_load);
} inflight SEC(".maps");

struct proc {
    s32 pid;
    s32 old_pid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

// used to make the bpf2go generate proc struct
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct proc);
} _fake_proc_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RING_BUFFER_SIZE);
} proc_events SEC(".maps");

struct dynlib {
    u64 fd;
    u64 pid_tgid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

// used to make the bpf2go generate dynlib struct
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct dynlib);
} _fake_dynlib_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RING_BUFFER_SIZE);
} dynlib_events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int tracepoint_sched_process_exec(struct sched_process_ctx *ctx) {
    if (ctx->pid == 0)
        return 0;

    struct proc *evt = bpf_ringbuf_reserve(&proc_events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->pid     = ctx->pid;
    evt->old_pid = ctx->old_pid;
    bpf_get_current_comm(&evt->comm, TASK_COMM_LEN);

    u32 length = ctx->filename >> 16;
    if (length > MAX_FILENAME_LEN)
        length = MAX_FILENAME_LEN;
    char *filename_ptr = (char *)((void *)ctx + (ctx->filename & 0xFFFF));
    bpf_probe_read_str(&evt->filename, length, filename_ptr);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

static __always_inline int is_libssl(const char *filename) {
#pragma unroll
    for (int i = 0; i < (MAX_FILENAME_LEN - LIBSSL_LEN); i++) {
        if (filename[i] == '\0')
            break;
        if (filename[i] == 'l' && filename[i + 1] == 'i' && filename[i + 2] == 'b' && filename[i + 3] == 's' &&
            filename[i + 4] == 's' && filename[i + 5] == 'l') {
            return 1;
        }
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_sys_enter_openat(struct openat_ctx *ctx) {
    struct inflight_load load = {};
    int length                = bpf_probe_read_user_str(load.filename, MAX_FILENAME_LEN, (void *)ctx->filename);
    if (length <= 0)
        return 0;
    if (is_libssl(load.filename) == 0)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&inflight, &pid_tgid, &load, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int tracepoint_sys_enter_mmap(struct mmap_ctx *ctx) {
    u64 pid_tgid               = bpf_get_current_pid_tgid();
    struct inflight_load *load = bpf_map_lookup_elem(&inflight, &pid_tgid);
    if (load == NULL) {
        return 0;
    }

    struct dynlib *evt = bpf_ringbuf_reserve(&dynlib_events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }

    evt->fd       = ctx->fd;
    evt->pid_tgid = pid_tgid;
    bpf_get_current_comm(&evt->comm, TASK_COMM_LEN);
    __builtin_memcpy(evt->filename, load->filename, sizeof(evt->filename));
    bpf_ringbuf_submit(evt, 0);
    return 0;
}
