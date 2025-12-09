//go:build ignore

#include <stddef.h>

#include "common.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

#define TASK_COMM_LEN 16
#define MAX_ENTRIES 10240
#define MAX_BUF_SIZE (16 * 1024) // 16 KiB
#define RING_BUFFER_SIZE (32 * 1024 * 1024) // 32 MiB

char __license[] SEC("license") = "Dual MIT/GPL";

// ref: /sys/kernel/debug/tracing/events/syscalls/sys_enter_recvfrom/format
struct enter_ctx {
    // padding
    long __common;
    long __syscall_nr;
    u64 fd;
    const void *buf;
    u64 size;
    u64 flags;
    const void *addr; // sockaddr, ignored
    u64 *addr_len;
};

// ref: /sys/kernel/debug/tracing/events/syscalls/sys_exit_recvfrom/format
struct exit_ctx {
    // padding
    long __common;
    long __syscall_nr;
    long ret;
};

struct inflight_read {
    u64 buf;
    u64 size;
    u64 fd;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, struct inflight_read);
} inflight SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RING_BUFFER_SIZE);
} events SEC(".maps");

struct event {
    u64 timestamp_ns;
    u64 pid_tgid;
    u64 uid_gid;
    u64 req_len;
    u64 cgroup_id;
    u64 data_len;
    u64 fd;
    u8 msg_type; // Q, P, B, E, C, X
    u8 data[MAX_BUF_SIZE];
    char comm[TASK_COMM_LEN];
};

// used to make the bpf2go generate event struct
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct event);
} _fake_event_map SEC(".maps");

static __always_inline u8 is_postgres_like_comm(const char *comm) {
    // treat "postgres" as a little-endian 64-bit constant
    const u64 POSTGRES_U64 = (u64)0x7365726774736f70;
    u64 first8;
    __builtin_memcpy(&first8, comm, sizeof(first8));
    if (first8 != POSTGRES_U64)
        return 0;
    char next = comm[8];
    return next == '\0' || next == ':' || next == ' ';
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int tracepoint_enter_recvfrom(struct enter_ctx *ctx) {
    if (ctx->size == 0)
        return 0;

    char comm[16];
    bpf_get_current_comm(&comm, TASK_COMM_LEN);
    if (!is_postgres_like_comm(comm))
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct inflight_read read = {
        .buf  = (u64)ctx->buf,
        .fd   = ctx->fd,
        .size = ctx->size,
    };
    bpf_map_update_elem(&inflight, &pid_tgid, &read, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int tracepoint_exit_recvfrom(struct exit_ctx *ctx) {
    if (ctx->ret <= 0)
        return 0;

    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, TASK_COMM_LEN);
    if (!is_postgres_like_comm(comm))
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct inflight_read *read = bpf_map_lookup_elem(&inflight, &pid_tgid);
    if (read == NULL)
        goto cleanup;

    struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        goto cleanup;

    u32 length = (u32)ctx->ret;
    if (length > MAX_BUF_SIZE)
        length = MAX_BUF_SIZE;

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid_tgid     = pid_tgid;
    evt->uid_gid      = bpf_get_current_uid_gid();
    evt->cgroup_id    = bpf_get_current_cgroup_id();
    evt->req_len      = read->size;
    evt->data_len     = length;
    evt->fd           = read->fd;
    __builtin_memcpy(&evt->comm, comm, TASK_COMM_LEN);
    bpf_probe_read(evt->data, length, (void *)read->buf);
    bpf_ringbuf_submit(evt, 0);

cleanup:
    bpf_map_delete_elem(&inflight, &pid_tgid);
    return 0;
}