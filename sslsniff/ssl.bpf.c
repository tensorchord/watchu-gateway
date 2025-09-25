//go:build ignore

#include <stddef.h>

#include "common.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

#define MAX_BODY_SIZE (16 * 1024) // 16 KiB
#define RING_BUFFER_SIZE (2 * 1024 * 1024) // 2 MiB
#define MAX_ENTRIES 10240
#define TASK_COMM_LEN 16

char __license[] SEC("license") = "Dual BSD/GPL";

struct event {
    u64 timestamp_ns;
    u64 req_len;
    u64 pid_tgid;
    u64 uid_gid;
    u64 ssl_ptr;
    u32 data_len;
    u8 rw; // rwx: 2 write, 4 read
    char comm[TASK_COMM_LEN];
    u8 data[MAX_BODY_SIZE];
};

struct call_info {
    u64 buf_addr;
    u64 len;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RING_BUFFER_SIZE);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, struct call_info);
} start_map SEC(".maps");

// used to make the bpf2go generate event struct
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct event);
} _fake_event_map SEC(".maps");

SEC("uprobe/ssl_read_entry")
int probe_ssl_read_entry(struct pt_regs *ctx) {
    struct call_info info = {};
    u64 key               = bpf_get_current_pid_tgid();
    info.buf_addr         = (u64)PT_REGS_PARM2(ctx);
    info.len              = (int)PT_REGS_PARM3(ctx);
    bpf_map_update_elem(&start_map, &key, &info, BPF_ANY);
    return 0;
};

SEC("uretprobe/ssl_read_exit")
int probe_ssl_read_exit(struct pt_regs *ctx) {
    u64 key                = bpf_get_current_pid_tgid();
    struct call_info *info = bpf_map_lookup_elem(&start_map, &key);
    if (info == NULL)
        return 0;

    u64 now   = bpf_ktime_get_ns();
    void *ssl = (void *)PT_REGS_PARM1(ctx);
    int ret   = PT_REGS_RC(ctx);

    if (ret <= 0)
        goto cleanup;

    u32 length = (u32)ret; // Cast is safe: ret > 0 guaranteed by guard above
    if (length > MAX_BODY_SIZE)
        length = MAX_BODY_SIZE;

    struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        goto cleanup;

    evt->pid_tgid     = key;
    evt->ssl_ptr      = (u64)ssl;
    evt->uid_gid      = bpf_get_current_uid_gid();
    evt->timestamp_ns = now;
    evt->req_len      = info->len;
    evt->data_len     = length;
    evt->rw           = 4;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    if (length > 0) {
        void *buf = (void *)info->buf_addr;
        bpf_probe_read_user(evt->data, length, buf);
    }

    bpf_ringbuf_submit(evt, 0);

cleanup:
    bpf_map_delete_elem(&start_map, &key);
    return 0;
}

SEC("uretprobe/SSL_read_ex_exit")
int probe_ssl_read_ex_exit(struct pt_regs *ctx) {
    u64 key                = bpf_get_current_pid_tgid();
    struct call_info *info = bpf_map_lookup_elem(&start_map, &key);
    if (info == NULL)
        return 0;

    u64 now          = bpf_ktime_get_ns();
    void *ssl        = (void *)PT_REGS_PARM1(ctx);
    size_t readbytes = (size_t)PT_REGS_PARM4(ctx);
    int ret          = PT_REGS_RC(ctx);

    if (ret != 1)
        goto cleanup;

    u32 length = (u32)readbytes;
    if (length > MAX_BODY_SIZE)
        length = MAX_BODY_SIZE;

    if (length == 0)
        goto cleanup;

    struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        goto cleanup;

    evt->pid_tgid     = key;
    evt->ssl_ptr      = (u64)ssl;
    evt->uid_gid      = bpf_get_current_uid_gid();
    evt->timestamp_ns = now;
    evt->req_len      = info->len;
    evt->data_len     = length;
    evt->rw           = 4;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    if (length > 0) {
        void *buf = (void *)info->buf_addr;
        bpf_probe_read_user(evt->data, length, buf);
    }

    bpf_ringbuf_submit(evt, 0);

cleanup:
    bpf_map_delete_elem(&start_map, &key);
    return 0;
}

SEC("uprobe/ssl_write_entry")
int probe_ssl_write_entry(struct pt_regs *ctx) {
    int len = (int)PT_REGS_PARM3(ctx);
    if (len <= 0) {
        return 0;
    }

    struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    void *buf = (void *)PT_REGS_PARM2(ctx);
    void *ssl = (void *)PT_REGS_PARM1(ctx);

    u32 length = (u32)len;
    if (length > MAX_BODY_SIZE)
        length = MAX_BODY_SIZE;

    evt->pid_tgid     = bpf_get_current_pid_tgid();
    evt->uid_gid      = bpf_get_current_uid_gid();
    evt->ssl_ptr      = (u64)ssl;
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->req_len      = (u64)len;
    evt->data_len     = length;
    evt->rw           = 2;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    bpf_probe_read_user(evt->data, length, buf);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("uprobe/ssl_write_ex_entry")
int probe_ssl_write_ex_entry(struct pt_regs *ctx) {
    size_t len = (size_t)PT_REGS_PARM3(ctx);
    if (len == 0) {
        return 0;
    }

    struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    void *buf      = (void *)PT_REGS_PARM2(ctx);
    void *ssl      = (void *)PT_REGS_PARM1(ctx);
    size_t written = (size_t)PT_REGS_PARM4(ctx);

    u32 length = (u32)written;
    if (length > MAX_BODY_SIZE)
        length = MAX_BODY_SIZE;

    evt->pid_tgid     = bpf_get_current_pid_tgid();
    evt->uid_gid      = bpf_get_current_uid_gid();
    evt->ssl_ptr      = (u64)ssl;
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->req_len      = (u64)len;
    evt->data_len     = length;
    evt->rw           = 2;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    bpf_probe_read_user(evt->data, length, buf);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}
