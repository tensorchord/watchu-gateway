//go:build ignore

#include <stddef.h>

#include "common.h"
#include "vm_used.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

#include "ssl_common.h"

struct call_info {
    u64 buf_addr;
    u64 ssl_ptr;
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
} read_info SEC(".maps");

// force bpf2go to generate the event struct
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct event);
} _fake_event_map SEC(".maps");

SEC("uprobe/poll_read")
int probe_rustls_tokio_poll_read_entry(struct pt_regs *ctx) {
    struct call_info info = {};
    u64 key               = bpf_get_current_pid_tgid();
    info.buf_addr         = (u64)PT_REGS_PARM3(ctx);
    info.ssl_ptr          = (u64)PT_REGS_PARM1(ctx);
    bpf_map_update_elem(&read_info, &key, &info, BPF_ANY);
    return 0;
};

SEC("uretprobe/poll_read")
int probe_rustls_tokio_poll_read_exit(struct pt_regs *ctx) {
    u64 key                = bpf_get_current_pid_tgid();
    struct call_info *info = bpf_map_lookup_elem(&read_info, &key);
    if (info == NULL)
        return 0;

    u64 now      = bpf_ktime_get_ns();
    u64 uid_gid  = bpf_get_current_uid_gid();
    u64 buf_addr = 0;
    u64 filled   = 0;

    if (bpf_probe_read_user(&buf_addr, sizeof(buf_addr), (void *)info->buf_addr) != 0)
        goto cleanup;
    if (bpf_probe_read_user(&filled, sizeof(filled), (void *)(info->buf_addr + 24)) != 0)
        goto cleanup;

    void *buf     = (void *)buf_addr;
    u64 total_len = filled;

    bpf_repeat(MAX_LOOP) {
        u64 length = filled;
        if (length == 0)
            break;
        if (length > MAX_BODY_SIZE)
            length = MAX_BODY_SIZE;

        struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
        if (!evt) {
            // retry in the next loop, but still limited to MAX_LOOP
            continue;
        }

        evt->pid_tgid     = key;
        evt->uid_gid      = uid_gid;
        evt->ssl_ptr      = info->ssl_ptr;
        evt->timestamp_ns = now;
        evt->req_len      = total_len;
        evt->data_len     = length;
        evt->rw           = 4;
        bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
        bpf_probe_read_user(evt->data, length, buf);

        bpf_ringbuf_submit(evt, 0);
        buf = (u8 *)buf + length;
        filled -= length;
    }

cleanup:
    bpf_map_delete_elem(&read_info, &key);
    return 0;
}

SEC("uprobe/poll_write")
int probe_rustls_tokio_poll_write_entry(struct pt_regs *ctx) {
    u64 ssl_ptr  = PT_REGS_PARM1(ctx);
    u64 buf_addr = PT_REGS_PARM3(ctx);
    u64 len      = PT_REGS_PARM4(ctx);

    if (len == 0)
        return 0;

    u64 total_len = len;
    u64 pid_tgid  = bpf_get_current_pid_tgid();
    u64 uid_gid   = bpf_get_current_uid_gid();
    u64 now       = bpf_ktime_get_ns();
    void *buf     = (void *)buf_addr;

    bpf_repeat(MAX_LOOP) {
        u64 length = len;
        if (length == 0)
            break;
        if (length > MAX_BODY_SIZE)
            length = MAX_BODY_SIZE;

        struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
        if (!evt) {
            // retry in the next loop, but still limited to MAX_LOOP
            continue;
        }

        evt->pid_tgid     = pid_tgid;
        evt->uid_gid      = uid_gid;
        evt->ssl_ptr      = ssl_ptr;
        evt->timestamp_ns = now;
        evt->req_len      = total_len;
        evt->data_len     = length;
        evt->rw           = 2;
        bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
        bpf_probe_read_user(evt->data, length, buf);

        bpf_ringbuf_submit(evt, 0);
        buf = (u8 *)buf + length;
        len -= length;
    }
    return 0;
}
