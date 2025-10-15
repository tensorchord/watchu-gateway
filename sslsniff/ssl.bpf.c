//go:build ignore

#include <stddef.h>

#include "common.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

#define MAX_BODY_SIZE (64 * 1024) // 64 KiB
#define RING_BUFFER_SIZE (32 * 1024 * 1024) // 32 MiB
#define MAX_LOOP 64  // make it 64 * 64 = 4096KiB = 4MiB
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
    u64 ssl_ptr;
};

struct call_info_ex {
    u64 buf_addr;
    u64 len;
    u64 ssl_ptr;
    u64 consumed_len_ptr;
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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);
    __type(value, struct call_info_ex);
} start_ex_map SEC(".maps");

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
    info.ssl_ptr          = (u64)PT_REGS_PARM1(ctx);
    info.buf_addr         = (u64)PT_REGS_PARM2(ctx);
    info.len              = (int)PT_REGS_PARM3(ctx);
    bpf_map_update_elem(&start_map, &key, &info, BPF_ANY);
    return 0;
};

SEC("uprobe/ssl_read_ex_entry")
int probe_ssl_read_ex_entry(struct pt_regs *ctx) {
    struct call_info_ex info = {};
    u64 key                  = bpf_get_current_pid_tgid();
    info.ssl_ptr             = (u64)PT_REGS_PARM1(ctx);
    info.buf_addr            = (u64)PT_REGS_PARM2(ctx);
    info.len                 = (int)PT_REGS_PARM3(ctx);
    info.consumed_len_ptr    = (u64)PT_REGS_PARM4(ctx);
    bpf_map_update_elem(&start_ex_map, &key, &info, BPF_ANY);
    return 0;
};

SEC("uretprobe/ssl_read_exit")
int probe_ssl_read_exit(struct pt_regs *ctx) {
    u64 key                = bpf_get_current_pid_tgid();
    struct call_info *info = bpf_map_lookup_elem(&start_map, &key);
    if (info == NULL)
        return 0;

    int ret = PT_REGS_RC(ctx);
    if (ret <= 0)
        goto cleanup;

    u64 now = bpf_ktime_get_ns();
    u64 uid_gid = bpf_get_current_uid_gid();
    void *buf = (void *)info->buf_addr;

    // bpf_repeat(MAX_LOOP) {
    #pragma unroll
    for (int i = 0; i < MAX_LOOP && ret > 0; ++i) {
        u32 length = (u32)ret; // Cast is safe: ret > 0 guaranteed by guard above
        if (length > MAX_BODY_SIZE)
            length = MAX_BODY_SIZE;

        struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
        if (!evt) {
            // retry in the next loop, but still limited to MAX_LOOP
            continue;
        }
    
        evt->pid_tgid     = key;
        evt->ssl_ptr      = info->ssl_ptr;
        evt->uid_gid      = uid_gid;
        evt->timestamp_ns = now;
        evt->req_len      = info->len;
        evt->data_len     = length;
        evt->rw           = 4;
        bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
        bpf_probe_read_user(evt->data, length, buf);
    
        bpf_ringbuf_submit(evt, 0);
        buf += length;
        ret -= length;
    }

cleanup:
    bpf_map_delete_elem(&start_map, &key);
    return 0;
}

SEC("uretprobe/SSL_read_ex_exit")
int probe_ssl_read_ex_exit(struct pt_regs *ctx) {
    u64 key                   = bpf_get_current_pid_tgid();
    struct call_info_ex *info = bpf_map_lookup_elem(&start_ex_map, &key);
    if (info == NULL)
        goto cleanup;

    int ret = PT_REGS_RC(ctx);
    if (ret != 1)
        goto cleanup;
    
    size_t readbytes = 0;
    u64 now = bpf_ktime_get_ns();
    u64 uid_gid = bpf_get_current_uid_gid();
    bpf_probe_read_user(&readbytes, sizeof(readbytes), (void *)info->consumed_len_ptr);

    void *buf = (void *)info->buf_addr;

    // bpf_repeat(MAX_LOOP) {
    #pragma unroll
    for (int i = 0; i < MAX_LOOP && readbytes > 0; ++i) {
        u32 length = (u32)readbytes;
        if (length > MAX_BODY_SIZE)
            length = MAX_BODY_SIZE;
    
        struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
        if (!evt) {
            // retry in the next loop, but still limited to MAX_LOOP
            continue;
        }
    
        evt->pid_tgid     = key;
        evt->ssl_ptr      = info->ssl_ptr;
        evt->uid_gid      = uid_gid;
        evt->timestamp_ns = now;
        evt->req_len      = info->len;
        evt->data_len     = length;
        evt->rw           = 4;
        bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
        bpf_probe_read_user(evt->data, length, buf);
    
        bpf_ringbuf_submit(evt, 0);
        buf += length;
        readbytes -= length;
    }

cleanup:
    bpf_map_delete_elem(&start_ex_map, &key);
    return 0;
}

SEC("uretprobe/ssl_write_exit")
int probe_ssl_write_exit(struct pt_regs *ctx) {
    u64 key                = bpf_get_current_pid_tgid();
    struct call_info *info = bpf_map_lookup_elem(&start_map, &key);
    if (info == NULL)
        return 0;

    int ret = PT_REGS_RC(ctx);
    if (ret <= 0)
        goto cleanup;
    
    u64 now = bpf_ktime_get_ns();
    u64 uid_gid = bpf_get_current_uid_gid();
    void *buf = (void *)info->buf_addr;

    // bpf_repeat(MAX_LOOP) {
    #pragma unroll
    for (int i = 0; i < MAX_LOOP && ret > 0; ++i) {
        u32 length = (u32)ret;
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
        evt->req_len      = info->len;
        evt->data_len     = length;
        evt->rw           = 2;
        bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
        bpf_probe_read_user(evt->data, length, buf);
        
        bpf_ringbuf_submit(evt, 0);
        buf += length;
        ret -= length;
    }

cleanup:
    bpf_map_delete_elem(&start_map, &key);
    return 0;
}

SEC("uretprobe/ssl_write_ex_exit")
int probe_ssl_write_ex_exit(struct pt_regs *ctx) {
    u64 key                   = bpf_get_current_pid_tgid();
    struct call_info_ex *info = bpf_map_lookup_elem(&start_ex_map, &key);
    if (info == NULL)
        goto cleanup;

    int ret = PT_REGS_RC(ctx);
    if (ret != 1)
        goto cleanup;
        
    size_t written = 0;
    bpf_probe_read_user(&written, sizeof(written), (void *)info->consumed_len_ptr);
    u64 uid_gid = bpf_get_current_uid_gid();
    u64 now = bpf_ktime_get_ns();
    
    void *buf = (void *)info->buf_addr;

    // bpf_repeat(MAX_LOOP) {
    #pragma unroll
    for (int i = 0; i < MAX_LOOP && written > 0; ++i) {
        u32 length = (u32)written;
        if (length > MAX_BODY_SIZE)
            length = MAX_BODY_SIZE;

        struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
        if (!evt)
            // retry in the next loop, but still limited to MAX_LOOP
            continue;

        evt->pid_tgid     = key;
        evt->uid_gid      = uid_gid;
        evt->ssl_ptr      = info->ssl_ptr;
        evt->timestamp_ns = now;
        evt->req_len      = info->len;
        evt->data_len     = length;
        evt->rw           = 2;
        bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
        bpf_probe_read_user(evt->data, length, buf);
        
        bpf_ringbuf_submit(evt, 0);
        buf += length;
        written -= length;
    }

cleanup:
    bpf_map_delete_elem(&start_ex_map, &key);
    return 0;
}
