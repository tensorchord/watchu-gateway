//go:build ignore

#include <stddef.h>

#include "common.h"
#include "bpf_core_read.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

#define AF_INET 2
#define AF_INET6 10
#define TASK_COMM_LEN 16
#define RING_BUFFER_SIZE (4 * 1024 * 1024)
#define BPF_TCP_ESTABLISHED 1
#define BPF_TCP_SYN_SENT 2

char __license[] SEC("license") = "Dual MIT/GPL";

struct in6_addr {
    union {
        u8 u6_addr8[16];
        __be32 u6_addr32[4];
    } in6_u;
} __attribute__((preserve_access_index));

struct sock_common {
    __be32 skc_daddr;
    __be32 skc_rcv_saddr;
    struct in6_addr skc_v6_daddr;
    struct in6_addr skc_v6_rcv_saddr;
    __be16 skc_dport;
    u16 skc_num;
    unsigned short skc_family;
    u8 skc_state;
} __attribute__((preserve_access_index));

struct sock {
    struct sock_common __sk_common;
} __attribute__((preserve_access_index));

struct event {
    u64 timestamp_ns;
    u64 pid_tgid;
    u64 uid_gid;
    u64 cgroup_id;
    u16 family;
    u16 dport;
    char comm[TASK_COMM_LEN];
    u8 daddr[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RING_BUFFER_SIZE);
} events SEC(".maps");

SEC("fentry/tcp_set_state")
int BPF_PROG(trace_tcp_set_state, struct sock *sk, int state) {
    if (!sk) {
        return 0;
    }
    if (state != BPF_TCP_ESTABLISHED) {
        return 0;
    }

    if (BPF_CORE_READ(sk, __sk_common.skc_state) != BPF_TCP_SYN_SENT) {
        return 0;
    }

    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6) {
        return 0;
    }

    struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }
    __builtin_memset(evt, 0, sizeof(*evt));

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid_tgid     = bpf_get_current_pid_tgid();
    evt->uid_gid      = bpf_get_current_uid_gid();
    evt->cgroup_id    = bpf_get_current_cgroup_id();
    evt->family       = family;
    evt->dport        = BPF_CORE_READ(sk, __sk_common.skc_dport);
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    if (family == AF_INET) {
        __be32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(evt->daddr, &daddr, sizeof(daddr));
    } else {
        BPF_CORE_READ_INTO(&evt->daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}
