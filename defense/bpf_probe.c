/*
 * Detect outbound TCP connect attempts from the monitored web-app cgroup.
 * Hooks sock:inet_sock_set_state and reports TCP_SYN_SENT transitions.
 * User space populates cgroup_filter with the Docker container cgroup id.
 * Only AF_INET and AF_INET6 sockets passing the cgroup filter are emitted.
 * events is a 256 KB BPF ring buffer consumed by Python bcc.
 * event_t carries timestamp, cgroup id, pid, address family, ports,
 * IPv4/IPv6 source and destination addresses, and process comm.
 */

/*
 * 不 #include <net/sock.h> / <linux/in.h> / <linux/in6.h>：
 *   - <net/sock.h> 會輾轉拉進 <linux/bpf.h>，在 kernel 6.10+ 上會引用
 *     bpfcc-tools (Bookworm 版本) 不認得的 struct（bpf_wq、bpf_rb_root、
 *     bpf_refcount 等），編譯會 incomplete-type error。
 *   - 我們用 TRACEPOINT_PROBE，args 結構由 bcc 從 tracefs 自動合成，
 *     不需要 kernel 結構定義。
 *   - 常數（AF_INET、IPPROTO_TCP）以下自行 #define。
 *   - u8/u16/u32/u64 由 bcc 自動注入。
 */

#define TCP_SYN_SENT_STATE 2
#define AF_INET_VALUE 2
#define AF_INET6_VALUE 10
#define IPPROTO_TCP_VALUE 6

struct event_t {
    u64 ts_ns;
    u64 cgroup_id;
    u32 pid;
    u32 family;
    u16 sport;
    u16 dport;
    u32 saddr_v4;
    u32 daddr_v4;
    u8 saddr_v6[16];
    u8 daddr_v6[16];
    char comm[16];
};

BPF_HASH(cgroup_filter, u64, u8, 16);
BPF_RINGBUF_OUTPUT(events, 64);

TRACEPOINT_PROBE(sock, inet_sock_set_state)
{
    if (args->newstate != TCP_SYN_SENT_STATE) {
        return 0;
    }

    if (args->protocol != IPPROTO_TCP_VALUE) {
        return 0;
    }

    if (args->family != AF_INET_VALUE && args->family != AF_INET6_VALUE) {
        return 0;
    }

    u64 cgroup_id = bpf_get_current_cgroup_id();
    u8 *marker = cgroup_filter.lookup(&cgroup_id);
    if (marker == 0) {
        return 0;
    }

    struct event_t event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();

    event.ts_ns = bpf_ktime_get_ns();
    event.cgroup_id = cgroup_id;
    event.pid = pid_tgid >> 32;
    event.family = args->family;
    /* inet_sock_set_state exposes sport/dport in host byte order. */
    event.sport = args->sport;
    event.dport = args->dport;

    if (args->family == AF_INET_VALUE) {
        __builtin_memcpy(&event.saddr_v4, args->saddr,
                         sizeof(event.saddr_v4));
        __builtin_memcpy(&event.daddr_v4, args->daddr,
                         sizeof(event.daddr_v4));
    } else {
        __builtin_memcpy(event.saddr_v6, args->saddr_v6,
                         sizeof(event.saddr_v6));
        __builtin_memcpy(event.daddr_v6, args->daddr_v6,
                         sizeof(event.daddr_v6));
    }

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    events.ringbuf_output(&event, sizeof(event), 0);

    return 0;
}
