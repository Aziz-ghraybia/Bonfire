#include <uapi/linux/ptrace.h>
#include <linux/in.h>
#include <linux/socket.h>

struct connect_event_t {
    u32 pid;
    u32 uid;
    char comm[16];
    u32 daddr;
    u16 dport;
};

BPF_PERF_OUTPUT(connect_events);

TRACEPOINT_PROBE(syscalls, sys_enter_connect)
{
    struct connect_event_t event = {};

    // read the sockaddr struct the process passed in
    struct sockaddr_in sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), args->uservaddr);

    // only IPv4
    if (sa.sin_family != AF_INET)
        return 0;

    event.pid   = bpf_get_current_pid_tgid() >> 32;
    event.uid   = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.daddr = sa.sin_addr.s_addr;
    event.dport = sa.sin_port;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    connect_events.perf_submit(args, &event, sizeof(event));
    return 0;
}
