#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct execve_event_t {
    u32 pid;
    u32 uid;
    char comm[16];
    char filename[256];
};

BPF_PERF_OUTPUT(execve_events);

// Use tracepoint instead of kprobe — args are stable here
TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    struct execve_event_t event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // args->filename is a stable pointer at tracepoint entry
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);

    execve_events.perf_submit(args, &event, sizeof(event));
    return 0;
}
