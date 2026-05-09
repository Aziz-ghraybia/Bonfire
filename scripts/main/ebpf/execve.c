#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAXARGS 20

struct execve_event_t {
    u32  pid;
    u32  uid;
    u32  ppid;
    u32  argc;          // number of arguments
    char comm[16];
    char pcomm[16];
    char filename[256];
};

BPF_PERF_OUTPUT(execve_events);
BPF_PERCPU_ARRAY(event_buf, struct execve_event_t, 1);

TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    int zero = 0;
    struct execve_event_t *event = event_buf.lookup(&zero);
    if (!event)
        return 0;

    event->pid  = bpf_get_current_pid_tgid() >> 32;
    event->uid  = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->ppid = 0;
    event->argc = 0;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), args->filename);

    // parent info
    struct task_struct *task   = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = NULL;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);

    if (parent) {
        bpf_probe_read_kernel(&event->ppid,  sizeof(event->ppid),  &parent->tgid);
        bpf_probe_read_kernel_str(&event->pcomm, sizeof(event->pcomm), &parent->comm);
    }

    // count arguments — just read the pointer, not the string
    // this is safe because we never dereference into a buffer
    const char __user *argp = NULL;
    u32 count = 0;

    #pragma unroll
    for (int i = 1; i < MAXARGS; i++) {
        bpf_probe_read_user(&argp, sizeof(argp), &args->argv[i]);
        if (!argp)
            break;
        count++;
    }

    event->argc = count;

    execve_events.perf_submit(args, event, sizeof(*event));
    return 0;
}
