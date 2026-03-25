from bcc import BPF
import ctypes
import pathlib

BPF_FILE = pathlib.Path(__file__).parent / "ebpf" / "execve.c"

def main():
    b = BPF(src_file=str(BPF_FILE))

    # Clean up any existing attachment before attaching
    try:
        b.detach_tracepoint(tp="syscalls:sys_enter_execve")
    except Exception:
        pass  # nothing was attached, that's fine
    # Switch from kprobe to tracepoint
    b.attach_tracepoint(tp="syscalls:sys_enter_execve", fn_name="tracepoint__syscalls__sys_enter_execve")

    print("Bonfire is watching... (Ctrl+C to stop)\n")
    print(f"{'PID':<8} {'UID':<6} {'PROCESS':<16} {'COMMAND'}")
    print("-" * 60)

    class ExecveEvent(ctypes.Structure):
        _fields_ = [
            ("pid",      ctypes.c_uint32),
            ("uid",      ctypes.c_uint32),
            ("comm",     ctypes.c_char * 16),
            ("filename", ctypes.c_char * 256),
        ]

    def handle_event(cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(ExecveEvent)).contents
        pid      = event.pid
        uid      = event.uid
        comm     = event.comm.decode("utf-8", errors="replace")
        filename = event.filename.decode("utf-8", errors="replace")
        print(f"{pid:<8} {uid:<6} {comm:<16} {filename}")

    b["execve_events"].open_perf_buffer(handle_event)

    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\n Bonfire stopped.")
            break

if __name__ == "__main__":
    main()
