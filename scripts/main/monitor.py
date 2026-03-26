from bcc import BPF
import ctypes
import pathlib
import socket
import struct
from events import ExecveEvent, ConnectEvent
from rules import RuleEngine

engine = RuleEngine()


EBPF_DIR = pathlib.Path(__file__).parent / "ebpf"

def load_bpf(filename: str) -> BPF:
    return BPF(src_file=str(EBPF_DIR / filename))

def attach_execve(b: BPF):
    try:
        b.detach_tracepoint(tp="syscalls:sys_enter_execve")
    except Exception:
        pass
    b.attach_tracepoint(
        tp="syscalls:sys_enter_execve",
        fn_name="tracepoint__syscalls__sys_enter_execve"
    )
def attach_connect(b: BPF):
    try:
        b.detach_tracepoint(tp="syscalls:sys_enter_connect")
    except Exception:
        pass
    b.attach_tracepoint(
        tp="syscalls:sys_enter_connect",
        fn_name="tracepoint__syscalls__sys_enter_connect"
    )

# ── ctypes raw structs ──────────────────────────────────────────

class _ExecveRaw(ctypes.Structure):
    _fields_ = [
        ("pid",      ctypes.c_uint32),
        ("uid",      ctypes.c_uint32),
        ("comm",     ctypes.c_char * 16),
        ("filename", ctypes.c_char * 256),
    ]

class _ConnectRaw(ctypes.Structure):
    _fields_ = [
        ("pid",   ctypes.c_uint32),
        ("uid",   ctypes.c_uint32),
        ("comm",  ctypes.c_char * 16),
        ("daddr", ctypes.c_uint32),
        ("dport", ctypes.c_uint16),
    ]

# ── helpers ─────────────────────────────────────────────────────

def int_to_ip(addr: int) -> str:
    # kernel gives us the IP as a little-endian u32
    return socket.inet_ntoa(struct.pack("<I", addr))

def ntohs(port: int) -> int:
    return socket.ntohs(port)

# ── main ────────────────────────────────────────────────────────

def main():
    # load both eBPF programs
    b_execve  = load_bpf("execve.c")
    b_connect = load_bpf("connect.c")

    attach_execve(b_execve)
    attach_connect(b_connect)

    print("🔥 Bonfire is watching... (Ctrl+C to stop)\n")
    print(f"{'TYPE':<10} {'PID':<8} {'UID':<6} {'PROCESS':<16} {'DETAIL'}")
    print("-" * 70)

    def handle_execve(cpu, data, size):
        raw = ctypes.cast(data, ctypes.POINTER(_ExecveRaw)).contents
        event = ExecveEvent(
            pid      = raw.pid,
            uid      = raw.uid,
            comm     = raw.comm.decode("utf-8", errors="replace"),
            filename = raw.filename.decode("utf-8", errors="replace"),
        )
        print(f"{'EXECVE':<10} {event.pid:<8} {event.uid:<6} {event.comm:<16} {event.filename}")

        # evaluate against rules
        for alert in engine.evaluate(event):
            print(f"\n  ⚠️  ALERT [{alert.severity}] {alert.rule_name}")
            print(f"      {alert.message}\n")

    def handle_connect(cpu, data, size):
        raw = ctypes.cast(data, ctypes.POINTER(_ConnectRaw)).contents
        event = ConnectEvent(
            pid   = raw.pid,
            uid   = raw.uid,
            comm  = raw.comm.decode("utf-8", errors="replace"),
            daddr = int_to_ip(raw.daddr),
            dport = ntohs(raw.dport),
        )
        print(f"{'CONNECT':<10} {event.pid:<8} {event.uid:<6} {event.comm:<16} {event.daddr}:{event.dport}")

        # evaluate against rules
        for alert in engine.evaluate(event):
            print(f"\n  ⚠️  ALERT [{alert.severity}] {alert.rule_name}")
            print(f"      {alert.message}\n")

    b_execve["execve_events"].open_perf_buffer(handle_execve)
    b_connect["connect_events"].open_perf_buffer(handle_connect)

    while True:
        try:
            b_execve.perf_buffer_poll(timeout=100)
            b_connect.perf_buffer_poll(timeout=100)
        except KeyboardInterrupt:
            print("\n Bonfire stopped.")
            break

if __name__ == "__main__":
    main()
