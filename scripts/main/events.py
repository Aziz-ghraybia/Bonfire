from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ExecveEvent:
    pid:       int
    uid:       int
    ppid:      int          # parent PID
    argc:      int          # number of arguments
    comm:      str          # process that called execve (e.g. "bash")
    pcomm:     str          # parent process name
    filename:  str          # what it's trying to execute (e.g. "/bin/sh")
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def is_root(self) -> bool:
        return self.uid == 0

    def is_high_argc(self, threshold: int = 6) -> bool:
        return self.argc >= threshold

    def __str__(self) -> str:
        return (
            f"[EXECVE] pid={self.pid} uid={self.uid} "
            f"ppid={self.ppid} parent={self.pcomm} "
            f"proc={self.comm} cmd={self.filename} argc={self.argc}"
        )


@dataclass
class ConnectEvent:
    pid:       int
    uid:       int
    comm:      str          # process making the connection (e.g. "curl")
    daddr:     str          # destination IP (e.g. "185.220.101.47")
    dport:     int          # destination port (e.g. 4444)
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def is_root(self) -> bool:
        return self.uid == 0

    def is_suspicious_port(self) -> bool:
        # ports that are never normal for outbound traffic
        return self.dport in {4444, 1337, 31337, 9001, 6666, 6667}

    def __str__(self) -> str:
        return (
            f"[CONNECT] pid={self.pid} uid={self.uid} "
            f"proc={self.comm} dst={self.daddr}:{self.dport}"
        )
