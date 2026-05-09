import yaml
import pathlib
from dataclasses import dataclass
from datetime import datetime
from events import ExecveEvent, ConnectEvent

RULES_FILE = pathlib.Path(__file__).parent.parent / "rules" / "default.yaml"


# ── Alert object ────────────────────────────────────────────────

@dataclass
class Alert:
    rule_id:   str
    rule_name: str
    severity:  str
    message:   str
    event:     object
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()

    def __str__(self):
        return (
            f"[{self.severity}] {self.rule_name} | "
            f"{self.message} | "
            f"pid={self.event.pid} proc={self.event.comm}"
        )


# ── Rule engine ─────────────────────────────────────────────────

class RuleEngine:

    def __init__(self, rules_path: pathlib.Path = RULES_FILE):
        self.rules = self._load(rules_path)
        print(f"[rules] loaded {len(self.rules)} rules from {rules_path}")

    def _load(self, path: pathlib.Path) -> list:
        with open(path) as f:
            data = yaml.safe_load(f)
        return data.get("rules", [])

    def evaluate(self, event) -> list[Alert]:
        """Evaluate an event against all rules. Returns list of alerts fired."""
        alerts = []
        for rule in self.rules:
            if self._matches(rule, event):
                alerts.append(Alert(
                    rule_id   = rule["id"],
                    rule_name = rule["name"],
                    severity  = rule["severity"],
                    message   = self._describe(rule, event),
                    event     = event,
                ))
        return alerts

    def _matches(self, rule: dict, event) -> bool:
        # rule only applies to its event type
        event_type = rule.get("event_type")
        if event_type == "execve" and not isinstance(event, ExecveEvent):
            return False
        if event_type == "connect" and not isinstance(event, ConnectEvent):
            return False

        conditions = rule.get("conditions", {})

        for condition, value in conditions.items():

            # comm must be in list
            if condition == "comm_in":
                if not any(event.comm == v for v in value):
                    return False

            # filename must contain one of the values
            elif condition == "filename_in":
                if not any(v in event.filename for v in value):
                    return False

            # parent process name must be in list
            elif condition == "parent_comm_in":
                if not hasattr(event, 'pcomm'):
                    return False
                if not any(event.pcomm == v for v in value):
                    return False

            # argument count exceeds threshold
            elif condition == "argc_gt":
                if not hasattr(event, 'argc') or event.argc <= value:
                    return False

            # destination port must be in list
            elif condition == "dport_in":
                if event.dport not in value:
                    return False

            # filename must contain one of the values (alias for path_contains)
            elif condition == "path_contains":
                if not any(v in event.filename for v in value):
                    return False

            # destination port must be greater than value
            elif condition == "dport_gt":
                if not hasattr(event, 'dport') or event.dport <= value:
                    return False

            # destination port must NOT be in list
            elif condition == "dport_not_in":
                if event.dport in value:
                    return False

            # uid must match exactly
            elif condition == "uid_is":
                if event.uid != value:
                    return False

        return True

    def _describe(self, rule: dict, event) -> str:
        if isinstance(event, ExecveEvent):
            return f"proc={event.comm} executed {event.filename}"
        if isinstance(event, ConnectEvent):
            return f"proc={event.comm} connected to {event.daddr}:{event.dport}"
        return str(event)
