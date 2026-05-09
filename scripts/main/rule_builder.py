import yaml
import pathlib
import re

RULES_FILE = pathlib.Path(__file__).parent.parent / "rules" / "default.yaml"

# ── Valid conditions per event type ──────────────────────────────

EXECVE_CONDITIONS = [
    ("filename_in",    "list", "Filename in (comma separated)"),
    ("path_contains",  "list", "Path contains (comma separated)"),
    ("comm_in",        "list", "Process name in (comma separated)"),
    ("parent_comm_in", "list", "Parent process in (comma separated)"),
    ("argc_gt",        "int",  "Argument count greater than"),
    ("uid_is",         "int",  "UID equals"),
]

CONNECT_CONDITIONS = [
    ("dport_in",     "list", "Destination port in (comma separated)"),
    ("dport_not_in", "list", "Destination port NOT in (comma separated)"),
    ("dport_gt",     "int",  "Destination port greater than"),
    ("uid_is",       "int",  "UID equals"),
]


# ── Form state ───────────────────────────────────────────────────

class RuleFormState:
    SEVERITIES  = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    EVENT_TYPES = ["execve", "connect"]

    def __init__(self):
        self.step       = "basic"
        self.field_idx  = 0
        self.sev_idx    = 0
        self.event_idx  = 0
        self.id         = ""
        self.name       = ""
        self.cond_values = {}
        self.error      = ""
        self.saved      = False

    @property
    def severity(self) -> str:
        return self.SEVERITIES[self.sev_idx]

    @property
    def event_type(self) -> str:
        return self.EVENT_TYPES[self.event_idx]

    @property
    def conditions(self) -> list[tuple]:
        if self.event_type == "execve":
            return EXECVE_CONDITIONS
        return CONNECT_CONDITIONS

    @property
    def basic_field_count(self) -> int:
        return 4

    @property
    def condition_field_count(self) -> int:
        return len(self.conditions)

    def current_field_count(self) -> int:
        if self.step == "basic":
            return self.basic_field_count
        if self.step == "conditions":
            return self.condition_field_count
        return 1

    def next_field(self):
        self.field_idx = (self.field_idx + 1) % self.current_field_count()

    def prev_field(self):
        self.field_idx = (self.field_idx - 1) % self.current_field_count()

    def next_step(self) -> bool:
        if self.step == "basic":
            err = self._validate_basic()
            if err:
                self.error = err
                return False
            self.step      = "conditions"
            self.field_idx = 0
            self.error     = ""
            return True

        if self.step == "conditions":
            self.step      = "confirm"
            self.field_idx = 0
            self.error     = ""
            return True

        return False

    def prev_step(self):
        if self.step == "conditions":
            self.step      = "basic"
            self.field_idx = 0
        elif self.step == "confirm":
            self.step      = "conditions"
            self.field_idx = 0

    def _validate_basic(self) -> str:
        if not self.id.strip():
            return "Rule ID is required"
        if not re.match(r'^R\d+$', self.id.strip()):
            return "Rule ID must be in format R001, R013, etc."
        if not self.name.strip():
            return "Rule name is required"
        existing = _load_existing_ids()
        if self.id.strip() in existing:
            return f"Rule ID {self.id.strip()} already exists"
        return ""

    def build_rule(self) -> dict:
        rule = {
            "id":         self.id.strip(),
            "name":       self.name.strip(),
            "severity":   self.severity,
            "event_type": self.event_type,
            "conditions": {},
        }

        for cond_name, cond_type, _ in self.conditions:
            value = self.cond_values.get(cond_name, "").strip()
            if not value:
                continue

            if cond_type == "list":
                items = [v.strip() for v in value.split(",") if v.strip()]
                if items:
                    rule["conditions"][cond_name] = items
            elif cond_type == "int":
                try:
                    rule["conditions"][cond_name] = int(value)
                except ValueError:
                    pass

        return rule

    def format_preview(self) -> list[str]:
        rule  = self.build_rule()
        lines = []
        lines.append(f"id:         {rule['id']}")
        lines.append(f"name:       {rule['name']}")
        lines.append(f"severity:   {rule['severity']}")
        lines.append(f"event_type: {rule['event_type']}")
        lines.append("conditions:")
        if rule["conditions"]:
            for k, v in rule["conditions"].items():
                lines.append(f"    {k}: {v}")
        else:
            lines.append("    (none — matches all events of this type)")
        return lines


# ── YAML writing ─────────────────────────────────────────────────

def _load_existing_ids() -> set[str]:
    if not RULES_FILE.exists():
        return set()
    with open(RULES_FILE) as f:
        data = yaml.safe_load(f)
    return {r["id"] for r in data.get("rules", [])}


def save_rule(rule: dict) -> bool:
    try:
        if RULES_FILE.exists():
            with open(RULES_FILE) as f:
                data = yaml.safe_load(f) or {"rules": []}
        else:
            data = {"rules": []}

        data["rules"].append(rule)

        with open(RULES_FILE, "w") as f:
            yaml.dump(
                data, f,
                default_flow_style=False,
                sort_keys=False,
                allow_unicode=True
            )
        return True
    except Exception:
        return False
