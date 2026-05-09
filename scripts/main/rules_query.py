import yaml
import sqlite3
import pathlib

RULES_FILE = pathlib.Path(__file__).parent.parent / "rules" / "default.yaml"
DB_PATH    = pathlib.Path(__file__).parent.parent / "storage" / "cold" / "alerts.db"


# ── Rule loading ─────────────────────────────────────────────────

def fetch_rules() -> list[dict]:
    """Load all rules from default.yaml."""
    if not RULES_FILE.exists():
        return []

    with open(RULES_FILE) as f:
        data = yaml.safe_load(f)

    rules = data.get("rules", [])
    return rules


def fetch_rule_hits() -> dict[str, int]:
    """
    Get hit counts per rule from cold DB.
    Returns {rule_id: count} for all rules that have fired.
    """
    if not DB_PATH.exists():
        return {}

    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT rule_id, COUNT(*) FROM alerts GROUP BY rule_id"
        ).fetchall()
        return {r[0]: r[1] for r in rows}


def fetch_rules_with_hits() -> list[dict]:
    """
    Merge rules from yaml with hit counts from DB.
    Returns enriched rule dicts with a 'hits' field added.
    """
    rules = fetch_rules()
    hits  = fetch_rule_hits()

    for rule in rules:
        rule["hits"] = hits.get(rule["id"], 0)

    return rules


def is_sequence_rule(rule: dict) -> bool:
    """Sequence rules have a 'sequence' key instead of 'conditions'."""
    return "sequence" in rule


def format_conditions(rule: dict) -> list[str]:
    """
    Format rule conditions into readable strings for the expanded view.
    Handles both regular rules (conditions) and sequence rules (sequence steps).
    """
    lines = []

    if is_sequence_rule(rule):
        within = rule.get("within", "?")
        lines.append(f"Type: SEQUENCE  (within {within}s)")
        lines.append("")
        for i, step in enumerate(rule.get("sequence", []), 1):
            lines.append(f"Step {i} — {step.get('event_type', '?').upper()}")
            for cond, value in step.get("conditions", {}).items():
                lines.append(f"  {cond}: {value}")
    else:
        lines.append(f"Type: SINGLE EVENT")
        lines.append(f"Event: {rule.get('event_type', '?').upper()}")
        lines.append("")
        lines.append("Conditions:")
        for cond, value in rule.get("conditions", {}).items():
            lines.append(f"  {cond}: {value}")

    return lines
