import sqlite3
import json
import pathlib
import math
from datetime import datetime, timedelta, timezone

DB_PATH   = pathlib.Path(__file__).parent.parent / "storage" / "cold" / "alerts.db"
PAGE_SIZE = 15


# ── Filter definition ────────────────────────────────────────────

class Filters:
    SEVERITIES = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
    TIME_OPTS  = {"ALL": None, "1h": 1, "24h": 24, "7d": 168, "30d": 720}

    def __init__(self):
        self.severity = "ALL"
        self.rule_id  = "ALL"
        self.time     = "ALL"
        self.process  = ""
        self.search   = ""
        self.year  = "ALL"
        self.month = "ALL"

    def build_query(self, count_only=False) -> tuple[str, list]:
        """
        Build a SQL query from active filters.
        Only adds WHERE clauses for filters that are actually set.
        Returns (sql, params).
        """
        conditions = []
        params     = []

        if self.severity != "ALL":
            conditions.append("severity = ?")
            params.append(self.severity)

        if self.rule_id != "ALL":
            conditions.append("rule_id = ?")
            params.append(self.rule_id)

        if self.time != "ALL":
            hours  = self.TIME_OPTS[self.time]
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
            conditions.append("timestamp >= ?")
            params.append(cutoff.isoformat())

        if self.year != "ALL" or self.month != "ALL":
            year = (self.year if self.year != "ALL" 
                    else str(datetime.now(timezone.utc).year))
            if self.month != "ALL":
                 # year + month — exact month
                 conditions.append("strftime('%Y-%m', timestamp) = ?")
                 params.append(f"{year}-{self.month}")
            else:
            	# year only
            	conditions.append("strftime('%Y', timestamp) = ?")
            	params.append(year)

        if self.process.strip():
            conditions.append("comm LIKE ?")
            params.append(f"%{self.process.strip()}%")

        if self.search.strip():
            conditions.append(
                "(rule_name LIKE ? OR message LIKE ? "
                "OR comm LIKE ? OR rule_id LIKE ?)"
            )
            term = f"%{self.search.strip()}%"
            params.extend([term, term, term, term])

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        if count_only:
            sql = f"SELECT COUNT(*) FROM alerts {where}"
        else:
            sql = (
                f"SELECT * FROM alerts {where} "
                f"ORDER BY timestamp DESC"
            )

        return sql, params


# ── Query functions ──────────────────────────────────────────────

def fetch_page(filters: Filters, page: int) -> list[dict]:
    """Fetch one page of alerts matching the current filters."""
    if not DB_PATH.exists():
        return []

    sql, params = filters.build_query()
    sql        += f" LIMIT {PAGE_SIZE} OFFSET ?"
    params.append((page - 1) * PAGE_SIZE)

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]


def fetch_count(filters: Filters) -> int:
    """Count total alerts matching current filters."""
    if not DB_PATH.exists():
        return 0

    sql, params = filters.build_query(count_only=True)
    with sqlite3.connect(DB_PATH) as conn:
        return conn.execute(sql, params).fetchone()[0]


def fetch_rule_ids() -> list[str]:
    """Get all distinct rule IDs present in the DB."""
    if not DB_PATH.exists():
        return ["ALL"]

    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT DISTINCT rule_id FROM alerts ORDER BY rule_id"
        ).fetchall()
        return ["ALL"] + [r[0] for r in rows]


def fetch_alert_by_id(alert_id: int) -> dict | None:
    """Fetch a single alert by its ID."""
    if not DB_PATH.exists():
        return None

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM alerts WHERE id = ?", (alert_id,)
        ).fetchone()
        return dict(row) if row else None

def fetch_years() -> list[str]:
    """Get all distinct years present in the DB."""
    if not DB_PATH.exists():
        return ["ALL"]

    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT DISTINCT strftime('%Y', timestamp) "
            "FROM alerts ORDER BY 1 DESC"
        ).fetchall()
        return ["ALL"] + [r[0] for r in rows if r[0]]

def total_pages(filters: Filters) -> int:
    """Calculate total number of pages for current filters."""
    return max(1, math.ceil(fetch_count(filters) / PAGE_SIZE))


def parse_detail(alert: dict) -> dict:
    """Safely parse the JSON detail field of an alert."""
    try:
        return json.loads(alert.get("detail") or "{}")
    except Exception:
        return {}
