import json
import zipfile
import pathlib
from datetime import datetime

HOT_DIR  = pathlib.Path(__file__).parent.parent / "storage" / "hot"
WARM_DIR = pathlib.Path(__file__).parent.parent / "storage" / "warm"


# ── Archive listing ──────────────────────────────────────────────

def fetch_archives() -> list[dict]:
    """
    Return all available monthly archives from warm/ sorted by date desc.
    Each entry: { ym, label, path, size_mb }
    """
    archives = []

    for f in sorted(WARM_DIR.glob("bonfire_*.zip"), reverse=True):
        # bonfire_2025-01.zip → 2025-01
        ym    = f.stem.replace("bonfire_", "")
        label = _ym_to_label(ym)
        size  = round(f.stat().st_size / (1024 * 1024), 2)
        archives.append({
            "ym":       ym,
            "label":    label,
            "path":     f,
            "size_mb":  size,
        })

    return archives


def fetch_hot_days() -> list[dict]:
    """
    Return all daily log files currently in hot/ sorted by date desc.
    Each entry: { date, label, path, line_count }
    """
    days = []

    for f in sorted(HOT_DIR.glob("bonfire_*.log"), reverse=True):
        date  = f.stem.replace("bonfire_", "")
        label = _date_to_label(date)
        count = _count_lines(f)
        days.append({
            "date":       date,
            "label":      label,
            "path":       f,
            "line_count": count,
        })

    return days


# ── Daily log reading ────────────────────────────────────────────

def fetch_days_from_archive(zip_path: pathlib.Path) -> list[dict]:
    """
    List all daily log files inside a zip archive.
    Returns entries sorted by date desc.
    """
    days = []

    with zipfile.ZipFile(zip_path, "r") as zf:
        for name in sorted(zf.namelist(), reverse=True):
            if not name.endswith(".log"):
                continue
            date  = name.replace("bonfire_", "").replace(".log", "")
            label = _date_to_label(date)
            info  = zf.getinfo(name)
            # count lines from compressed data
            data  = zf.read(name).decode("utf-8", errors="replace")
            count = len([l for l in data.splitlines() if l.strip()])
            days.append({
                "date":       date,
                "label":      label,
                "filename":   name,
                "line_count": count,
            })

    return days


def fetch_events_from_archive(zip_path: pathlib.Path,
                               filename: str) -> list[dict]:
    """Read and parse all events from a daily log inside a zip."""
    with zipfile.ZipFile(zip_path, "r") as zf:
        data = zf.read(filename).decode("utf-8", errors="replace")

    return _parse_log_lines(data.splitlines())


def fetch_events_from_hot(log_path: pathlib.Path) -> list[dict]:
    """Read and parse all events from a hot daily log file."""
    with open(log_path, "r") as f:
        lines = f.readlines()

    return _parse_log_lines(lines)


# ── Helpers ──────────────────────────────────────────────────────

def _parse_log_lines(lines: list[str]) -> list[dict]:
    """Parse JSON lines into event dicts, skip SYSTEM entries."""
    events = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
            if ev.get("type") == "SYSTEM":
                continue
            events.append(ev)
        except json.JSONDecodeError:
            continue
    return events


def _count_lines(path: pathlib.Path) -> int:
    try:
        with open(path, "r") as f:
            return sum(1 for l in f if l.strip())
    except Exception:
        return 0


def _ym_to_label(ym: str) -> str:
    """'2025-01' → 'January 2025'"""
    try:
        dt = datetime.strptime(ym, "%Y-%m")
        return dt.strftime("%B %Y")
    except Exception:
        return ym


def _date_to_label(date: str) -> str:
    """'2025-01-15' → 'Wednesday 15 January 2025'"""
    try:
        dt = datetime.strptime(date, "%Y-%m-%d")
        return dt.strftime("%A %d %B %Y")
    except Exception:
        return date
