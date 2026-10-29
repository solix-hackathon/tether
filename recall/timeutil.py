"""Simulated time. Everything runs on integer epoch seconds; output uses ISO-8601 UTC strings."""

from datetime import datetime, timezone

ISO_FMT = "%Y-%m-%dT%H:%M:%SZ"


def parse_iso(s: str) -> int:
    return int(datetime.strptime(s, ISO_FMT).replace(tzinfo=timezone.utc).timestamp())


def iso(ts) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, timezone.utc).strftime(ISO_FMT)


def parse_offset(s: str) -> int:
    """'+01:30:00' -> 5400, '-00:00:30' -> -30."""
    sign = -1 if s.startswith("-") else 1
    h, m, sec = (int(p) for p in s.lstrip("+-").split(":"))
    return sign * (h * 3600 + m * 60 + sec)


def resolve(value, base: int) -> int:
    """A scenario time is either an absolute ISO string or an offset from the scenario start."""
    if isinstance(value, int):
        return value
    if value.startswith(("+", "-")):
        return base + parse_offset(value)
    return parse_iso(value)
