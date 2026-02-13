import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo


@dataclass(slots=True)
class ParsedLine:
    ts: datetime | None
    sender: str
    text: str
    inferred: bool = False


@dataclass(slots=True)
class ParseResult:
    messages: list[ParsedLine]
    total_lines: int
    matched_lines: int
    inferred_lines: int
    first_lines: list[str]
    unmatched_lines: list[str]


WHATSAPP_RE = re.compile(
    r"^(?P<date>\d{1,2}[/-]\d{1,2}[/-]\d{2,4}),\s(?P<time>\d{1,2}:\d{2})(?:\s?(?P<ampm>[APMapm]{2}))?\s-\s(?P<sender>[^:]{1,80}):\s?(?P<text>.*)$"
)
BRACKET_RE = re.compile(
    r"^\[(?P<date>\d{1,2}[/-]\d{1,2}[/-]\d{2,4}),\s(?P<time>\d{1,2}:\d{2})(?:\s?(?P<ampm>[APMapm]{2}))?\]\s(?P<sender>[^:]{1,80}):\s?(?P<text>.*)$"
)
IMESSAGE_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})\s(?P<time>\d{2}:\d{2}:\d{2})\s(?P<sender>[^:]{1,80}):\s?(?P<text>.*)$"
)
DISCORD_RE = re.compile(
    r"^(?P<sender>[^:]{1,80})\s[—-]\s(?P<when>(?:Today|Yesterday)\sat\s\d{1,2}:\d{2}\s?[APMapm]{2}):\s?(?P<text>.*)$"
)
SENDER_FALLBACK_RE = re.compile(r"^(?P<sender>[A-Za-z0-9 _.\-]{1,80}):\s?(?P<text>.+)$")


def parse_chat_file(path: str, timezone_name: str = "UTC") -> ParseResult:
    raw = Path(path).read_text(encoding="utf-8", errors="replace")
    if not raw.strip():
        return ParseResult(messages=[], total_lines=0, matched_lines=0, inferred_lines=0, first_lines=[], unmatched_lines=[])

    if Path(path).suffix.lower() == ".json":
        return _parse_json(raw, timezone_name)
    return _parse_text(raw, timezone_name)


def _parse_json(raw: str, timezone_name: str) -> ParseResult:
    lines = raw.splitlines()
    first_lines = lines[:10]
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        # Fall back to text parsing heuristics if JSON is malformed.
        return _parse_text(raw, timezone_name)

    rows = payload.get("messages", []) if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        return ParseResult(messages=[], total_lines=len(lines), matched_lines=0, inferred_lines=0, first_lines=first_lines, unmatched_lines=lines[:5])

    parsed: list[ParsedLine] = []
    inferred_count = 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        sender = str(
            row.get("sender")
            or row.get("author")
            or row.get("from")
            or row.get("username")
            or row.get("name")
            or "Unknown"
        ).strip() or "Unknown"
        text = str(row.get("text") or row.get("content") or row.get("message") or row.get("body") or "").strip()
        ts_val = row.get("ts") or row.get("timestamp") or row.get("date") or row.get("created_at") or row.get("time")
        ts = _coerce_ts(ts_val, timezone_name)
        if not text:
            continue
        inferred = ts is None
        inferred_count += 1 if inferred else 0
        parsed.append(ParsedLine(ts=ts, sender=sender, text=text, inferred=inferred))

    return ParseResult(
        messages=parsed,
        total_lines=len(lines),
        matched_lines=len(parsed) - inferred_count,
        inferred_lines=inferred_count,
        first_lines=first_lines,
        unmatched_lines=[],
    )


def _parse_text(raw: str, timezone_name: str) -> ParseResult:
    lines = raw.splitlines()
    tz = ZoneInfo(timezone_name)
    parsed: list[ParsedLine] = []
    unmatched: list[str] = []
    matched_lines = 0
    inferred_lines = 0

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue

        parsed_line = _match_structured_line(line, tz)
        if parsed_line:
            parsed.append(parsed_line)
            if parsed_line.inferred:
                inferred_lines += 1
            else:
                matched_lines += 1
            continue

        # Permissive fallback for "Name: message"
        fallback = SENDER_FALLBACK_RE.match(line)
        if fallback:
            parsed.append(
                ParsedLine(
                    ts=parsed[-1].ts if parsed else None,
                    sender=fallback.group("sender").strip() or "Unknown",
                    text=fallback.group("text").strip(),
                    inferred=True,
                )
            )
            inferred_lines += 1
            continue

        # Multiline continuation
        if parsed:
            parsed[-1].text = f"{parsed[-1].text}\n{line}".strip()
            continue

        unmatched.append(line)

    return ParseResult(
        messages=parsed,
        total_lines=len(lines),
        matched_lines=matched_lines,
        inferred_lines=inferred_lines,
        first_lines=lines[:10],
        unmatched_lines=unmatched[:5],
    )


def _match_structured_line(line: str, tz: ZoneInfo) -> ParsedLine | None:
    m = WHATSAPP_RE.match(line)
    if m:
        ts = _parse_mdy(m.group("date"), m.group("time"), m.group("ampm"), tz)
        return ParsedLine(ts=ts, sender=(m.group("sender").strip() or "Unknown"), text=m.group("text").strip(), inferred=False)

    m = BRACKET_RE.match(line)
    if m:
        ts = _parse_mdy(m.group("date"), m.group("time"), m.group("ampm"), tz)
        return ParsedLine(ts=ts, sender=(m.group("sender").strip() or "Unknown"), text=m.group("text").strip(), inferred=False)

    m = IMESSAGE_RE.match(line)
    if m:
        ts = datetime.strptime(f"{m.group('date')} {m.group('time')}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=tz)
        return ParsedLine(ts=ts, sender=(m.group("sender").strip() or "Unknown"), text=m.group("text").strip(), inferred=False)

    m = DISCORD_RE.match(line)
    if m:
        ts = _parse_discord_when(m.group("when"), tz)
        return ParsedLine(ts=ts, sender=(m.group("sender").strip() or "Unknown"), text=m.group("text").strip(), inferred=False)

    return None


def _parse_mdy(date_part: str, time_part: str, ampm: str | None, tz: ZoneInfo) -> datetime | None:
    raw = f"{date_part} {time_part}".strip()
    candidates = [
        "%m/%d/%y %H:%M",
        "%d/%m/%y %H:%M",
        "%m/%d/%Y %H:%M",
        "%d/%m/%Y %H:%M",
        "%m-%d-%y %H:%M",
        "%d-%m-%y %H:%M",
        "%m-%d-%Y %H:%M",
        "%d-%m-%Y %H:%M",
    ]
    if ampm:
        raw = f"{date_part} {time_part} {ampm.upper()}"
        candidates = [
            "%m/%d/%y %I:%M %p",
            "%d/%m/%y %I:%M %p",
            "%m/%d/%Y %I:%M %p",
            "%d/%m/%Y %I:%M %p",
            "%m-%d-%y %I:%M %p",
            "%d-%m-%y %I:%M %p",
            "%m-%d-%Y %I:%M %p",
            "%d-%m-%Y %I:%M %p",
        ]
    for fmt in candidates:
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=tz)
        except ValueError:
            continue
    return None


def _parse_discord_when(when: str, tz: ZoneInfo) -> datetime:
    now = datetime.now(tz)
    lower = when.lower().strip()
    base = now.date()
    if lower.startswith("yesterday"):
        base = (now - timedelta(days=1)).date()
    time_part = lower.split("at", 1)[-1].strip()
    parsed_time = datetime.strptime(time_part.upper(), "%I:%M %p")
    return datetime(base.year, base.month, base.day, parsed_time.hour, parsed_time.minute, tzinfo=tz)


def _coerce_ts(value: object, timezone_name: str) -> datetime | None:
    if value is None or value == "":
        return None
    tz = ZoneInfo(timezone_name)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    raw = str(value).strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=tz)
    return dt

