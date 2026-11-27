"""
Log loading and normalization.

Supported inputs:
  * .jsonl / .json   flat Sysmon-style records, Winlogbeat / Elastic exports,
                     or PowerShell `Get-WinEvent | ConvertTo-Json` style output
  * .xml             `wevtutil qe <log> /f:xml` exports
  * .evtx            native Windows event logs (requires `pip install python-evtx`)
"""
from __future__ import annotations

import json
import ntpath
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

_NS = re.compile(r"\{.*?\}")
_FRACTION = re.compile(r"(\.\d{6})\d+")


@dataclass
class Event:
    event_id: int
    timestamp: datetime
    computer: str = "unknown"
    fields: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._lower = {k.lower(): v for k, v in self.fields.items()}

    def get(self, name: str, default: str = "") -> str:
        """Case-insensitive field lookup, plus a few derived fields."""
        key = name.lower()
        if key == "computer":
            return self.computer
        if key == "eventid":
            return str(self.event_id)
        if key.endswith("name") and key[:-4] in ("image", "parentimage", "targetimage", "sourceimage"):
            return ntpath.basename(self._lower.get(key[:-4], "")) or default
        return self._lower.get(key, default)


def parse_timestamp(value: str | int | float | None) -> datetime:
    if value is None or value == "":
        return datetime.fromtimestamp(0, tz=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value / 1000 if value > 1e11 else value, tz=timezone.utc)
    text = str(value).strip()
    m = re.fullmatch(r"/Date\((\d+)\)/", text)  # PowerShell JSON dates
    if m:
        return datetime.fromtimestamp(int(m.group(1)) / 1000, tz=timezone.utc)
    text = text.replace("Z", "+00:00").replace(" ", "T", 1)
    text = _FRACTION.sub(r"\1", text)
    ts = datetime.fromisoformat(text)
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _stringify(data: dict) -> dict[str, str]:
    return {str(k): "" if v is None else str(v) for k, v in data.items()
            if not isinstance(v, (dict, list))}


def normalize_record(rec: dict) -> Event | None:
    """Turn one JSON record (any supported flavour) into an Event."""
    if "winlog" in rec:  # Winlogbeat / Elastic
        wl = rec["winlog"]
        fields = _stringify(wl.get("event_data", {}))
        eid = wl.get("event_id") or rec.get("event", {}).get("code")
        computer = wl.get("computer_name") or rec.get("host", {}).get("name", "unknown")
        ts = rec.get("@timestamp") or fields.get("UtcTime")
    else:
        fields = _stringify(rec)
        for nested in ("EventData", "event_data", "Properties"):
            if isinstance(rec.get(nested), dict):
                fields.update(_stringify(rec[nested]))
        eid = rec.get("EventID", rec.get("Id", rec.get("event_id")))
        computer = rec.get("Computer") or rec.get("MachineName") or "unknown"
        ts = fields.get("UtcTime") or rec.get("TimeCreated") or rec.get("@timestamp")
    if eid is None:
        return None
    return Event(int(eid), parse_timestamp(ts), str(computer), fields)


def parse_event_xml(xml_text: str) -> Event | None:
    root = ET.fromstring(xml_text)
    for el in root.iter():
        el.tag = _NS.sub("", el.tag)
    system = root.find("System")
    if system is None:
        return None
    eid = system.findtext("EventID")
    created = system.find("TimeCreated")
    fields = {d.get("Name", f"Data{i}"): d.text or ""
              for i, d in enumerate(root.findall("EventData/Data"))}
    ts = fields.get("UtcTime") or (created.get("SystemTime") if created is not None else None)
    return Event(int(eid), parse_timestamp(ts), system.findtext("Computer") or "unknown", fields)


def _iter_xml_events(text: str) -> Iterator[str]:
    yield from re.findall(r"<Event[\s>].*?</Event>", text, flags=re.S)


def load_events(path: str | Path) -> list[Event]:
    path = Path(path)
    suffix = path.suffix.lower()
    events: Iterable[Event | None]

    if suffix == ".evtx":
        try:
            from Evtx.Evtx import Evtx
        except ImportError as exc:
            raise SystemExit("Reading .evtx needs: pip install python-evtx") from exc
        with Evtx(str(path)) as log:
            events = [parse_event_xml(r.xml()) for r in log.records()]
    elif suffix == ".xml":
        events = [parse_event_xml(x) for x in _iter_xml_events(path.read_text(encoding="utf-8-sig"))]
    else:
        text = path.read_text(encoding="utf-8-sig").strip()
        if text.startswith("["):
            records = json.loads(text)
        else:
            records = [json.loads(line) for line in text.splitlines() if line.strip()]
        events = [normalize_record(r) for r in records]

    return sorted((e for e in events if e), key=lambda e: e.timestamp)
