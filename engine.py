"""
Detection, correlation and storytelling.

1. Run every rule over every event          -> Detections
2. Group detections per host by time gaps   -> Incidents
3. Rebuild the Sysmon process tree          -> who spawned what
4. Render each hit as a plain-English line  -> the "story"
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from logparser import Event
from rules import RULES, SEVERITY_ORDER, TACTICS, THRESHOLD_RULES, Rule, ThresholdRule


class _SafeDict(dict):
    def __missing__(self, key: str) -> str:
        return "?"


@dataclass
class Detection:
    rule: Rule | ThresholdRule
    event: Event
    story: str

    @property
    def timestamp(self) -> datetime:
        return self.event.timestamp

    @property
    def severity(self) -> str:
        return self.rule.severity

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "computer": self.event.computer,
            "rule_id": self.rule.id,
            "title": self.rule.title,
            "severity": self.severity,
            "tactic": self.rule.tactic,
            "technique": self.rule.technique,
            "technique_name": self.rule.technique_name,
            "story": self.story,
            "event_id": self.event.event_id,
            "fields": self.event.fields,
        }


@dataclass
class ProcessNode:
    guid: str
    image: str
    command_line: str
    user: str
    timestamp: datetime
    parent_guid: str = ""
    children: list["ProcessNode"] = field(default_factory=list)
    flagged: list[str] = field(default_factory=list)  # rule ids

    @property
    def name(self) -> str:
        return self.image.replace("/", "\\").rsplit("\\", 1)[-1]


@dataclass
class Incident:
    id: int
    computer: str
    detections: list[Detection]
    roots: list[ProcessNode] = field(default_factory=list)

    @property
    def start(self) -> datetime:
        return self.detections[0].timestamp

    @property
    def end(self) -> datetime:
        return self.detections[-1].timestamp

    @property
    def severity(self) -> str:
        return max((d.severity for d in self.detections), key=SEVERITY_ORDER.get)

    @property
    def tactics(self) -> list[str]:
        hit = {d.rule.tactic for d in self.detections}
        return [t for t in TACTICS if t in hit]

    @property
    def users(self) -> list[str]:
        return sorted({d.event.get("User") for d in self.detections if d.event.get("User")})

    def headline(self) -> str:
        secs = int((self.end - self.start).total_seconds())
        span = f"{secs // 60} min" if secs >= 60 else f"{secs} s"
        n, t = len(self.detections), len(self.tactics)
        if n == 1:
            return f"1 suspicious action on {self.computer} ({self.tactics[0]})"
        return (f"{n} suspicious action{'s' * (n != 1)} on {self.computer} over {span}, "
                f"covering {t} ATT&CK tactic{'s' * (t != 1)}: {' -> '.join(self.tactics)}")


@dataclass
class Analysis:
    events: list[Event]
    detections: list[Detection]
    incidents: list[Incident]

    @property
    def tactic_hits(self) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for d in self.detections:
            counts[d.rule.tactic] += 1
        return {t: counts.get(t, 0) for t in TACTICS}

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for d in self.detections:
            counts[d.severity] += 1
        return counts

    def to_dict(self) -> dict:
        return {
            "summary": {
                "events": len(self.events),
                "detections": len(self.detections),
                "incidents": len(self.incidents),
                "severity": self.severity_counts,
            },
            "incidents": [
                {"id": i.id, "computer": i.computer, "severity": i.severity,
                 "start": i.start.isoformat(), "end": i.end.isoformat(),
                 "tactics": i.tactics, "headline": i.headline(),
                 "detections": [d.to_dict() for d in i.detections]}
                for i in self.incidents
            ],
        }


# ---------------------------------------------------------------- detection
def _story(template: str, event: Event, **extra) -> str:
    values = _SafeDict(extra)
    for key in ("ImageName", "ParentImageName", "SourceImageName", "TargetImageName", "Computer"):
        values[key] = event.get(key) or "?"
    for k, v in event.fields.items():
        values.setdefault(k, v)
    return template.format_map(values)


def detect(events: list[Event], rules: list[Rule] = RULES,
           threshold_rules: list[ThresholdRule] = THRESHOLD_RULES) -> list[Detection]:
    hits: list[Detection] = []
    for ev in events:
        for rule in rules:
            if rule.matches(ev):
                hits.append(Detection(rule, ev, _story(rule.story, ev)))

    for trule in threshold_rules:
        windows: dict[tuple, deque] = defaultdict(deque)
        fired: set[tuple] = set()
        for ev in events:
            if ev.event_id not in trule.event_ids:
                continue
            key = (ev.computer, ev.get(trule.group_by) or "unknown")
            win = windows[key]
            win.append(ev.timestamp)
            while (ev.timestamp - win[0]).total_seconds() > trule.window:
                win.popleft()
            if len(win) >= trule.count and key not in fired:
                fired.add(key)
                story = _story(trule.story, ev, count=len(win), key=key[1], window=trule.window)
                hits.append(Detection(trule, ev, story))

    return sorted(hits, key=lambda d: d.timestamp)


# -------------------------------------------------------------- correlation
def build_process_tree(events: list[Event]) -> dict[str, ProcessNode]:
    nodes: dict[str, ProcessNode] = {}
    for ev in events:
        if ev.event_id != 1 or not ev.get("ProcessGuid"):
            continue
        nodes[ev.get("ProcessGuid")] = ProcessNode(
            guid=ev.get("ProcessGuid"), image=ev.get("Image"),
            command_line=ev.get("CommandLine"), user=ev.get("User"),
            timestamp=ev.timestamp, parent_guid=ev.get("ParentProcessGuid"))
    for node in nodes.values():
        parent = nodes.get(node.parent_guid)
        if parent:
            parent.children.append(node)
    return nodes


def _root_of(node: ProcessNode, nodes: dict[str, ProcessNode]) -> ProcessNode:
    seen = set()
    while node.parent_guid in nodes and node.guid not in seen:
        seen.add(node.guid)
        node = nodes[node.parent_guid]
    return node


def correlate(detections: list[Detection], nodes: dict[str, ProcessNode],
              gap: timedelta = timedelta(minutes=60)) -> list[Incident]:
    by_host: dict[str, list[Detection]] = defaultdict(list)
    for d in detections:
        by_host[d.event.computer].append(d)

    incidents: list[Incident] = []
    for host, dets in by_host.items():
        current: list[Detection] = []
        for d in dets:
            if current and d.timestamp - current[-1].timestamp > gap:
                incidents.append(Incident(0, host, current))
                current = []
            current.append(d)
        if current:
            incidents.append(Incident(0, host, current))

    for inc in incidents:
        roots: dict[str, ProcessNode] = {}
        for d in inc.detections:
            guid = d.event.get("ProcessGuid") or d.event.get("SourceProcessGuid")
            node = nodes.get(guid)
            if node:
                if d.rule.id not in node.flagged:
                    node.flagged.append(d.rule.id)
                root = _root_of(node, nodes)
                roots[root.guid] = root
        inc.roots = sorted(roots.values(), key=lambda n: n.timestamp)

    incidents.sort(key=lambda i: i.start)
    for n, inc in enumerate(incidents, 1):
        inc.id = n
    return incidents


def analyze(events: list[Event]) -> Analysis:
    detections = detect(events)
    nodes = build_process_tree(events)
    return Analysis(events, detections, correlate(detections, nodes))
