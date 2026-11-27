"""Self-contained HTML report: kill chain, story timeline, process tree."""
from __future__ import annotations

import html
from datetime import datetime, timezone

from engine import Analysis, Incident, ProcessNode
from rules import TACTICS

e = html.escape

CSS = """
:root{--bg:#0b0f17;--panel:#121826;--panel2:#182033;--line:#243049;--text:#e6ebf5;--muted:#8a96ad;
--accent:#5ac8fa;--low:#64d2a0;--medium:#ffd166;--high:#ff8c42;--critical:#ff4d6d}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:32px 20px 64px}
header h1{margin:0;font-size:30px;letter-spacing:-.5px}header h1 span{color:var(--accent)}
header p{color:var(--muted);margin:4px 0 24px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:28px}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.stat b{display:block;font-size:26px}.stat small{color:var(--muted);text-transform:uppercase;font-size:11px;letter-spacing:.8px}
h2{font-size:18px;margin:36px 0 12px}
.chain{display:grid;grid-template-columns:repeat(6,1fr);gap:6px}
@media(max-width:700px){.chain{grid-template-columns:repeat(3,1fr)}}
.tac{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px 8px;font-size:12px;
color:var(--muted);text-align:center;min-height:62px;display:flex;flex-direction:column;justify-content:center}
.tac.hit{background:linear-gradient(160deg,#3a1220,#251424);border-color:var(--critical);color:var(--text)}
.tac.hit b{color:var(--critical);font-size:18px}
.incident{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:20px 22px;margin-top:18px}
.incident h3{margin:0 0 4px;font-size:17px}.headline{color:var(--muted);margin:0 0 18px}
.sev{display:inline-block;padding:2px 9px;border-radius:99px;font-size:11px;font-weight:700;text-transform:uppercase;
letter-spacing:.6px;color:#0b0f17}
.sev.low{background:var(--low)}.sev.medium{background:var(--medium)}.sev.high{background:var(--high)}.sev.critical{background:var(--critical)}
.timeline{position:relative;margin-left:8px;padding-left:26px;border-left:2px solid var(--line)}
.step{position:relative;margin:0 0 18px}
.step:before{content:"";position:absolute;left:-33px;top:6px;width:12px;height:12px;border-radius:50%;
background:var(--bg);border:3px solid var(--sevc)}
.step.low{--sevc:var(--low)}.step.medium{--sevc:var(--medium)}.step.high{--sevc:var(--high)}.step.critical{--sevc:var(--critical)}
.meta{font-size:12px;color:var(--muted);display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.meta time{font-family:ui-monospace,Menlo,Consolas,monospace;color:var(--text)}
.chip{background:var(--panel2);border:1px solid var(--line);border-radius:6px;padding:1px 7px}
.chip a{color:var(--accent);text-decoration:none}
.story{margin:4px 0 0}.story code,code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;
background:#0a0e16;border:1px solid var(--line);border-radius:5px;padding:1px 5px;word-break:break-all}
.tree{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;background:#0a0e16;border:1px solid var(--line);
border-radius:10px;padding:14px 16px;overflow-x:auto}
.tree ul{list-style:none;margin:0;padding-left:20px;border-left:1px dashed var(--line)}.tree>ul{border:0;padding:0}
.tree li{margin:5px 0;white-space:nowrap}.tree .bad{color:var(--critical);font-weight:700}
.tree .cmd{color:var(--muted);font-size:12px}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.6px}
td a{color:var(--accent)}footer{margin-top:40px;color:var(--muted);font-size:12px;text-align:center}
.clean{background:var(--panel);border:1px solid var(--low);border-radius:12px;padding:20px;color:var(--low)}
"""


def _fmt(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _story_html(text: str) -> str:
    """Escape, then turn `backticks` into <code>."""
    parts = e(text).split("`")
    return "".join(f"<code>{p}</code>" if i % 2 else p for i, p in enumerate(parts))


def _on_attack_path(node: ProcessNode, depth: int = 0) -> bool:
    """True if this process or any descendant was flagged by a rule."""
    if node.flagged:
        return True
    return depth < 12 and any(_on_attack_path(c, depth + 1) for c in node.children)


def _tree(node: ProcessNode, depth: int = 0) -> str:
    """Render only the branches that lead to flagged processes (hides benign noise)."""
    if depth > 12 or not _on_attack_path(node):
        return ""
    cls = "bad" if node.flagged else ""
    flags = f' <span class="sev critical">{", ".join(node.flagged)}</span>' if node.flagged else ""
    cmd = node.command_line if len(node.command_line) < 140 else node.command_line[:137] + "..."
    kids = "".join(_tree(c, depth + 1) for c in sorted(node.children, key=lambda n: n.timestamp))
    return (f'<li><span class="{cls}">{e(node.name)}</span>{flags} '
            f'<span class="cmd">{e(cmd)}</span>{"<ul>" + kids + "</ul>" if kids else ""}</li>')


def _incident(inc: Incident) -> str:
    steps = []
    for d in inc.detections:
        r = d.rule
        steps.append(f"""
      <div class="step {d.severity}">
        <div class="meta"><time>{_fmt(d.timestamp)}</time>
          <span class="sev {d.severity}">{d.severity}</span>
          <span class="chip">{e(r.tactic)}</span>
          <span class="chip"><a href="{r.technique_url}" target="_blank" rel="noopener">{r.technique} {e(r.technique_name)}</a></span>
          <span class="chip">{r.id}</span></div>
        <p class="story"><b>{e(r.title)}.</b> {_story_html(d.story)}</p>
      </div>""")
    tree = ""
    if inc.roots:
        tree = ('<h2>Process tree (attack path)</h2><div class="tree"><ul>'
                + "".join(_tree(r) for r in inc.roots) + "</ul></div>")
    users = ", ".join(inc.users) or "n/a"
    return f"""
  <section class="incident">
    <h3>Incident #{inc.id} &middot; {e(inc.computer)} <span class="sev {inc.severity}">{inc.severity}</span></h3>
    <p class="headline">{e(inc.headline())}<br>Users: {e(users)} &middot; {_fmt(inc.start)} to {_fmt(inc.end)}</p>
    <div class="timeline">{''.join(steps)}</div>
    {tree}
  </section>"""


def render(analysis: Analysis, source: str = "") -> str:
    sev = analysis.severity_counts
    hits = analysis.tactic_hits
    chain = "".join(
        f'<div class="tac {"hit" if hits[t] else ""}"><b>{hits[t] or "&middot;"}</b>{e(t)}</div>'
        for t in TACTICS)
    techniques: dict[str, tuple] = {}
    for d in analysis.detections:
        r = d.rule
        cnt = techniques.get(r.technique, (r, 0))[1]
        techniques[r.technique] = (r, cnt + 1)
    rows = "".join(
        f'<tr><td><a href="{r.technique_url}" target="_blank" rel="noopener">{r.technique}</a></td>'
        f"<td>{e(r.technique_name)}</td><td>{e(r.tactic)}</td><td>{n}</td></tr>"
        for r, n in sorted(techniques.values(), key=lambda x: TACTICS.index(x[0].tactic)))
    body = "".join(_incident(i) for i in analysis.incidents) or \
        '<div class="clean">No suspicious activity found. The story is a quiet one.</div>'
    span = ""
    if analysis.events:
        span = f"{_fmt(analysis.events[0].timestamp)} to {_fmt(analysis.events[-1].timestamp)}"

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LogStory Report</title><style>{CSS}</style></head>
<body><div class="wrap">
<header><h1>Log<span>Story</span></h1>
<p>Attack timeline reconstructed from {e(source) or "Windows logs"} &middot; {span}</p></header>
<div class="stats">
  <div class="stat"><small>Events analyzed</small><b>{len(analysis.events):,}</b></div>
  <div class="stat"><small>Detections</small><b>{len(analysis.detections)}</b></div>
  <div class="stat"><small>Incidents</small><b>{len(analysis.incidents)}</b></div>
  <div class="stat"><small>Critical / High</small><b style="color:var(--critical)">{sev['critical']} / {sev['high']}</b></div>
  <div class="stat"><small>Tactics hit</small><b>{sum(1 for v in hits.values() if v)} / {len(TACTICS)}</b></div>
</div>
<h2>Kill chain (MITRE ATT&amp;CK)</h2><div class="chain">{chain}</div>
<h2>The story</h2>{body}
<h2>Techniques observed</h2>
<table><thead><tr><th>ID</th><th>Technique</th><th>Tactic</th><th>Hits</th></tr></thead><tbody>{rows}</tbody></table>
<footer>Generated by LogStory &middot; {_fmt(datetime.now(timezone.utc))}</footer>
</div></body></html>"""
