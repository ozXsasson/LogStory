"""Self-contained HTML report, styled as an incident case file."""
from __future__ import annotations

import html
from datetime import datetime, timezone

from engine import Analysis, Detection, Incident, ProcessNode
from rules import TACTICS

e = html.escape

CSS = """
:root{
  --paper:#f6f3ec;--sheet:#fffdf8;--ink:#1c1b19;--soft:#5f5a51;--faint:#8d877b;
  --rule:#dcd5c6;--rule2:#ebe5d8;--tint:#f0ebe0;--link:#1d4f91;
  --critical:#b3261e;--high:#c25a0a;--medium:#9a7b06;--low:#4b7a57;
  --serif:"Iowan Old Style","Charter","Bitstream Charter",Georgia,"Times New Roman",serif;
  --sans:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  --mono:"JetBrains Mono","SF Mono",Menlo,Consolas,"DejaVu Sans Mono",monospace}
*{box-sizing:border-box}
html{background:var(--paper)}
body{margin:0;color:var(--ink);font:15px/1.6 var(--sans);-webkit-font-smoothing:antialiased}
a{color:var(--link)}
.sheet{max-width:980px;margin:28px auto 56px;background:var(--sheet);border:1px solid var(--rule);
  box-shadow:0 1px 0 var(--rule2),0 12px 40px -24px rgba(60,50,30,.35);padding:44px 56px 40px}
@media(max-width:760px){.sheet{margin:0;border:0;padding:24px 18px}}

/* masthead */
.mast{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;
  border-bottom:3px double var(--ink);padding-bottom:10px;font:600 11px/1.4 var(--sans);
  letter-spacing:.14em;text-transform:uppercase;color:var(--soft)}
.mast .brand{color:var(--ink)}
.stamp{border:2px solid var(--critical);color:var(--critical);padding:3px 9px;transform:rotate(-2deg);
  font:700 11px/1 var(--mono);letter-spacing:.08em}
h1{font:600 36px/1.15 var(--serif);margin:26px 0 8px;letter-spacing:-.01em}
.lede{font:italic 18px/1.5 var(--serif);color:var(--soft);margin:0 0 22px;max-width:46em}

/* figures */
.figures{display:flex;flex-wrap:wrap;border-top:1px solid var(--rule);border-bottom:1px solid var(--rule)}
.fig{flex:1 1 120px;padding:12px 16px 10px;border-right:1px solid var(--rule2)}
.fig:last-child{border-right:0}
.fig b{display:block;font:600 26px/1.1 var(--serif)}
.fig span{font:600 10.5px/1.3 var(--sans);letter-spacing:.12em;text-transform:uppercase;color:var(--faint)}
.fig.alert b{color:var(--critical)}

h2{font:600 13px/1 var(--sans);letter-spacing:.16em;text-transform:uppercase;color:var(--soft);
  margin:40px 0 14px;display:flex;align-items:center;gap:12px}
h2:after{content:"";flex:1;border-top:1px solid var(--rule)}

/* kill chain */
.chain{display:grid;grid-template-columns:repeat(12,1fr);gap:3px}
@media(max-width:760px){.chain{grid-template-columns:repeat(6,1fr);row-gap:14px}}
.tac .bar{height:10px;background:var(--rule2)}
.tac.hit .bar{background:var(--ink)}
.tac .n{font:600 13px/1 var(--mono);height:18px;color:var(--ink)}
.tac:not(.hit) .n{color:var(--rule)}
.tac .lbl{font:11px/1.25 var(--sans);color:var(--faint);margin-top:6px;hyphens:auto}
.tac.hit .lbl{color:var(--ink)}

/* incidents */
.incident{margin-top:30px;padding-top:6px}
.inc-head{display:flex;flex-wrap:wrap;align-items:baseline;gap:6px 14px}
.inc-head h3{font:600 23px/1.2 var(--serif);margin:0}
.host{font:13px var(--mono);color:var(--soft)}
.sevword{font:700 11px/1 var(--sans);letter-spacing:.14em;text-transform:uppercase}
.sevword.critical{color:var(--critical)}.sevword.high{color:var(--high)}
.sevword.medium{color:var(--medium)}.sevword.low{color:var(--low)}
.inc-sum{margin:8px 0 4px;color:var(--soft)}
.inc-meta{font:12px var(--mono);color:var(--faint);margin-bottom:18px}

.log{border-top:1px solid var(--ink)}
.entry{display:grid;grid-template-columns:118px 1fr;border-bottom:1px solid var(--rule2)}
.when{padding:12px 12px 12px 0;font:12.5px/1.45 var(--mono);color:var(--ink)}
.when small{display:block;color:var(--faint);font-size:11px}
.what{padding:11px 0 12px 16px;border-left:3px solid var(--sevc)}
.entry.critical{--sevc:var(--critical)}.entry.high{--sevc:var(--high)}
.entry.medium{--sevc:var(--medium)}.entry.low{--sevc:var(--low)}
.what h4{margin:0;font:600 15px/1.35 var(--sans)}
.what h4 .sevword{margin-left:8px;font-size:10px;color:var(--sevc)}
.what p{margin:3px 0 5px}
.what .ref{font:11.5px/1.4 var(--mono);color:var(--faint)}
.what .ref a{color:var(--soft);text-decoration:none;border-bottom:1px dotted var(--faint)}
.gap{grid-column:1/-1;font:italic 13px var(--serif);color:var(--faint);padding:8px 0 8px 134px;
  background:repeating-linear-gradient(90deg,transparent 0 6px,var(--tint) 6px 7px)}
code{font:12.5px/1.5 var(--mono);background:var(--tint);border:1px solid var(--rule2);padding:0 4px;
  word-break:break-all;border-radius:2px}
@media(max-width:760px){.entry{grid-template-columns:1fr}.when{padding-bottom:0}.gap{padding-left:0}}

/* process tree */
.tree{font:12.5px/1.7 var(--mono);background:var(--tint);border:1px solid var(--rule);padding:14px 18px;
  overflow-x:auto;white-space:pre}
.tree .br{color:var(--faint)}.tree .p{color:var(--ink)}
.tree .bad{color:var(--critical);font-weight:700}
.tree .ids{color:var(--critical);font-size:11px}
.tree .cmd{color:var(--faint)}

table{width:100%;border-collapse:collapse;font-size:13.5px}
th{font:600 10.5px var(--sans);letter-spacing:.12em;text-transform:uppercase;color:var(--faint);text-align:left;
  border-bottom:1px solid var(--ink);padding:6px 8px}
td{border-bottom:1px solid var(--rule2);padding:7px 8px}
td.m{font-family:var(--mono);font-size:12.5px}
td.n{text-align:right;font-family:var(--mono)}
.clean{font:italic 18px var(--serif);color:var(--low);padding:18px 0}
footer{margin-top:36px;padding-top:10px;border-top:1px solid var(--rule);font:11.5px var(--mono);
  color:var(--faint);display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px}
@media print{html{background:#fff}.sheet{box-shadow:none;border:0;margin:0}}
"""


def _fmt(ts: datetime, with_date: bool = True) -> str:
    fmt = "%Y-%m-%d %H:%M:%S UTC" if with_date else "%H:%M:%S"
    return ts.astimezone(timezone.utc).strftime(fmt)


def _delta(seconds: float) -> str:
    s = int(seconds)
    if s < 60:
        return f"+{s}s"
    if s < 3600:
        return f"+{s // 60}m {s % 60:02d}s"
    return f"+{s // 3600}h {(s % 3600) // 60:02d}m"


def _story_html(text: str) -> str:
    """Escape, then turn `backticks` into <code>."""
    parts = e(text).split("`")
    return "".join(f"<code>{p}</code>" if i % 2 else p for i, p in enumerate(parts))


def _on_attack_path(node: ProcessNode, depth: int = 0) -> bool:
    """True if this process or any descendant was flagged by a rule."""
    if node.flagged:
        return True
    return depth < 12 and any(_on_attack_path(c, depth + 1) for c in node.children)


def _tree_lines(node: ProcessNode, prefix: str = "", last: bool = True,
                root: bool = True, depth: int = 0) -> list[str]:
    """Draw the attack path as a classic ├─ / └─ tree, hiding benign branches."""
    if depth > 12 or not _on_attack_path(node):
        return []
    branch = "" if root else ("└─ " if last else "├─ ")
    name_cls = "bad" if node.flagged else "p"
    ids = f' <span class="ids">[{", ".join(node.flagged)}]</span>' if node.flagged else ""
    cmd = node.command_line if len(node.command_line) < 110 else node.command_line[:107] + "..."
    lines = [f'<span class="br">{e(prefix + branch)}</span><span class="{name_cls}">{e(node.name)}</span>'
             f'{ids}  <span class="cmd">{e(cmd)}</span>']
    kids = [c for c in sorted(node.children, key=lambda n: n.timestamp) if _on_attack_path(c)]
    child_prefix = prefix if root else prefix + ("   " if last else "│  ")
    for i, child in enumerate(kids):
        lines += _tree_lines(child, child_prefix, i == len(kids) - 1, False, depth + 1)
    return lines


def _entry(d: Detection, start: datetime) -> str:
    r = d.rule
    return f"""
    <div class="entry {d.severity}">
      <div class="when">{_fmt(d.timestamp, False)}<small>{_delta((d.timestamp - start).total_seconds())}</small></div>
      <div class="what">
        <h4>{e(r.title)}<span class="sevword">{d.severity}</span></h4>
        <p>{_story_html(d.story)}</p>
        <div class="ref"><a href="{r.technique_url}" target="_blank" rel="noopener">{r.technique}</a>
          {e(r.technique_name)} &middot; {e(r.tactic)} &middot; {r.id}</div>
      </div>
    </div>"""


def _incident(inc: Incident) -> str:
    rows, prev = [], None
    for d in inc.detections:
        if prev is not None:
            gap = (d.timestamp - prev).total_seconds()
            if gap >= 240:
                rows.append(f'<div class="gap">{int(gap // 60)} minutes pass&hellip;</div>')
        rows.append(_entry(d, inc.start))
        prev = d.timestamp
    tree = ""
    if inc.roots:
        lines = [ln for r in inc.roots for ln in _tree_lines(r)]
        tree = '<h2>Process tree &middot; attack path</h2><div class="tree">' + "\n".join(lines) + "</div>"
    users = ", ".join(inc.users) or "n/a"
    return f"""
  <section class="incident">
    <div class="inc-head"><h3>Incident {inc.id}</h3><span class="host">{e(inc.computer)}</span>
      <span class="sevword {inc.severity}">{inc.severity}</span></div>
    <p class="inc-sum">{e(inc.headline())}</p>
    <div class="inc-meta">{_fmt(inc.start)} &rarr; {_fmt(inc.end, False)} &middot; user: {e(users)}</div>
    <div class="log">{''.join(rows)}</div>
    {tree}
  </section>"""


def _title(analysis: Analysis) -> tuple[str, str]:
    if not analysis.incidents:
        return "Nothing suspicious found", "No detection rule fired on these logs."
    worst = max(analysis.incidents, key=lambda i: (
        ["low", "medium", "high", "critical"].index(i.severity), len(i.detections)))
    first, last = worst.detections[0], worst.detections[-1]
    host = worst.computer.split(".")[0]
    mins = max(1, int((worst.end - worst.start).total_seconds() // 60))
    return (f"What happened on {host}",
            f"The first sign shows up at {_fmt(first.timestamp, False)}: {first.rule.title.lower()}. "
            f"The last one, {mins} minutes later: {last.rule.title.lower()}. "
            f"Every step in between is below, in the order it happened.")


def render(analysis: Analysis, source: str = "") -> str:
    sev = analysis.severity_counts
    hits = analysis.tactic_hits
    chain = "".join(
        f'<div class="tac {"hit" if hits[t] else ""}"><div class="n">{hits[t] or "&middot;"}</div>'
        f'<div class="bar"></div><div class="lbl">{e(t)}</div></div>'
        for t in TACTICS)

    techniques: dict[str, tuple] = {}
    for d in analysis.detections:
        r = d.rule
        techniques[r.technique] = (r, techniques.get(r.technique, (r, 0))[1] + 1)
    rows = "".join(
        f'<tr><td class="m"><a href="{r.technique_url}" target="_blank" rel="noopener">{r.technique}</a></td>'
        f'<td>{e(r.technique_name)}</td><td>{e(r.tactic)}</td><td class="n">{n}</td></tr>'
        for r, n in sorted(techniques.values(), key=lambda x: TACTICS.index(x[0].tactic)))

    body = "".join(_incident(i) for i in analysis.incidents) or \
        '<p class="clean">The logs are quiet. Nothing matched any rule.</p>'
    span = ""
    if analysis.events:
        span = f"{_fmt(analysis.events[0].timestamp)} &rarr; {_fmt(analysis.events[-1].timestamp)}"
    title, lede = _title(analysis)
    tactics_hit = sum(1 for v in hits.values() if v)
    stamp = '<span class="stamp">TLP:AMBER</span>' if analysis.detections else ""

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LogStory: {e(title)}</title><style>{CSS}</style></head>
<body><article class="sheet">
<div class="mast"><div><span class="brand">LogStory</span> &middot; incident report<br>
  source: {e(source) or "windows logs"} &middot; {span}</div>{stamp}</div>
<h1>{e(title)}</h1>
<p class="lede">{e(lede)}</p>
<div class="figures">
  <div class="fig"><b>{len(analysis.events):,}</b><span>events read</span></div>
  <div class="fig"><b>{len(analysis.detections)}</b><span>detections</span></div>
  <div class="fig"><b>{len(analysis.incidents)}</b><span>incidents</span></div>
  <div class="fig alert"><b>{sev['critical']}</b><span>critical</span></div>
  <div class="fig"><b>{tactics_hit}<small style="font-size:15px;color:var(--faint)"> / {len(TACTICS)}</small></b><span>ATT&amp;CK tactics</span></div>
</div>
<h2>Kill chain</h2><div class="chain">{chain}</div>
<h2>Timeline</h2>{body}
<h2>Techniques seen</h2>
<table><thead><tr><th>ID</th><th>Technique</th><th>Tactic</th><th style="text-align:right">Hits</th></tr></thead>
<tbody>{rows}</tbody></table>
<footer><span>LogStory &middot; github.com/ozXsasson/LogStory</span><span>{_fmt(datetime.now(timezone.utc))}</span></footer>
</article></body></html>"""
