"""Turn a session's flows.jsonl into a terminal summary and a self-contained HTML report."""

from __future__ import annotations

import html
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

SEV_ORDER = {"high": 0, "medium": 1, "low": 2}


def load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    recs = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                recs.append(json.loads(line))
            except json.JSONDecodeError:
                pass  # a line cut short by a hard kill
    return sorted(recs, key=lambda r: r.get("ts") or 0)


def summarize(recs: list[dict]) -> dict:
    hosts: dict[str, dict] = {}
    flags: dict[tuple, dict] = {}
    for i, r in enumerate(recs):
        h = hosts.setdefault(r["host"], {"host": r["host"], "category": r["category"], "requests": 0,
                                         "bytes_up": 0, "bytes_down": 0, "high": 0, "medium": 0, "expected": 0})
        h["requests"] += 1
        h["bytes_up"] += r.get("req_bytes") or 0
        h["bytes_down"] += r.get("resp_bytes") or 0
        for f in r.get("findings", []):
            if f.get("expected"):
                h["expected"] += 1
            elif f["severity"] in ("high", "medium"):
                h[f["severity"]] += 1
            k = (f["category"], f["kind"], f["where"], f["sample"], r["host"], f.get("expected", False))
            agg = flags.setdefault(k, {**f, "host": r["host"], "count": 0, "first": i})
            agg["count"] += 1
    flag_list = sorted(flags.values(), key=lambda f: (f.get("expected", False), SEV_ORDER.get(f["severity"], 3),
                                                      f["category"] != "secret", f["host"], f["kind"]))
    host_list = sorted(hosts.values(), key=lambda h: (-(h["high"] * 100 + h["medium"]), -h["requests"]))
    return {
        "requests": len(recs),
        "hosts": host_list,
        "flags": flag_list,
        "bytes_up": sum(h["bytes_up"] for h in host_list),
        "high": sum(1 for f in flag_list if f["severity"] == "high" and not f.get("expected")),
        "medium": sum(1 for f in flag_list if f["severity"] == "medium" and not f.get("expected")),
        "expected": sum(1 for f in flag_list if f.get("expected")),
        "blocked": sum(1 for r in recs if r.get("method") == "CONNECT" and r.get("error")),
    }


def human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n} B"


# ---------------------------------------------------------------- terminal

def terminal_summary(recs: list[dict], report_path: Path | None = None, color: bool = True) -> str:
    s = summarize(recs)
    R, Y, D, B, X = ("\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m") if color else ("",) * 5
    lines = [f"{B}tattle{X}  {s['requests']} requests · {len(s['hosts'])} hosts · {human_bytes(s['bytes_up'])} sent"
             f" · {R}{s['high']} high{X} · {Y}{s['medium']} medium{X} · {D}{s['expected']} expected auth{X}"]
    for f in s["flags"]:
        if f.get("expected"):
            continue
        c = R if f["severity"] == "high" else Y
        lines.append(f"  {c}{f['severity']:<6}{X} {f['kind']:<26} {f['sample']:<26} {D}{f['where']} → {f['host']}"
                     f"{' ×' + str(f['count']) if f['count'] > 1 else ''}{X}")
    if s["blocked"]:
        lines.append(f"  {D}{s['blocked']} connection(s) refused interception (pinned or ignoring CA env vars){X}")
    if report_path:
        lines.append(f"  report: {report_path}")
    return "\n".join(lines)


def live_line(r: dict, color: bool = True) -> str:
    R, Y, D, X = ("\033[31m", "\033[33m", "\033[2m", "\033[0m") if color else ("",) * 4
    fs = [f for f in r.get("findings", []) if not f.get("expected")]
    mark = f"{R}●{X}" if any(f["severity"] == "high" for f in fs) else f"{Y}●{X}" if fs else f"{D}·{X}"
    tail = "  " + ", ".join(f"{f['kind']} in {f['where']}" for f in fs[:3]) if fs else ""
    path = r["path"] if len(r["path"]) < 60 else r["path"][:57] + "…"
    return f"{mark} {r['method']:<6} {r['host']}{D}{path}{X} {D}{human_bytes(r.get('req_bytes') or 0)}{X}{tail}"


# ---------------------------------------------------------------- html

CSS = r"""
:root{--paper:#f3efe6;--card:#fbf9f4;--ink:#1d1b17;--mute:#6f6a5f;--rule:#d9d2c3;--red:#c2361c;--redbg:#f6ddd5;
--amber:#a8670a;--amberbg:#f4e5c8;--ok:#3b6b4a;--chip:#ece6d8;--mono:ui-monospace,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace;
--sans:-apple-system,"Inter","Segoe UI",system-ui,sans-serif}
@media (prefers-color-scheme:dark){:root{--paper:#16150f;--card:#1e1c16;--ink:#ece6d6;--mute:#9a927f;--rule:#34302a;
--red:#ff6a4d;--redbg:#3a1c14;--amber:#e8a63c;--amberbg:#352712;--ok:#7fb48f;--chip:#2a2720}}
*{box-sizing:border-box}html{background:var(--paper)}
body{margin:0;color:var(--ink);font:14px/1.5 var(--sans);background:var(--paper)}
.wrap{max-width:1120px;margin:0 auto;padding:40px 24px 80px}
header{display:flex;justify-content:space-between;align-items:flex-end;gap:24px;border-bottom:2px solid var(--ink);padding-bottom:16px}
.brand{font:700 13px var(--mono);letter-spacing:.18em;text-transform:uppercase}
.brand b{display:inline-block;background:var(--ink);color:var(--paper);padding:2px 8px;margin-right:10px;letter-spacing:.12em}
h1{font:700 30px/1.15 var(--sans);letter-spacing:-.02em;margin:14px 0 0}
.meta{font:12px/1.7 var(--mono);color:var(--mute);text-align:right;white-space:nowrap}
.meta code{color:var(--ink)}
.stats{display:grid;grid-template-columns:repeat(5,1fr);border-bottom:1px solid var(--rule)}
.stat{padding:18px 0 16px;border-right:1px solid var(--rule);padding-left:16px}
.stat:first-child{padding-left:0}.stat:last-child{border-right:0}
.stat .n{font:600 28px/1 var(--mono);letter-spacing:-.03em}
.stat .l{font:11px var(--mono);text-transform:uppercase;letter-spacing:.12em;color:var(--mute);margin-top:6px}
.stat.hot .n{color:var(--red)}.stat.warm .n{color:var(--amber)}
h2{font:700 11px var(--mono);text-transform:uppercase;letter-spacing:.16em;margin:40px 0 12px;display:flex;gap:10px;align-items:baseline}
h2 span{color:var(--mute);font-weight:400}
.flags{border-top:1px solid var(--ink)}
.flag{display:grid;grid-template-columns:78px 1.1fr 1fr 1.4fr 48px;gap:16px;align-items:center;padding:11px 0;border-bottom:1px solid var(--rule)}
.flag.exp{opacity:.55}
.sev{font:700 10px var(--mono);text-transform:uppercase;letter-spacing:.12em;padding:3px 0;text-align:center;border:1.5px solid}
.sev.high{color:var(--red);background:var(--redbg)}.sev.medium{color:var(--amber);background:var(--amberbg)}
.sev.expected{color:var(--mute);background:transparent}
.kind{font-weight:600}.kind small{display:block;font:11px var(--mono);color:var(--mute);font-weight:400;text-transform:uppercase;letter-spacing:.08em}
.sample{font:13px var(--mono);background:var(--chip);padding:2px 7px;justify-self:start;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.route{font:12.5px var(--mono);color:var(--mute);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.route b{color:var(--ink);font-weight:600}
.count{font:12px var(--mono);color:var(--mute);text-align:right}
.empty{padding:28px 0;font:13px var(--mono);color:var(--ok);border-bottom:1px solid var(--rule)}
table{width:100%;border-collapse:collapse;font:12.5px var(--mono)}
th{text-align:left;font-weight:700;font-size:10.5px;text-transform:uppercase;letter-spacing:.12em;color:var(--mute);padding:8px 10px 8px 0;border-bottom:1px solid var(--ink)}
td{padding:8px 10px 8px 0;border-bottom:1px solid var(--rule);vertical-align:top}
td.num,th.num{text-align:right}
.cat{font-size:10.5px;text-transform:uppercase;letter-spacing:.08em;color:var(--mute)}
.bar{height:6px;background:var(--chip);min-width:80px}.bar i{display:block;height:100%;background:var(--ink)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;vertical-align:1px;background:var(--rule)}
.dot.high{background:var(--red)}.dot.medium{background:var(--amber)}
.tools{display:flex;gap:12px;align-items:center;margin-bottom:10px;flex-wrap:wrap}
.tools input[type=search]{font:13px var(--mono);padding:7px 10px;border:1px solid var(--rule);background:var(--card);color:var(--ink);min-width:260px;outline:none}
.tools input[type=search]:focus{border-color:var(--ink)}
.tools label{font:12px var(--mono);color:var(--mute);display:flex;gap:6px;align-items:center;cursor:pointer}
.req td.path{max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.req tr.f td.path{color:var(--ink)}
.req .m{font-weight:700}
.req tr.err td{color:var(--mute)}
.tags{color:var(--red);font-size:11.5px}
footer{margin-top:48px;font:11.5px var(--mono);color:var(--mute);border-top:1px solid var(--rule);padding-top:14px;display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap}
@media (max-width:760px){header{flex-direction:column;align-items:flex-start}.meta{text-align:left}
.stats{grid-template-columns:repeat(2,1fr)}.stat{padding-left:0;border-right:0}
.flag{grid-template-columns:70px 1fr;}.flag .route,.flag .sample{grid-column:2}.flag .count{display:none}
.req td.path{max-width:160px}}
"""

JS = r"""
const data = JSON.parse(document.getElementById('tattle-data').textContent);
const tbody = document.querySelector('#reqs tbody');
const q = document.getElementById('q'), onlyF = document.getElementById('onlyf');
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const kb = n => n < 1024 ? n + ' B' : n < 1048576 ? (n/1024).toFixed(1) + ' KB' : (n/1048576).toFixed(1) + ' MB';
function render(){
  const term = q.value.trim().toLowerCase();
  const rows = data.filter(r => {
    const fs = r.findings.filter(f => !f.expected);
    if (onlyF.checked && !fs.length) return false;
    if (!term) return true;
    return (r.host + r.path + r.method + fs.map(f => f.kind).join(' ')).toLowerCase().includes(term);
  });
  tbody.innerHTML = rows.slice(0, 2000).map(r => {
    const fs = r.findings.filter(f => !f.expected);
    const sev = fs.some(f => f.severity === 'high') ? 'high' : fs.length ? 'medium' : '';
    const t = new Date(r.ts * 1000).toLocaleTimeString([], {hour12:false});
    return `<tr class="${fs.length ? 'f' : ''} ${r.error ? 'err' : ''}"><td>${t}</td><td class="m">${esc(r.method)}</td>
      <td><span class="dot ${sev}"></span>${esc(r.host)}</td><td class="path" title="${esc(r.path)}">${esc(r.path || r.error)}</td>
      <td class="num">${kb(r.req_bytes)}</td><td class="num">${r.status ?? '—'}</td>
      <td class="tags">${esc([...new Set(fs.map(f => f.kind))].join(', '))}</td></tr>`;
  }).join('');
  document.getElementById('shown').textContent = rows.length + ' of ' + data.length;
}
q.addEventListener('input', render); onlyF.addEventListener('change', render); render();
"""


def render_html(recs: list[dict], meta: dict | None = None) -> str:
    meta = meta or {}
    s = summarize(recs)
    e = html.escape
    started = datetime.fromtimestamp(recs[0]["ts"]).strftime("%Y-%m-%d %H:%M") if recs else "—"
    duration = f"{recs[-1]['ts'] - recs[0]['ts']:.0f}s" if len(recs) > 1 else "—"

    def stat(n, label, cls=""):
        return f'<div class="stat {cls}"><div class="n">{n}</div><div class="l">{label}</div></div>'

    stats = (stat(s["requests"], "requests") + stat(len(s["hosts"]), "destinations") + stat(human_bytes(s["bytes_up"]), "sent")
             + stat(s["high"], "high flags", "hot" if s["high"] else "") + stat(s["medium"], "medium flags", "warm" if s["medium"] else ""))

    flag_rows = []
    for f in s["flags"]:
        sev = "expected" if f.get("expected") else f["severity"]
        cat = "auth header" if f.get("expected") else f["category"]
        flag_rows.append(
            f'<div class="flag {"exp" if f.get("expected") else ""}"><div class="sev {sev}">{e(sev)}</div>'
            f'<div class="kind">{e(f["kind"])}<small>{e(cat)}</small></div>'
            f'<div class="sample" title="{e(f["sample"])}">{e(f["sample"])}</div>'
            f'<div class="route">{e(f["where"])} → <b>{e(f["host"])}</b></div>'
            f'<div class="count">{"×" + str(f["count"]) if f["count"] > 1 else ""}</div></div>')
    flags_html = "".join(flag_rows) or '<div class="empty">Nothing secret-like or personal left this machine.</div>'

    max_up = max((h["bytes_up"] for h in s["hosts"]), default=1) or 1
    host_rows = "".join(
        f'<tr><td><span class="dot {"high" if h["high"] else "medium" if h["medium"] else ""}"></span>{e(h["host"])}</td>'
        f'<td class="cat">{e(h["category"])}</td><td class="num">{h["requests"]}</td>'
        f'<td class="num">{human_bytes(h["bytes_up"])}</td><td><div class="bar"><i style="width:{100 * h["bytes_up"] / max_up:.1f}%"></i></div></td>'
        f'<td class="num">{human_bytes(h["bytes_down"])}</td><td class="num">{h["high"] + h["medium"] or ""}</td></tr>'
        for h in s["hosts"])

    data_json = json.dumps(recs).replace("</", "<\\/")
    command = meta.get("command", "")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>tattle report · {e(started)}</title>
<style>{CSS}</style></head><body><div class="wrap">
<header><div><div class="brand"><b>tattle</b>egress report</div><h1>What left this machine</h1></div>
<div class="meta">started <code>{e(started)}</code> · ran <code>{e(duration)}</code><br>{('command <code>' + e(command) + '</code>') if command else ''}</div></header>
<section class="stats">{stats}</section>
<h2>Flags <span>{len(s["flags"])} distinct · values masked</span></h2><div class="flags">{flags_html}</div>
<h2>Destinations <span>{len(s["hosts"])} hosts</span></h2>
<table><thead><tr><th>host</th><th>kind</th><th class="num">reqs</th><th class="num">sent</th><th></th><th class="num">received</th><th class="num">flags</th></tr></thead>
<tbody>{host_rows}</tbody></table>
<h2>Requests <span id="shown"></span></h2>
<div class="tools"><input id="q" type="search" placeholder="filter host, path, flag…"><label><input id="onlyf" type="checkbox"> flagged only</label></div>
<table id="reqs" class="req"><thead><tr><th>time</th><th>method</th><th>host</th><th>path</th><th class="num">sent</th><th class="num">status</th><th>flags</th></tr></thead><tbody></tbody></table>
<footer><span>generated by tattle · secrets and personal values are masked before they are written to disk</span><span>{e(meta.get("session", ""))}</span></footer>
</div><script type="application/json" id="tattle-data">{data_json}</script><script>{JS}</script></body></html>"""


def write_report(jsonl: Path, out: Path, meta: dict | None = None) -> Path:
    out.write_text(render_html(load(jsonl), meta))
    return out
