"""Turn a session's flows.jsonl into a terminal summary and a self-contained HTML report."""

from __future__ import annotations

import copy
import html
import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from tattle.detect import host_category

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


UUIDISH = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[A-Za-z0-9_]*[0-9][A-Za-z0-9_]{15,}")


def share_safe(recs: list[dict]) -> list[dict]:
    """Stronger masking for a report you intend to show other people:
    drop the leading characters the default mask keeps, and blank account and
    object IDs in paths."""
    out = copy.deepcopy(recs)
    for r in out:
        r["path"] = UUIDISH.sub("{id}", r.get("path", ""))
        for f in r.get("findings", []):
            f["sample"] = re.sub(r"[A-Za-z0-9]•••", "•••", f["sample"])
            f["sample"] = re.sub(r"^.{4}…", "••••…", f["sample"]) if f["category"] == "secret" else f["sample"]
    return out


def summarize(recs: list[dict]) -> dict:
    hosts: dict[str, dict] = {}
    flags: dict[tuple, dict] = {}
    for i, r in enumerate(recs):
        # Re-derive so old sessions pick up an improved host table.
        h = hosts.setdefault(r["host"], {"host": r["host"], "category": host_category(r["host"]), "requests": 0,
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
header{display:flex;flex-direction:column;gap:10px;border-bottom:2px solid var(--ink);padding-bottom:16px}
.brand{font:700 13px var(--mono);letter-spacing:.18em;text-transform:uppercase}
.brand b{display:inline-block;background:var(--ink);color:var(--paper);padding:2px 8px;margin-right:10px;letter-spacing:.12em}
h1{font:700 30px/1.15 var(--sans);letter-spacing:-.02em;margin:14px 0 0}
.meta{font:12px/1.7 var(--mono);color:var(--mute);overflow-wrap:anywhere}
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
@media (max-width:760px){.stats{grid-template-columns:repeat(2,1fr)}.stat{padding-left:0;border-right:0}
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


def render_html(recs: list[dict], meta: dict | None = None, share: bool = False) -> str:
    meta = meta or {}
    if share:
        recs = share_safe(recs)
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


def write_report(jsonl: Path, out: Path, meta: dict | None = None, share: bool = False) -> Path:
    out.write_text(render_html(load(jsonl), meta, share))
    return out


# ---------------------------------------------------------------- retro (past sessions)

RETRO_CSS = r"""
.note{margin:28px 0 0;padding:14px 16px;border:1px solid var(--rule);font-size:13.5px;color:var(--mute);max-width:820px}
.note b{color:var(--ink)}
.channel{margin-top:44px}
.channel>h2{font:800 22px/1.2 var(--sans);text-transform:none;letter-spacing:-.01em;margin:0 0 4px;display:block}
.channel>p{margin:0 0 14px;color:var(--mute);font-size:13.5px;max-width:760px}
.flag.retro{grid-template-columns:78px 1.1fr .9fr 1.5fr 60px}
.flag .route small{display:block;font-size:11.5px;white-space:normal}
.ph summary{cursor:pointer;font:12px var(--mono);color:var(--mute);padding:12px 0}
.rotate{margin-top:18px;border:1.5px solid var(--red);padding:14px 18px}
.rotate h3{margin:0 0 6px;font:700 11px var(--mono);text-transform:uppercase;letter-spacing:.14em;color:var(--red)}
.rotate li{font:12.5px var(--mono);margin:3px 0}
.rotate ul{margin:0;padding-left:18px}
.split{display:grid;grid-template-columns:repeat(4,1fr)}
.note.info{margin:0 0 14px;max-width:none}
"""


def _share_host(host: str, seen: dict) -> str:
    if re.fullmatch(r"[\d.:]+", host) or ("." not in host and " " not in host):
        return seen.setdefault(host, f"private host {len(seen) + 1}")
    return host


def _share_session(label: str, seen: dict) -> str:
    parts = label.split(" · ")
    if len(parts) == 3:
        parts[1] = seen.setdefault(parts[1], f"project {len(seen) + 1}")
    return " · ".join(parts)


def render_retro(d: dict, share: bool = False) -> str:
    e = html.escape
    d = copy.deepcopy(d)
    if share:
        hosts: dict = {}
        projs: dict = {}
        for g in d["groups"]:
            g["sample"] = re.sub(r"[A-Za-z0-9]•••", "•••", g["sample"])
            g["sample"] = re.sub(r"^.{4}…", "••••…", g["sample"]) if g["category"] == "secret" else g["sample"]
            g["host"] = _share_host(g["host"], hosts) if g["host"] else ""
            g["sessions"] = [_share_session(s, projs) for s in g["sessions"]]
        for c in d["calls"]:
            c["host"] = _share_host(c["host"], hosts)

    groups = [g for g in d["groups"] if not g["placeholder"]]
    ph = [g for g in d["groups"] if g["placeholder"]]

    def sev_count(ch, sev):
        return sum(1 for g in groups if g["channel"] == ch and g["severity"] == sev)

    def day(ts):
        return ts[:10] if ts else "—"

    def stat(n, label, cls=""):
        return f'<div class="stat {cls}"><div class="n">{n}</div><div class="l">{label}</div></div>'

    hi = sev_count("provider", "high") + sev_count("tools", "high")
    med = sev_count("provider", "medium") + sev_count("tools", "medium")
    stats = (stat(f'{d["sessions"]:,}', "sessions") + stat(f'{d["bytes"] / 1e9:.1f} GB' if d["bytes"] > 1e9 else human_bytes(d["bytes"]), "transcripts read")
             + stat(len({c["host"] for c in d["calls"]}), "hosts contacted by tools")
             + stat(hi, "high flags", "hot" if hi else "") + stat(med, "medium flags", "warm" if med else ""))

    def rows(items):
        out = []
        for g in items:
            sev = "expected" if g["placeholder"] else g["severity"]
            places = ", ".join(f"{k}" + (f" ×{v}" if v > 1 else "") for k, v in sorted(g["places"].items(), key=lambda kv: -kv[1])[:3])
            sess = g["sessions"][0] if g["sessions"] else ""
            more = f' +{len(g["sessions"]) - 1} more' if len(g["sessions"]) > 1 else ""
            dest = f' → <b>{e(g["host"])}</b>' if g["host"] else ""
            out.append(
                f'<div class="flag retro"><div class="sev {sev}">{e("placeholder" if g["placeholder"] else sev)}</div>'
                f'<div class="kind">{e(g["kind"])}<small>{e(g["category"])}</small></div>'
                f'<div class="sample" title="{e(g["sample"])}">{e(g["sample"])}</div>'
                f'<div class="route">{e(places)}{dest}<small>{e(sess)}{e(more)} · last {e(day(g["last"]))}</small></div>'
                f'<div class="count">×{g["count"]:,}</div></div>')
        return "".join(out) or '<div class="empty">Nothing flagged.</div>'

    prov = [g for g in groups if g["channel"] == "provider"]
    tools = [g for g in groups if g["channel"] == "tools"]
    rot, seen_rot = [], set()
    for g in groups:
        if g["category"] == "secret" and g["severity"] == "high" and (g["kind"], g["sample"]) not in seen_rot:
            seen_rot.add((g["kind"], g["sample"]))
            rot.append(g)
    rotate = ""
    if rot:
        items = "".join(f'<li>{e(g["kind"])} <span style="color:var(--mute)">{e(g["sample"])}</span> · {e(g["sessions"][0] if g["sessions"] else "")}'
                        f'{" · seen in " + str(len(g["sessions"])) + " sessions" if len(g["sessions"]) > 1 else ""}</li>' for g in rot[:40])
        rotate = f'<div class="rotate"><h3>Rotate these · {len(rot)} live-looking secrets</h3><ul>{items}</ul></div>'

    calls = d["calls"]
    max_c = max((c["count"] for c in calls), default=1)
    flagged_hosts = {}
    for g in tools:
        flagged_hosts[g["host"]] = flagged_hosts.get(g["host"], 0) + 1
    call_rows = "".join(
        f'<tr><td><span class="dot {"high" if flagged_hosts.get(c["host"]) else ""}"></span>{e(c["host"])}</td><td class="cat">{e(c["via"])}</td>'
        f'<td class="cat">{e(c["category"])}</td><td class="num">{c["count"]:,}</td><td><div class="bar"><i style="width:{100 * c["count"] / max_c:.1f}%"></i></div></td>'
        f'<td class="num">{c["sessions"]:,}</td><td class="num">{flagged_hosts.get(c["host"], "") or ""}</td></tr>'
        for c in calls[:60])
    agents = " · ".join(f"{k} {v:,}" for k, v in d["agents"].items())
    ph_html = (f'<details class="ph"><summary>{len(ph)} more look like placeholders or test values (EXAMPLE, fake, low entropy). Show them.</summary>'
               f'<div class="flags">{rows(ph[:200])}</div></details>') if ph else ""

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>tattle retro · {e(day(d["first"]))} to {e(day(d["last"]))}</title>
<style>{CSS}{RETRO_CSS}</style></head><body><div class="wrap">
<header><div><div class="brand"><b>tattle</b>retro audit</div><h1>What already left this machine</h1></div>
<div class="meta">{e(day(d["first"]))} → {e(day(d["last"]))} · {e(agents)} transcripts · scanned in <code>{d["elapsed"]}s</code></div></header>
<section class="stats">{stats}</section>
<div class="note"><b>Reconstructed from transcripts.</b> This shows what the agents' conversations contained and what their tools were asked to send.
It cannot see traffic the agent runtime sent on its own, such as telemetry, update checks and feature flags. For that, run the agent through <code>tattle run</code>.</div>

{rotate}
<div class="channel"><h2>Sent to the model provider</h2>
<p>Everything in a transcript went to Anthropic or OpenAI as part of the prompt: your messages, files the agent read, command output.</p>
{identity_line(d)}
<div class="flags">{rows(prov[:300])}</div></div>

<div class="channel"><h2>Sent to third parties by tools</h2>
<p>Network calls the agent's tools made, rebuilt from WebFetch, WebSearch, MCP calls and shell commands (curl, wget, gh api, git push, ssh, scp, rsync).</p>
<div class="flags">{rows(tools[:300])}</div>
<h2>Destinations <span>{len(calls)} host and tool pairs</span></h2>
<table><thead><tr><th>host</th><th>via</th><th>kind</th><th class="num">calls</th><th></th><th class="num">sessions</th><th class="num">flags</th></tr></thead><tbody>{call_rows}</tbody></table></div>
{ph_html}
<footer><span>generated by tattle retro · values masked before display{" · share mode" if share else ""}</span><span>{d["files"]:,} files · {d["lines"]:,} lines</span></footer>
</div></body></html>"""


def identity_text(d: dict) -> str:
    idn = d.get("identity") or {}
    if not idn.get("count"):
        return ""
    kinds = ", ".join(k.replace("your ", "") for k in idn["kinds"])
    return (f"Your identity ({kinds}) appears {idn['count']:,} times across {idn['sessions']:,}+ sessions sent to the "
            f"provider, as expected: it is in every system prompt and working directory.")


def identity_line(d: dict) -> str:
    t = identity_text(d)
    return f'<div class="note info"><b>Expected.</b> {html.escape(t)}</div>' if t else ""


def retro_terminal(d: dict, out: Path | None, color: bool = True) -> str:
    R, Y, D, B, X = ("\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m") if color else ("",) * 5
    groups = [g for g in d["groups"] if not g["placeholder"]]
    lines = [f'{B}tattle retro{X}  {d["sessions"]:,} sessions · {d["first"][:10]} → {d["last"][:10]} · '
             f'{d["bytes"] / 1e6:,.0f} MB in {d["elapsed"]}s']
    for ch, title in (("provider", "sent to the model provider"), ("tools", "sent to third parties by tools")):
        gs = [g for g in groups if g["channel"] == ch]
        hi = sum(1 for g in gs if g["severity"] == "high")
        lines.append(f"\n{B}{title}{X}  {R}{hi} high{X} · {Y}{len(gs) - hi} other{X}")
        if ch == "provider" and identity_text(d):
            idn = d["identity"]
            lines.append(f"  {D}info   your identity appears in prompts ×{idn['count']:,}, as expected{X}")
        for g in gs[:8]:
            c = R if g["severity"] == "high" else Y
            dest = f" → {g['host']}" if g["host"] else ""
            lines.append(f"  {c}{g['severity']:<6}{X} {g['kind']:<26} {g['sample']:<24} {D}×{g['count']}{dest}{X}")
        if len(gs) > 8:
            lines.append(f"  {D}… {len(gs) - 8} more in the report{X}")
    top = ", ".join(f"{c['host']} ({c['count']})" for c in d["calls"][:6])
    if top:
        lines.append(f"\n{B}top hosts{X}  {top}")
    ph = len(d["groups"]) - len(groups)
    if ph:
        lines.append(f"{D}{ph} placeholder-looking values not counted above{X}")
    lines.append(f"{D}reconstructed from transcripts: runtime telemetry is not visible here; use `tattle run` for that{X}")
    if out:
        lines.append(f"report: {out}")
    return "\n".join(lines)
