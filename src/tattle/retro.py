"""Retro audit: what already left this machine, reconstructed from agent transcripts.

Two channels, kept apart:
  provider  - everything in a transcript was sent to the model provider
  tools     - outbound calls the agent's tools made (WebFetch, curl, git push, ssh...)

Transcripts are streamed one line at a time; nothing holds a whole file. Only
masked samples and in-memory hashes of matched values are kept.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from tattle.detect import Finding, Identity, host_category, scan, scrub

MAX_TEXT = 2 * 1024 * 1024  # scan at most this much of any single text block
MAX_GROUPS = 20000  # cap on distinct findings kept, so memory stays flat

SEV_RANK = {"high": 0, "medium": 1, "low": 2}


# ------------------------------------------------------------------ sources

@dataclass
class Source:
    agent: str  # "Claude Code" | "Codex"
    path: Path
    kind: str  # "claude" | "codex" | "codex-history"


def discover(home: Path | None = None, since: float | None = None) -> list[Source]:
    home = home or Path.home()
    out: list[Source] = []
    roots = [
        ("Claude Code", "claude", home / ".claude" / "projects", "**/*.jsonl"),
        ("Codex", "codex", home / ".codex" / "sessions", "**/*.jsonl"),
        ("Codex", "codex", home / ".codex" / "archived_sessions", "**/*.jsonl"),
    ]
    for agent, kind, root, pattern in roots:
        if root.is_dir():
            for p in root.glob(pattern):
                out.append(Source(agent, p, kind))
    hist = home / ".codex" / "history.jsonl"
    if hist.is_file():
        out.append(Source("Codex", hist, "codex-history"))
    if since:
        out = [s for s in out if _mtime(s.path) >= since]
    return sorted(out, key=lambda s: _mtime(s.path))


def _mtime(p: Path) -> float:
    try:
        return p.stat().st_mtime
    except OSError:
        return 0.0


# ------------------------------------------------------------------ results

@dataclass
class Group:
    """One distinct value seen somewhere, with where and how often."""

    channel: str
    category: str
    kind: str
    sample: str
    severity: str
    placeholder: bool
    host: str = ""
    count: int = 0
    places: dict = field(default_factory=dict)  # location -> count
    sessions: dict = field(default_factory=dict)  # session label -> last ts (capped)
    first: str = ""
    last: str = ""

    def add(self, where: str, session: str, ts: str) -> None:
        self.count += 1
        self.places[where] = self.places.get(where, 0) + 1
        if session in self.sessions or len(self.sessions) < 12:
            self.sessions[session] = ts
        if ts:
            self.first = min(self.first or ts, ts)
            self.last = max(self.last, ts)


@dataclass
class Call:
    host: str
    via: str
    count: int = 0
    category: str = "web"
    sessions: set = field(default_factory=set)


class Results:
    def __init__(self) -> None:
        self.groups: dict[tuple, Group] = {}
        self.calls: dict[tuple, Call] = {}
        self.sessions: dict[str, dict] = {}
        self.files = 0
        self.bytes = 0
        self.lines = 0
        self.bad_lines = 0
        self.first_ts = ""
        self.last_ts = ""
        self.dropped = 0
        self.agents: dict[str, int] = {}

    def finding(self, channel: str, f: Finding, where: str, session: str, ts: str, host: str = "") -> None:
        key = (channel, f.category, f.kind, f.fp or f.sample, host)
        g = self.groups.get(key)
        if g is None:
            if len(self.groups) >= MAX_GROUPS:
                self.dropped += 1
                return
            g = self.groups[key] = Group(channel, f.category, f.kind, f.sample, f.severity, f.placeholder, host)
        g.add(where, session, ts)
        if f.severity == "high" and not f.placeholder and g.severity != "high":
            g.severity = "high"

    def call(self, host: str, via: str, session: str) -> None:
        c = self.calls.get((host, via))
        if c is None:
            c = self.calls[(host, via)] = Call(host, via, category=host_category(host) if "." in host else "remote host")
        c.count += 1
        if len(c.sessions) < 2000:
            c.sessions.add(session)

    def seen_ts(self, ts: str) -> None:
        if ts:
            self.first_ts = min(self.first_ts or ts, ts)
            self.last_ts = max(self.last_ts, ts)


# ------------------------------------------------------------------ command parsing (tools channel)

NET_CMD = re.compile(r"(?<![\w./-])(curl|wget|https?|xh|gh\s+api|git\s+(?:push|clone|fetch|pull|ls-remote)|ssh|scp|rsync|sftp|mosh|nc|ncat|aws\s+s3)(?![\w-])")
URL = re.compile(r"https?://[^\s'\"<>`)\]}\\]+")
LOCAL_HOST = re.compile(r"^(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|::1|\[::1\]|[\w-]+\.local(?:host)?)$", re.I)
SCP_TARGET = re.compile(r"^(?:[\w.-]+@)?([\w.-]+):")


def _split(segment: str) -> list[str]:
    try:
        return shlex.split(segment, posix=True)
    except ValueError:
        return segment.split()


def _segments(cmd: str):
    """Yield (tool, argv) for each network command inside a shell string."""
    for m in NET_CMD.finditer(cmd):
        rest = cmd[m.start():]
        # Cut at the end of this simple command.
        end = re.search(r"\n(?<!\\\n)|;|&&|\|\||(?<![|])\|(?![|])", rest)
        seg = rest[: end.start()] if end else rest
        seg = seg.replace("\\\n", " ")
        argv = _split(seg[:4000])
        if argv:
            yield " ".join(m.group(1).split()), argv


def parse_command(cmd: str) -> list[dict]:
    """Outbound calls visible in a shell command: host, via, plus the parts worth scanning."""
    calls = []
    for tool, argv in _segments(cmd):
        call = {"via": tool, "host": "", "parts": []}  # parts: (where, text)
        if tool in ("curl", "wget", "http", "https", "xh"):
            i = 1
            while i < len(argv):
                a = argv[i]
                nxt = argv[i + 1] if i + 1 < len(argv) else ""
                if a in ("-H", "--header") and nxt:
                    name, _, val = nxt.partition(":")
                    call["parts"].append((f"header:{name.strip().lower()}", val.strip()))
                    i += 2
                    continue
                if a in ("-A", "--user-agent", "-U") and nxt:
                    call["parts"].append(("header:user-agent", nxt)); i += 2; continue
                if a in ("-u", "--user") and nxt:
                    call["parts"].append(("header:authorization", nxt))
                    if ":" in nxt:
                        call["basic_auth"] = nxt
                    i += 2
                    continue
                if a in ("-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--json", "-F", "--form",
                         "--post-data", "--body-data") and nxt:
                    call["parts"].append(("body", nxt)); i += 2; continue
                if a.startswith(("--header=", "--user-agent=", "--post-data=")):
                    k, _, v = a.partition("=")
                    call["parts"].append(("header:user-agent" if "agent" in k else "body" if "data" in k else "header", v))
                elif tool in ("http", "https", "xh") and not a.startswith("-") and not URL.match(a):
                    # httpie items: Header:value, field=value, field:=json
                    if re.match(r"^[\w-]+:(?!=)", a) and "://" not in a:
                        n, _, v = a.partition(":")
                        call["parts"].append((f"header:{n.lower()}", v))
                    elif "=" in a:
                        call["parts"].append(("body", a))
                i += 1
            for u in URL.findall(" ".join(argv)):
                calls.append(_url_call(dict(call, parts=list(call["parts"])), u))
            continue
        if tool == "gh api":
            endpoint = next((a for a in argv[2:] if not a.startswith("-")), "")
            call["host"] = "api.github.com"
            call["parts"] += [("path", endpoint)] + [("body", argv[i + 1]) for i, a in enumerate(argv[:-1]) if a in ("-f", "-F", "--field", "--raw-field")]
        elif tool.startswith("git "):
            remote = next((a for a in argv[2:] if not a.startswith("-")), "origin")
            if "://" in remote or SCP_TARGET.match(remote):
                call.update(_remote_host(remote))
            else:
                call["host"] = f"git remote '{remote}'"
        elif tool in ("ssh", "mosh", "sftp", "nc", "ncat"):
            opts_with_arg = set("bcDEeFIiJLlmOopQRSWw")
            i = 1
            while i < len(argv):
                a = argv[i]
                if a.startswith("-") and len(a) == 2 and a[1] in opts_with_arg:
                    i += 2
                    continue
                if not a.startswith("-"):
                    call["host"] = a.split("@")[-1]
                    if "@" in a:
                        call["parts"].append(("ssh user", a.split("@")[0]))
                    break
                i += 1
        elif tool in ("scp", "rsync"):
            for a in argv[1:]:
                m = SCP_TARGET.match(a)
                if m and not a.startswith("-"):
                    call["host"] = m.group(1)
                    break
        elif tool == "aws s3":
            call["host"] = "s3.amazonaws.com"
        if call["host"]:
            calls.append(call)
    return calls


def _remote_host(remote: str) -> dict:
    if "://" in remote:
        u = urlsplit(remote)
        d = {"host": u.hostname or remote, "parts": [("path", u.path)]}
        if u.password:
            d["basic_auth"] = f"{u.username}:{u.password}"
        return d
    m = SCP_TARGET.match(remote)
    return {"host": m.group(1) if m else remote, "parts": []}


def _url_call(call: dict, url: str) -> dict:
    try:
        u = urlsplit(url)
    except ValueError:
        return call
    call["host"] = (u.hostname or "").lower()
    call["parts"].append(("path", unquote_plus(u.path)))
    if u.query:
        call["parts"].append(("query", unquote_plus(u.query)))
    if u.password:
        call["basic_auth"] = f"{u.username}:{u.password}"
    return call


# ------------------------------------------------------------------ transcript walking

def _text(x) -> str:
    """Flatten tool-result content (str, list of blocks) into text, skipping images."""
    if isinstance(x, str):
        return x
    if isinstance(x, list):
        return "\n".join(_text(b) for b in x if not (isinstance(b, dict) and b.get("type") in ("image", "input_image")))
    if isinstance(x, dict):
        if "text" in x and isinstance(x["text"], str):
            return x["text"]
        if "content" in x:
            return _text(x["content"])
        return ""
    return ""


READ_TOOLS = {"Read": "file read", "NotebookRead": "file read", "Grep": "search output", "Glob": "search output",
              "Bash": "command output", "WebFetch": "web page content", "WebSearch": "web search results"}
WEB_MCP = re.compile(r"fetch|search|web|http|browse|navigate|scrape|crawl|request|research", re.I)


class Scanner:
    def __init__(self, ident: Identity, since: str = "") -> None:
        self.ident = ident
        self.since = since
        self.r = Results()

    # -- shared
    def provider(self, text: str, where: str, session: str, ts: str) -> None:
        if not text:
            return
        for f in scan(text[:MAX_TEXT], "body", self.ident):
            self.r.finding("provider", f, where, session, ts)

    def tool_call(self, name: str, inp, session: str, ts: str) -> None:
        """Third-party channel: reconstruct network calls from a tool invocation."""
        calls: list[dict] = []
        if name == "WebFetch" and isinstance(inp, dict):
            calls.append(_url_call({"via": "WebFetch", "host": "", "parts": []}, str(inp.get("url", ""))))
        elif name == "WebSearch" and isinstance(inp, dict):
            calls.append({"via": "WebSearch", "host": "web search (run by the provider)",
                          "parts": [("query", str(inp.get("query", "")))]})
        elif name.startswith("mcp__") and WEB_MCP.search(name):
            server = name.split("__")[1] if name.count("__") >= 2 else name
            blob = json.dumps(inp)[:MAX_TEXT] if not isinstance(inp, str) else inp[:MAX_TEXT]
            urls = URL.findall(blob)
            base = {"via": f"MCP {server}", "host": "", "parts": [("body", blob)]}
            if urls:
                calls += [_url_call(dict(base, parts=list(base["parts"]) if i == 0 else []), u) for i, u in enumerate(urls[:5])]
            else:
                calls.append(dict(base, host=f"MCP server '{server}'"))
        else:
            cmd = self._command_text(inp)
            if cmd and NET_CMD.search(cmd):
                calls = parse_command(cmd)
        for c in calls:
            if not c.get("host") or LOCAL_HOST.match(c["host"]):
                continue
            via = c["via"]
            self.r.call(c["host"], via, session)
            if c.get("basic_auth"):
                f = Finding("secret", "credential in URL or -u", "auth", "••••…", "high")
                from tattle.detect import fingerprint, mask
                f.sample, f.fp = mask(c["basic_auth"].split(":", 1)[-1], "secret"), fingerprint(c["basic_auth"])
                self.r.finding("tools", f, f"{via} auth", session, ts, c["host"])
            for where, text in c["parts"]:
                for f in scan(text[:MAX_TEXT], where, self.ident):
                    self.r.finding("tools", f, f"{via} {where}", session, ts, c["host"])

    @staticmethod
    def _command_text(inp) -> str:
        if isinstance(inp, dict):
            for k in ("command", "cmd", "script"):
                v = inp.get(k)
                if isinstance(v, list):
                    return " ".join(map(str, v))
                if isinstance(v, str):
                    return v
            return ""
        if isinstance(inp, str):
            # Codex: JSON arguments or a JS snippet with cmd:"..." strings.
            try:
                parsed = json.loads(inp)
                if isinstance(parsed, dict):
                    return Scanner._command_text(parsed)
            except ValueError:
                pass
            cmds = re.findall(r"""\bcmd\s*:\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`[^`]*`)""", inp)
            out = []
            for c in cmds:
                try:
                    out.append(json.loads(c) if c[0] == '"' else c[1:-1])
                except ValueError:
                    out.append(c[1:-1])
            return "\n".join(out) if out else inp
        return ""

    # -- per format
    def scan_file(self, src: Source) -> None:
        r = self.r
        tool_names: dict[str, str] = {}
        labeled = False
        try:
            fh = src.path.open("rb")
        except OSError:
            return
        r.files += 1
        r.agents[src.agent] = r.agents.get(src.agent, 0) + 1
        label = self._label(src)
        with fh:
            for raw in fh:
                r.lines += 1
                r.bytes += len(raw)
                try:
                    d = json.loads(raw)
                except ValueError:
                    r.bad_lines += 1
                    continue
                if not isinstance(d, dict):
                    continue
                if src.kind == "claude":
                    if not labeled and d.get("cwd"):
                        label, labeled = self._label(src, d.get("cwd")), True
                    self._claude(d, label, tool_names)
                elif src.kind == "codex":
                    if d.get("type") == "session_meta" and isinstance(d.get("payload"), dict):
                        cwd = d["payload"].get("cwd")
                        if cwd:
                            label = self._label(src, cwd)
                    self._codex(d, label, tool_names)
                else:
                    ts = d.get("ts")
                    ts = datetime.fromtimestamp(ts, timezone.utc).isoformat() if isinstance(ts, (int, float)) else ""
                    if self._skip(ts):
                        continue
                    lbl = f"Codex history · {str(d.get('session_id', ''))[:8]}"
                    r.seen_ts(ts)
                    self._session(lbl, src.agent, ts)
                    self.provider(str(d.get("text", "")), "user message", lbl, ts)

    def _label(self, src: Source, cwd: str | None = None) -> str:
        proj = Path(cwd).name if cwd else ""
        sid = src.path.stem[-8:] if src.kind != "codex" else src.path.stem.rsplit("-", 1)[-1][:8]
        sub = " (subagent)" if "subagents" in src.path.parts else ""
        return f"{src.agent} · {scrub(proj, self.ident) or '?'} · {sid}{sub}"

    def _skip(self, ts: str) -> bool:
        return bool(self.since and ts and ts < self.since)

    def _session(self, label: str, agent: str, ts: str) -> dict:
        s = self.r.sessions.get(label)
        if s is None:
            s = self.r.sessions[label] = {"agent": agent, "first": ts, "last": ts, "provider": 0, "tools": 0}
        if ts:
            s["first"] = min(s["first"] or ts, ts)
            s["last"] = max(s["last"] or ts, ts)
        return s

    def _claude(self, d: dict, label: str, tool_names: dict) -> None:
        t = d.get("type")
        ts = d.get("timestamp") or ""
        if t not in ("user", "assistant", "attachment") or self._skip(ts):
            return
        self.r.seen_ts(ts)
        self._session(label, "Claude Code", ts)
        if t == "attachment":
            self.provider(_text(d.get("attachment")) or json.dumps(d.get("attachment"))[:MAX_TEXT], "attachment", label, ts)
            return
        msg = d.get("message") or {}
        content = msg.get("content")
        if isinstance(content, str):
            if t == "user":
                self.provider(content, "user message", label, ts)
            return
        if not isinstance(content, list):
            return
        for b in content:
            if not isinstance(b, dict):
                continue
            bt = b.get("type")
            if bt == "text" and t == "user":
                self.provider(b.get("text", ""), "user message", label, ts)
            elif bt == "tool_use":
                name = b.get("name", "")
                tool_names[b.get("id", "")] = name
                inp = b.get("input")
                blob = json.dumps(inp) if not isinstance(inp, str) else inp
                self.provider(blob, f"tool call ({name})", label, ts)
                self.tool_call(name, inp, label, ts)
            elif bt == "tool_result":
                name = tool_names.pop(b.get("tool_use_id", ""), "")
                where = READ_TOOLS.get(name) or (f"tool output ({name})" if name else "tool output")
                self.provider(_text(b.get("content")), where, label, ts)

    def _codex(self, d: dict, label: str, tool_names: dict) -> None:
        p = d.get("payload")
        ts = d.get("timestamp") or ""
        if d.get("type") != "response_item" or not isinstance(p, dict) or self._skip(ts):
            return
        self.r.seen_ts(ts)
        self._session(label, "Codex", ts)
        pt = p.get("type")
        if pt == "message" and p.get("role") in ("user", "developer"):
            self.provider(_text(p.get("content")), "user message" if p["role"] == "user" else "system prompt", label, ts)
        elif pt in ("function_call", "custom_tool_call", "local_shell_call"):
            name = p.get("name") or "shell"
            inp = p.get("arguments") if pt == "function_call" else p.get("input") if pt == "custom_tool_call" else p.get("action")
            tool_names[p.get("call_id", "")] = name
            self.provider(inp if isinstance(inp, str) else json.dumps(inp), f"tool call ({name})", label, ts)
            self.tool_call(name, inp, label, ts)
        elif pt in ("function_call_output", "custom_tool_call_output", "local_shell_call_output"):
            name = tool_names.pop(p.get("call_id", ""), "")
            out = p.get("output")
            self.provider(_text(out) if not isinstance(out, dict) else _text(out.get("content") or out.get("output") or ""),
                          "command output" if name in ("exec", "shell", "exec_command") else "tool output", label, ts)
        elif pt == "web_search_call":
            q = (p.get("action") or {}).get("query", "")
            self.r.call("web search (run by the provider)", "web_search", label)
            for f in scan(str(q), "query", self.ident):
                self.r.finding("tools", f, "web_search query", label, ts, "web search (run by the provider)")


# ------------------------------------------------------------------ driver

def run(ident: Identity, since: float | None = None, home: Path | None = None, sources: list[Source] | None = None,
        progress: bool = False) -> Results:
    srcs = sources if sources is not None else discover(home, since)
    since_iso = datetime.fromtimestamp(since, timezone.utc).isoformat() if since else ""
    sc = Scanner(ident, since_iso)
    total = sum(_size(s.path) for s in srcs) or 1
    t0 = time.time()
    last = 0.0
    for i, s in enumerate(srcs, 1):
        sc.scan_file(s)
        if progress and (time.time() - last > 0.25 or i == len(srcs)):
            last = time.time()
            mb = sc.r.bytes / 1e6
            print(f"\r\033[2Kscanning {i}/{len(srcs)} transcripts · {mb:,.0f}/{total / 1e6:,.0f} MB · "
                  f"{mb / max(time.time() - t0, 0.01):,.0f} MB/s", end="", file=sys.stderr, flush=True)
    if progress:
        print("\r\033[2K", end="", file=sys.stderr, flush=True)
    sc.r.elapsed = time.time() - t0
    # Per-session counts, after the fact.
    for g in sc.r.groups.values():
        for sess in g.sessions:
            if sess in sc.r.sessions:
                sc.r.sessions[sess][g.channel] += 1
    return sc.r


def _size(p: Path) -> int:
    try:
        return p.stat().st_size
    except OSError:
        return 0


def parse_since(value: str | None) -> float | None:
    """'30d', '12h', '2026-10-01' -> epoch seconds."""
    if not value:
        return None
    m = re.fullmatch(r"(\d+)\s*([dhw])", value.strip())
    if m:
        n, unit = int(m.group(1)), m.group(2)
        return time.time() - n * {"h": 3600, "d": 86400, "w": 604800}[unit]
    return datetime.fromisoformat(value).replace(tzinfo=timezone.utc).timestamp()


def to_dict(r: Results) -> dict:
    """JSON-safe summary; only masked samples."""
    def g(x: Group) -> dict:
        return {"channel": x.channel, "category": x.category, "kind": x.kind, "sample": x.sample, "severity": x.severity,
                "placeholder": x.placeholder, "host": x.host, "count": x.count, "places": x.places,
                "sessions": sorted(x.sessions, key=lambda s: x.sessions[s], reverse=True), "first": x.first, "last": x.last}
    return {
        "files": r.files, "bytes": r.bytes, "lines": r.lines, "bad_lines": r.bad_lines, "agents": r.agents,
        "first": r.first_ts, "last": r.last_ts, "elapsed": round(getattr(r, "elapsed", 0), 1), "dropped": r.dropped,
        "sessions": len(r.sessions),
        "groups": sorted((g(x) for x in r.groups.values()),
                         key=lambda x: (x["placeholder"], SEV_RANK.get(x["severity"], 3), x["category"] != "secret", -x["count"])),
        "calls": sorted(({"host": c.host, "via": c.via, "count": c.count, "category": c.category, "sessions": len(c.sessions)}
                         for c in r.calls.values()), key=lambda c: -c["count"]),
        "session_list": [{"label": k, **v} for k, v in sorted(r.sessions.items(), key=lambda kv: kv[1]["last"] or "", reverse=True)],
    }
