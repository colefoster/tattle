"""tattle: run a coding agent through a local proxy and see what it sends where."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from datetime import datetime
from pathlib import Path

from tattle import report
from tattle.detect import Identity, scrub

ADDON = Path(__file__).with_name("addon.py")


def home() -> Path:
    return Path(os.environ.get("TATTLE_HOME", "~/.tattle")).expanduser()


def ca_cert() -> Path:
    return home() / "ca" / "mitmproxy-ca-cert.pem"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def latest_session() -> Path | None:
    root = home() / "sessions"
    sessions = sorted(p for p in root.glob("*") if p.is_dir()) if root.exists() else []
    return sessions[-1] if sessions else None


def resolve_session(arg: str | None) -> Path:
    if arg:
        p = Path(arg).expanduser()
        if not p.exists():
            p = home() / "sessions" / arg
        return p if p.is_dir() else p.parent
    s = latest_session()
    if not s:
        sys.exit("tattle: no sessions yet. Start one with `tattle run -- <agent>`.")
    return s


class Proxy:
    """A mitmdump child process with the tattle addon, plus the env that routes a client through it."""

    def __init__(self, port: int | None = None, cwd: Path | None = None):
        self.port = port or free_port()
        self.session = home() / "sessions" / datetime.now().strftime("%Y%m%d-%H%M%S")
        self.session.mkdir(parents=True, exist_ok=True)
        self.jsonl = self.session / "flows.jsonl"
        self.jsonl.touch()
        self.ident = Identity.discover(cwd or Path.cwd(), home() / "watch.txt")
        (self.session / "identity.json").write_text(json.dumps(self.ident.to_dict()))
        os.chmod(self.session / "identity.json", 0o600)
        self.proc: subprocess.Popen | None = None

    def start(self) -> None:
        (home() / "ca").mkdir(parents=True, exist_ok=True)
        cmd = [sys.executable, "-c", "from mitmproxy.tools.main import mitmdump; mitmdump()",
               "--listen-host", "127.0.0.1", "--listen-port", str(self.port), "-q",
               "--set", f"confdir={home() / 'ca'}", "-s", str(ADDON),
               "--set", f"tattle_out={self.jsonl}", "--set", f"tattle_identity={self.session / 'identity.json'}"]
        log = (self.session / "proxy.log").open("w")
        self.proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.time() + 20
        while time.time() < deadline:
            if self.proc.poll() is not None:
                sys.exit(f"tattle: proxy failed to start, see {self.session / 'proxy.log'}")
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                    if ca_cert().exists():
                        break
            except OSError:
                pass
            time.sleep(0.1)
        else:
            self.stop()
            sys.exit("tattle: proxy did not come up within 20s")
        self.bundle = self._bundle()

    def _bundle(self) -> Path:
        # Public roots + our CA, so tools that *replace* their trust store with
        # SSL_CERT_FILE still trust anything that bypasses the proxy (NO_PROXY hosts).
        import certifi

        bundle = home() / "ca" / "bundle.pem"
        bundle.write_text(Path(certifi.where()).read_text() + "\n" + ca_cert().read_text())
        return bundle

    def env(self) -> dict[str, str]:
        url = f"http://127.0.0.1:{self.port}"
        e = {k: url for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")}
        e.update({k: "localhost,127.0.0.1,::1" for k in ("NO_PROXY", "no_proxy")})
        e["NODE_EXTRA_CA_CERTS"] = str(ca_cert())
        e["NODE_USE_ENV_PROXY"] = "1"  # Node 24+ fetch honours HTTP(S)_PROXY with this
        for k in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "AWS_CA_BUNDLE",
                  "CODEX_CA_CERTIFICATE"):
            e[k] = str(self.bundle)
        return e

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def finish(self, command: str, open_browser: bool = False, color: bool = True) -> Path:
        self.stop()
        try:
            (self.session / "identity.json").unlink()  # the only file holding raw identity strings
        except FileNotFoundError:
            pass
        meta = {"command": scrub(command, self.ident), "session": self.session.name}
        (self.session / "meta.json").write_text(json.dumps(meta))
        out = report.write_report(self.jsonl, self.session / "report.html", meta)
        print(report.terminal_summary(report.load(self.jsonl), out, color), file=sys.stderr)
        if open_browser:
            webbrowser.open(out.as_uri())
        return out


def follow(jsonl: Path, stop: threading.Event, color: bool) -> None:
    with jsonl.open() as fh:
        while not stop.is_set():
            line = fh.readline()
            if not line:
                time.sleep(0.2)
                continue
            try:
                print(report.live_line(json.loads(line), color), file=sys.stderr, flush=True)
            except json.JSONDecodeError:
                pass


def cmd_run(a: argparse.Namespace) -> int:
    if not a.command:
        sys.exit("usage: tattle run [--live] [--open] -- <command> [args...]")
    color = sys.stderr.isatty()
    proxy = Proxy(a.port)
    proxy.start()
    print(f"tattle: proxy on 127.0.0.1:{proxy.port} · session {proxy.session.name}", file=sys.stderr)
    stop = threading.Event()
    if a.live:
        threading.Thread(target=follow, args=(proxy.jsonl, stop, color), daemon=True).start()
    env = {**os.environ, **proxy.env()}
    old = signal.signal(signal.SIGINT, signal.SIG_IGN)  # the agent owns Ctrl-C
    try:
        code = subprocess.call(a.command, env=env)
    except FileNotFoundError:
        code = 127
        print(f"tattle: command not found: {a.command[0]}", file=sys.stderr)
    finally:
        signal.signal(signal.SIGINT, old)
        time.sleep(0.5)  # let in-flight responses land
        stop.set()
        proxy.finish(" ".join(a.command), a.open, color)
    return code


def cmd_proxy(a: argparse.Namespace) -> int:
    color = sys.stderr.isatty()
    proxy = Proxy(a.port)
    proxy.start()
    print("# tattle proxy is up. In another shell:", file=sys.stderr)
    for k, v in proxy.env().items():
        print(f"export {k}={v}")
    print("# Ctrl-C here to stop and write the report.\n", file=sys.stderr, flush=True)
    stop = threading.Event()
    t = threading.Thread(target=follow, args=(proxy.jsonl, stop, color), daemon=True)
    t.start()
    try:
        while proxy.proc and proxy.proc.poll() is None:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    stop.set()
    proxy.finish("tattle proxy", a.open, color)
    return 0


def cmd_tail(a: argparse.Namespace) -> int:
    s = resolve_session(a.session)
    print(f"tattle: following {s.name} (Ctrl-C to stop)", file=sys.stderr)
    try:
        follow(s / "flows.jsonl", threading.Event(), sys.stderr.isatty())
    except KeyboardInterrupt:
        pass
    return 0


def cmd_report(a: argparse.Namespace) -> int:
    s = resolve_session(a.session)
    name = "report.share.html" if a.share else "report.html"
    meta_file = s / "meta.json"
    meta = json.loads(meta_file.read_text()) if meta_file.exists() else {"session": s.name}
    out = report.write_report(s / "flows.jsonl", s / name, meta, a.share)
    if a.json:
        print(json.dumps(report.summarize(report.load(s / "flows.jsonl")), indent=2))
    else:
        print(report.terminal_summary(report.load(s / "flows.jsonl"), out, sys.stdout.isatty()))
    if a.open:
        webbrowser.open(out.as_uri())
    return 0


def cmd_retro(a: argparse.Namespace) -> int:
    from tattle import retro

    since = retro.parse_since(a.since)
    ident = Identity.discover(None, home() / "watch.txt")
    srcs = retro.discover(Path(a.root).expanduser() if a.root else None, since)
    if not srcs:
        print("tattle retro: no Claude Code or Codex transcripts found (~/.claude/projects, ~/.codex/sessions).", file=sys.stderr)
        return 1
    res = retro.run(ident, since, sources=srcs, progress=sys.stderr.isatty())
    d = retro.to_dict(res)
    out_dir = home() / "retro"
    out_dir.mkdir(parents=True, exist_ok=True)
    name = "report.share.html" if a.share else "report.html"
    out = out_dir / name
    out.write_text(report.render_retro(d, a.share))
    if a.json:
        print(json.dumps({k: v for k, v in d.items() if k != "session_list"}, indent=2))
    else:
        print(report.retro_terminal(d, out, sys.stdout.isatty()))
    if a.open:
        webbrowser.open(out.as_uri())
    return 0


def cmd_ls(a: argparse.Namespace) -> int:
    root = home() / "sessions"
    for p in sorted(root.glob("*")) if root.exists() else []:
        recs = report.load(p / "flows.jsonl")
        s = report.summarize(recs)
        print(f"{p.name}  {s['requests']:>5} reqs  {len(s['hosts']):>3} hosts  {s['high']} high  {s['medium']} medium")
    return 0


def cmd_ca(a: argparse.Namespace) -> int:
    print(ca_cert() if ca_cert().exists() else "no CA yet; it is created on the first `tattle run`")
    print("tattle never installs this CA system-wide. Only processes started by `tattle run`\n"
          "(or shells using `tattle proxy` exports) trust it, via environment variables.", file=sys.stderr)
    return 0


def cmd_clean(a: argparse.Namespace) -> int:
    h = home()
    if not h.exists():
        print("nothing to clean")
        return 0
    if not a.yes:
        ans = input(f"Delete {h} (CA key and all sessions)? [y/N] ")
        if ans.strip().lower() != "y":
            return 1
    shutil.rmtree(h)
    print(f"removed {h}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="tattle", description="See what your coding agent sends to the internet.")
    sub = p.add_subparsers(dest="cmd")

    rr = sub.add_parser("retro", help="audit past Claude Code and Codex sessions (the default)")
    rr.add_argument("--since", help="only sessions newer than this: 30d, 12h, 2w or 2026-10-01")
    rr.add_argument("--open", action="store_true", help="open the HTML report")
    rr.add_argument("--share", action="store_true", help="extra masking for a report you will show others")
    rr.add_argument("--json", action="store_true", help="print the summary as JSON (masked values only)")
    rr.add_argument("--root", help=argparse.SUPPRESS)  # alternate home dir, for tests
    rr.set_defaults(fn=cmd_retro)

    r = sub.add_parser("run", help="run a command through the audit proxy")
    r.add_argument("--live", action="store_true", help="print each request as it happens (stderr)")
    r.add_argument("--open", action="store_true", help="open the HTML report when done")
    r.add_argument("--port", type=int)
    r.add_argument("command", nargs=argparse.REMAINDER)
    r.set_defaults(fn=cmd_run)

    x = sub.add_parser("proxy", help="run the proxy standalone and print env exports")
    x.add_argument("--port", type=int)
    x.add_argument("--open", action="store_true")
    x.set_defaults(fn=cmd_proxy)

    t = sub.add_parser("tail", help="live view of a session (default: latest)")
    t.add_argument("session", nargs="?")
    t.set_defaults(fn=cmd_tail)

    rp = sub.add_parser("report", help="rebuild and print a session report (default: latest)")
    rp.add_argument("session", nargs="?")
    rp.add_argument("--open", action="store_true")
    rp.add_argument("--json", action="store_true")
    rp.add_argument("--share", action="store_true", help="extra masking for a report you will show others")
    rp.set_defaults(fn=cmd_report)

    sub.add_parser("ls", help="list sessions").set_defaults(fn=cmd_ls)
    sub.add_parser("ca", help="show the local CA path").set_defaults(fn=cmd_ca)
    c = sub.add_parser("clean", help="delete ~/.tattle: the CA and every session")
    c.add_argument("-y", "--yes", action="store_true")
    c.set_defaults(fn=cmd_clean)

    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0].startswith("--") and argv[0] not in ("-h", "--help"):
        argv = ["retro", *argv]  # bare `tattle` audits what already happened
    a = p.parse_args(argv)
    if a.cmd == "run" and a.command and a.command[0] == "--":
        a.command = a.command[1:]
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
