"""mitmproxy addon: one JSON line per outbound request, with findings.

Load with: mitmdump -s addon.py --set tattle_out=flows.jsonl --set tattle_identity=identity.json
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from urllib.parse import unquote_plus

from mitmproxy import ctx, http

from tattle.detect import Identity, host_category, scan, scrub

MAX_SCAN_BYTES = 8 * 1024 * 1024


def _body_text(req: http.Request) -> str:
    raw = req.get_content(strict=False) or b""
    return raw[:MAX_SCAN_BYTES].decode("utf-8", errors="ignore")


def build_record(flow: http.HTTPFlow, ident: Identity) -> dict:
    req = flow.request
    path, _, query = req.path.partition("?")
    findings = []
    findings += scan(unquote_plus(path), "path", ident)
    findings += scan(unquote_plus(query), "query", ident)
    for name, value in req.headers.items(multi=True):
        findings += scan(value, f"header:{name.lower()}", ident)
    findings += scan(_body_text(req), "body", ident)

    resp = flow.response
    return {
        "ts": req.timestamp_start,
        "method": req.method,
        "scheme": req.scheme,
        "host": req.pretty_host,
        "port": req.port,
        "path": scrub(unquote_plus(req.path), ident)[:400],
        "category": host_category(req.pretty_host),
        "req_bytes": len(req.raw_content or b""),
        "header_names": sorted({k.lower() for k in req.headers.keys()}),
        "user_agent": scrub(req.headers.get("user-agent", ""), ident)[:300],
        "content_type": req.headers.get("content-type", "").split(";")[0],
        "status": resp.status_code if resp else None,
        "resp_bytes": len(resp.raw_content or b"") if resp else 0,
        "error": str(flow.error) if flow.error else None,
        "findings": [f.__dict__ for f in findings],
    }


class Tattle:
    def __init__(self) -> None:
        self.ident = Identity()
        self.lock = threading.Lock()
        self.out: Path | None = None

    def load(self, loader) -> None:
        loader.add_option("tattle_out", str, "", "JSONL file to append request records to")
        loader.add_option("tattle_identity", str, "", "JSON file describing the user's identity strings")

    def configure(self, updated) -> None:
        if "tattle_identity" in updated and ctx.options.tattle_identity:
            data = json.loads(Path(ctx.options.tattle_identity).read_text())
            self.ident = Identity(**data)
        if "tattle_out" in updated and ctx.options.tattle_out:
            self.out = Path(ctx.options.tattle_out)

    def _write(self, flow: http.HTTPFlow) -> None:
        if flow.metadata.get("tattle_done"):
            return
        flow.metadata["tattle_done"] = True
        rec = build_record(flow, self.ident)
        if self.out is None:
            return
        with self.lock, self.out.open("a") as fh:
            fh.write(json.dumps(rec) + "\n")

    def response(self, flow: http.HTTPFlow) -> None:
        self._write(flow)

    def error(self, flow: http.HTTPFlow) -> None:
        self._write(flow)

    def tls_failed_client(self, data) -> None:
        # The client refused our certificate: usually certificate pinning or a
        # tool that ignores the CA env vars. We can't see inside, but we can say so.
        sni = data.context.client.sni or ""
        host = sni or (data.context.server.address or ("?",))[0]
        rec = {
            "ts": time.time(), "method": "CONNECT", "scheme": "https", "host": host, "port": 443,
            "path": "", "category": host_category(host), "req_bytes": 0, "header_names": [],
            "user_agent": "", "content_type": "", "status": None, "resp_bytes": 0,
            "error": "client rejected the interception certificate (pinned, or ignores the CA env vars)",
            "findings": [],
        }
        if self.out is not None:
            with self.lock, self.out.open("a") as fh:
                fh.write(json.dumps(rec) + "\n")


addons = [Tattle()]
