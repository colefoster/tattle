"""Real proxy, real sockets: `tattle run` a client that leaks a planted key and email."""

import http.server
import json
import os
import socket
import sys
import threading
import textwrap

from conftest import FAKE_ANTHROPIC

from tattle import cli, report

PLANTED_EMAIL = "planted.person@example-mail.net"


def test_run_catches_planted_key_and_email(tmp_path, monkeypatch):
    monkeypatch.setenv("TATTLE_HOME", str(tmp_path / "home"))
    got = {}

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            got["body"] = self.rfile.read(int(self.headers["content-length"]))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    target = f"http://127.0.0.1:{srv.server_port}/collect?user={PLANTED_EMAIL}"

    # The client sends through $HTTP_PROXY explicitly (localhost is in NO_PROXY,
    # which is right for real agents but would skip the proxy here).
    client = tmp_path / "client.py"
    client.write_text(textwrap.dedent(f"""
        import os, socket, urllib.parse
        p = urllib.parse.urlparse(os.environ["HTTP_PROXY"])
        body = b'{{"api_key": "{FAKE_ANTHROPIC}"}}'
        s = socket.create_connection((p.hostname, p.port))
        s.sendall(b"POST {target} HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\nUser-Agent: test-agent/1.0\\r\\n"
                  b"Content-Type: application/json\\r\\nContent-Length: " + str(len(body)).encode() + b"\\r\\n"
                  b"Connection: close\\r\\n\\r\\n" + body)
        assert b"200" in s.recv(4096).split(b"\\r\\n")[0]
    """))
    rc = cli.main(["run", "--", sys.executable, str(client)])
    srv.shutdown()

    assert rc == 0
    assert FAKE_ANTHROPIC.encode() in got["body"]  # the proxy is transparent
    session = cli.latest_session()
    recs = report.load(session / "flows.jsonl")
    kinds = {f["kind"] for r in recs for f in r["findings"]}
    assert "Anthropic API key" in kinds
    assert "email address" in kinds
    on_disk = "".join(p.read_text() for p in session.iterdir() if p.is_file())
    assert FAKE_ANTHROPIC not in on_disk and PLANTED_EMAIL not in on_disk
    assert not (session / "identity.json").exists()
    assert (session / "report.html").exists()
