from conftest import FAKE_ANTHROPIC

from mitmproxy.test import tflow, tutils

from tattle import report
from tattle.addon import build_record


def make_flow(**req):
    f = tflow.tflow(req=tutils.treq(**req), resp=True)
    return f


def test_build_record_finds_planted_values(ident):
    f = make_flow(host="collect.example.org", path=b"/v1/log?email=jane.doe%40example-mail.net",
                  headers=[(b"user-agent", b"agent/1.0 (janes-laptop)"), (b"content-type", b"application/json")],
                  content=('{"k": "' + FAKE_ANTHROPIC + '"}').encode())
    rec = build_record(f, ident)
    kinds = {(x["kind"], x["where"]) for x in rec["findings"]}
    assert ("Anthropic API key", "body") in kinds
    assert ("your email", "query") in kinds
    assert ("your machine name", "header:user-agent") in kinds
    # nothing raw is stored
    blob = str(rec)
    assert FAKE_ANTHROPIC not in blob and "jane.doe" not in blob and "janes-laptop" not in blob


def test_report_renders(ident):
    f = make_flow(host="collect.example.org", path=b"/x", content=FAKE_ANTHROPIC.encode())
    recs = [build_record(f, ident)]
    s = report.summarize(recs)
    assert s["high"] == 1 and s["requests"] == 1
    page = report.render_html(recs, {"command": "claude -p hi"})
    assert "Anthropic API key" in page and "collect.example.org" in page
    assert FAKE_ANTHROPIC not in page
    assert "high" in report.terminal_summary(recs, color=False)


def test_report_escapes_script_close(ident):
    f = make_flow(host="a.example", path=b"/</script><b>")
    page = report.render_html([build_record(f, ident)])
    assert page.count("</script>") == 2  # just our two closing tags


def test_share_mode_drops_initials_and_ids(ident):
    f = make_flow(host="a.example", path=b"/org/6cd9c656-eadf-4d14-be8a-70a498b8e414/x?e=jane.doe%40example-mail.net")
    page = report.render_html([build_record(f, ident)], share=True)
    assert "6cd9c656" not in page and "j•••@" not in page and "•••@•••.net" in page
