"""Build a fixture transcript home (invented people, random keys) and render the retro report.

Used for the product-page screenshots: no real session data goes near the page.
    uv run python scripts/demo_retro.py OUT_DIR
"""

import json
import random
import string
import sys
from pathlib import Path

from tattle import report, retro
from tattle.detect import Identity

rnd = random.Random(42)
out = Path(sys.argv[1])
home = out / "home"


def key(prefix, n):
    return prefix + "".join(rnd.choice(string.ascii_letters + string.digits) for _ in range(n))


def jl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")


ME = "jane.doe@example-mail.net"
projects = ["storefront", "billing-api", "infra", "blog", "ml-pipeline", "dotfiles"]
gh, oa, stripe, slack = key("ghp_", 36), key("sk-proj-", 48), key("sk_live_", 24), key("xoxb-", 40)
tid = 0


def tu(name, inp):
    global tid
    tid += 1
    return {"type": "tool_use", "id": f"t{tid}", "name": name, "input": inp}, f"t{tid}"


for i in range(64):
    proj = projects[i % len(projects)]
    cwd = f"/Users/jdoe/Dev/{proj}"
    day = f"2026-{7 + i // 20:02d}-{1 + i % 28:02d}"
    rows = [{"cwd": cwd, "type": "user", "timestamp": f"{day}T09:00:00Z",
             "message": {"role": "user", "content": f"Work on {proj}. Ping me at {ME} when done."}}]
    tools = []
    if i % 9 == 0:
        a, t = tu("Read", {"file_path": f"{cwd}/.env"})
        tools.append((a, t, f"     1\tSTRIPE_SECRET_KEY={stripe}\n     2\tOPENAI_API_KEY={oa}\n"))
    if i % 7 == 1:
        a, t = tu("Bash", {"command": f"curl -s -H 'Authorization: token {gh}' 'https://api.github.com/repos/acme/{proj}/issues'"})
        tools.append((a, t, "[]"))
    if i % 11 == 2:
        a, t = tu("Bash", {"command": f"curl -X POST -H 'Content-Type: application/json' -d '{{\"text\":\"deployed\",\"token\":\"{slack}\"}}' https://hooks.slack.com/services/T000/B000"})
        tools.append((a, t, "ok"))
    if i % 5 == 3:
        a, t = tu("WebFetch", {"url": f"https://status.vendor.example.com/check?user={ME}", "prompt": "is it up"})
        tools.append((a, t, "All systems normal"))
    if i % 4 == 0:
        a, t = tu("WebFetch", {"url": "https://docs.python.org/3/library/re.html", "prompt": "syntax"})
        tools.append((a, t, "docs"))
    if i % 6 == 4:
        a, t = tu("Bash", {"command": f"git push origin main && rsync -az dist/ deploy@web1.example.net:/srv/{proj}"})
        tools.append((a, t, "done"))
    if i % 8 == 5:
        a, t = tu("Bash", {"command": "cat ~/.ssh/config"})
        tools.append((a, t, "Host web1\n  User deploy\n  IdentityFile /Users/jdoe/.ssh/id_ed25519\n"))
    if i % 13 == 6:
        a, t = tu("Bash", {"command": "grep -r phone crm/export.csv | head -3"})
        tools.append((a, t, "Ada Park,(415) 867-2309,12 Harbour Street\n"))
    if i % 3 == 0:
        a, t = tu("WebSearch", {"query": f"{proj} deploy error 502"})
        tools.append((a, t, "results"))
    for a, t, res in tools:
        rows.append({"cwd": cwd, "type": "assistant", "timestamp": f"{day}T09:01:00Z", "message": {"role": "assistant", "content": [a]}})
        rows.append({"cwd": cwd, "type": "user", "timestamp": f"{day}T09:01:02Z",
                     "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": t, "content": res}]}})
    jl(home / ".claude" / "projects" / f"-Users-jdoe-Dev-{proj}" / f"{i:04x}{key('', 28)}.jsonl", rows)

ident = Identity(username="jdoe", full_name="Jane Doe", hostname="janes-mbp", emails=[ME])
d = retro.to_dict(retro.run(ident, sources=retro.discover(home)))
d["elapsed"] = 0.4
(out / "retro.html").write_text(report.render_retro(d, share=True))
print(report.retro_terminal(d, None, False))
