"""Find secrets and personal data in outbound request text.

Everything here is pure: callers pass text plus an Identity and get Findings back.
Raw matched values never leave this module unmasked.
"""

from __future__ import annotations

import getpass
import os
import pwd
import re
import socket
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path

# Headers whose whole job is to carry a credential. A key here is "expected":
# still reported, but dimmed, because that is how the agent authenticates.
AUTH_HEADERS = {"authorization", "proxy-authorization", "x-api-key", "cookie", "api-key", "x-goog-api-key"}

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI API key", re.compile(r"sk-(?:proj-|svcacct-)?(?!ant-)[A-Za-z0-9_\-]{32,}")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
    ("Private key block", re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----")),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
]

# .env-style assignment of something secret-named. The prefix also accepts a
# literal "\n" so it still matches .env contents embedded in a JSON string.
ENV_ASSIGN = re.compile(
    r"(?:^|\\n|[\s;\"'])(?:export\s+)?([A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?))"
    r"\s*=\s*['\"]?([^\s'\"\\]{8,})",
    re.MULTILINE,
)

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")
HOME_PATH = re.compile(r"(?:/Users/|/home/|[A-Za-z]:\\\\?Users\\\\?)([A-Za-z0-9._-]+)")
# Emails that turn up in every agent prompt and say nothing about the user.
BORING_EMAIL = re.compile(r"(?:^noreply@|@anthropic\.com$|@example\.(?:com|org|net)$|@users\.noreply\.github\.com$)", re.I)
BORING_HOME_USERS = {"shared", "runner", "user", "username", "you", "me", "name", "<user>", "xxx"}


@dataclass
class Identity:
    """Things that identify the person running the agent."""

    username: str = ""
    full_name: str = ""
    hostname: str = ""
    emails: list[str] = field(default_factory=list)
    extra: list[str] = field(default_factory=list)  # user-supplied watch strings
    dotenv_values: list[str] = field(default_factory=list)

    @classmethod
    def discover(cls, cwd: Path | None = None, watch_file: Path | None = None) -> "Identity":
        ident = cls()
        try:
            ident.username = getpass.getuser()
        except Exception:
            pass
        try:
            gecos = pwd.getpwnam(ident.username).pw_gecos.split(",")[0].strip()
            ident.full_name = gecos if " " in gecos else ""
        except Exception:
            pass
        host = socket.gethostname().split(".")[0]
        ident.hostname = host if len(host) >= 4 and host.lower() not in {"localhost"} else ""
        for key in ("user.email", "user.name"):
            try:
                val = subprocess.run(["git", "config", "--get", key], capture_output=True, text=True, timeout=3).stdout.strip()
            except Exception:
                val = ""
            if val and key == "user.email":
                ident.emails.append(val)
            elif val and " " in val and not ident.full_name:
                ident.full_name = val
        if watch_file and watch_file.exists():
            ident.extra = [l.strip() for l in watch_file.read_text().splitlines() if l.strip() and not l.startswith("#")]
        if cwd:
            ident.dotenv_values = read_dotenv_values(cwd)
        return ident

    def to_dict(self) -> dict:
        return asdict(self)


def read_dotenv_values(cwd: Path) -> list[str]:
    """Values from .env files in cwd, so we can spot them leaving verbatim."""
    values: list[str] = []
    for p in sorted(cwd.glob(".env*")):
        if not p.is_file() or p.name.endswith((".example", ".sample", ".template")):
            continue
        try:
            text = p.read_text(errors="ignore")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            val = line.split("=", 1)[1].strip().strip("'\"")
            if len(val) >= 8 and val.lower() not in {"true", "false", "localhost"}:
                values.append(val)
    return values


@dataclass
class Finding:
    category: str  # "secret" | "personal"
    kind: str  # human label, e.g. "GitHub token", "your email"
    where: str  # "query", "path", "header:user-agent", "body"
    sample: str  # masked
    severity: str = "high"  # "high" | "medium" | "low"
    expected: bool = False  # credential sent in its own auth header

    def key(self) -> tuple:
        return (self.category, self.kind, self.where, self.sample)


def mask(value: str, category: str) -> str:
    if category == "secret":
        return f"{value[:4]}…({len(value)} chars)"
    if "@" in value:
        local, _, domain = value.partition("@")
        tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
        return f"{local[:1]}•••@{domain[:1]}•••.{tld}"
    if value.startswith(("/Users/", "/home/")):
        prefix, _, user = value.rpartition("/")
        return f"{prefix}/{user[:1]}•••/"
    if "\\" in value:
        prefix, _, user = value.rpartition("\\")
        return f"{prefix}\\{user[:1]}•••\\"
    return " ".join(w[:1] + "•••" for w in value.split())


def _word(value: str) -> re.Pattern[str]:
    return re.compile(r"(?<![A-Za-z0-9])" + re.escape(value) + r"(?![A-Za-z0-9])", re.IGNORECASE)


def scan(text: str, where: str, ident: Identity | None = None) -> list[Finding]:
    """Scan one piece of request text (a header value, the query, the body...)."""
    if not text:
        return []
    ident = ident or Identity()
    out: list[Finding] = []
    header = where.split(":", 1)[1] if where.startswith("header:") else ""
    expected = header in AUTH_HEADERS

    seen_spans: list[tuple[int, int]] = []
    for kind, pat in SECRET_PATTERNS:
        for m in pat.finditer(text):
            if any(s <= m.start() < e for s, e in seen_spans):
                continue
            seen_spans.append(m.span())
            out.append(Finding("secret", kind, where, mask(m.group(0), "secret"), "medium" if expected else "high", expected))
    for m in ENV_ASSIGN.finditer(text):
        val_start = m.start(2)
        if any(s <= val_start < e for s, e in seen_spans):
            continue
        out.append(Finding("secret", f".env-style {m.group(1)}", where, mask(m.group(2), "secret"), "high"))
    for val in ident.dotenv_values:
        if val in text and not any(f.sample == mask(val, "secret") for f in out):
            out.append(Finding("secret", "value from your .env", where, mask(val, "secret"), "medium" if expected else "high", expected))

    own_emails = {e.lower() for e in ident.emails}
    for m in EMAIL.finditer(text):
        addr = m.group(0)
        if addr.lower() in own_emails:
            out.append(Finding("personal", "your email", where, mask(addr, "personal"), "high"))
        elif not BORING_EMAIL.search(addr):
            out.append(Finding("personal", "email address", where, mask(addr, "personal"), "medium"))

    for m in HOME_PATH.finditer(text):
        user = m.group(1)
        if user.lower() in BORING_HOME_USERS:
            continue
        sev = "high" if header or where in ("query", "path") else "medium"
        out.append(Finding("personal", "home directory path", where, mask(m.group(0), "personal"), sev))

    loc_sev = "high" if header or where in ("query", "path") else "medium"
    if ident.full_name and _word(ident.full_name).search(text):
        out.append(Finding("personal", "your full name", where, mask(ident.full_name, "personal"), "high"))
    if ident.username and len(ident.username) >= 3:
        # A bare username in a big prompt body is mostly echoes of home paths;
        # only call it out on its own when it is in a header, path or query.
        stripped = HOME_PATH.sub("", text)
        if _word(ident.username).search(stripped) and (header or where in ("query", "path")):
            out.append(Finding("personal", "your login name", where, mask(ident.username, "personal"), loc_sev))
    if ident.hostname and _word(ident.hostname).search(text):
        out.append(Finding("personal", "your machine name", where, mask(ident.hostname, "personal"), loc_sev))
    for val in ident.extra:
        if _word(val).search(text):
            out.append(Finding("personal", "watched string", where, mask(val, "personal"), "high"))

    uniq: dict[tuple, Finding] = {}
    for f in out:
        uniq.setdefault(f.key(), f)
    return list(uniq.values())


def scrub(text: str, ident: Identity | None = None) -> str:
    """Mask secrets and identity strings in text we store (paths, user agents)."""
    ident = ident or Identity()
    for _, pat in SECRET_PATTERNS:
        text = pat.sub(lambda m: mask(m.group(0), "secret"), text)
    text = EMAIL.sub(lambda m: mask(m.group(0), "personal"), text)
    text = HOME_PATH.sub(lambda m: mask(m.group(0), "personal"), text)
    for val in [ident.full_name, ident.hostname, *ident.extra]:
        if val:
            text = _word(val).sub(mask(val, "personal"), text)
    if ident.username and len(ident.username) >= 3:
        text = _word(ident.username).sub(mask(ident.username, "personal"), text)
    for val in ident.dotenv_values:
        text = text.replace(val, mask(val, "secret"))
    return text


HOST_CATEGORIES: list[tuple[str, tuple[str, ...]]] = [
    ("model API", ("api.anthropic.com", "claude.ai", "api.openai.com", "chatgpt.com", "generativelanguage.googleapis.com",
                   "openrouter.ai", "api.mistral.ai", "api.groq.com", "api.x.ai")),
    ("telemetry", ("statsig.anthropic.com", "statsig.com", "featuregates.org", "datadoghq.com", "sentry.io",
                   "segment.io", "amplitude.com", "mixpanel.com", "posthog.com", "honeycomb.io", "growthbook.io")),
    ("packages & code", ("registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "github.com",
                         "githubusercontent.com", "crates.io", "storage.googleapis.com")),
]


def host_category(host: str) -> str:
    host = host.lower()
    for cat, domains in HOST_CATEGORIES:
        if any(host == d or host.endswith("." + d) for d in domains):
            return cat
    return "web"
