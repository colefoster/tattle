"""Find secrets and personal data in outbound request text.

Everything here is pure: callers pass text plus an Identity and get Findings back.
Raw matched values never leave this module unmasked.
"""

from __future__ import annotations

import functools
import getpass
import hashlib
import math
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
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-|svcacct-)?(?!ant-)[A-Za-z0-9_\-]{32,200}(?![A-Za-z0-9_\-])")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
    # Header plus real key material, so docs that only mention the header don't count.
    ("Private key block", re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----(?:\s|\\n|\\r)+[A-Za-z0-9+/=]{40,}")),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
]

# Literal substrings at least one of which must appear before a pattern is run.
# Retro scans gigabytes of transcripts; skipping regexes that cannot match is
# most of the speed.
SECRET_HINTS: dict[str, tuple[str, ...]] = {
    "Anthropic API key": ("sk-ant-",), "OpenAI API key": ("sk-",), "AWS access key": ("AKIA", "ASIA"),
    "GitHub token": ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"), "Slack token": ("xox",),
    "Stripe live key": ("_live_",), "Google API key": ("AIza",), "Hugging Face token": ("hf_",),
    "Private key block": ("PRIVATE KEY",), "JSON Web Token": ("eyJ",),
}

PHONE = re.compile(r"(?<![\w.+-])(?:\+1[ .-]?)?\(?[2-9]\d{2}\)?[ .-]\d{3}[ .-]\d{4}(?![\w-])|(?<![\w+])\+[1-9]\d{1,2}[ -]?\d{2,4}[ -]\d{3,4}[ -]\d{3,4}(?![\w-])")
STREET = re.compile(r"\b\d{1,5} (?:[A-Z][a-z]+ ){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Boulevard|Blvd|Court|Ct|Crescent|Cres|Way|Place|Pl|Terrace|Circle)\b\.?")
PLACEHOLDER_WORDS = re.compile(r"example|fake|dummy|placeholder|sample|test|your|xxxx|redacted|changeme|hunter2|abcd|1234|"
                               r"supersecret|canary|JBSWY3DPEHPK3PXP|\*\*\*|\.\.\.|<|&lt;|\{|\$", re.I)
# A value that is itself a name (OTHER_VAR, settings.key, my-app-token) rather than a secret.
NAME_LIKE = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+|[a-z]+(?:[-_.:/][a-z]+)*[-_.:/]?\d{0,2}")
NOT_A_VALUE = re.compile(r"^[A-Z][A-Z0-9_]*=|[$({\[<]|os\.environ|process\.env|getenv|secrets\.|\bnull\b|\bNone\b|\btrue\b|\bfalse\b", re.I)


def looks_placeholder(value: str) -> bool:
    """Fixture, docs or template value rather than a live credential."""
    if PLACEHOLDER_WORDS.search(value):
        return True
    body = re.sub(r"^[a-z]+[-_](?:[a-z0-9]+[-_])?", "", value)
    if len(body) < 8:
        return True
    counts = {c: body.count(c) for c in set(body)}
    entropy = -sum(n / len(body) * math.log2(n / len(body)) for n in counts.values())
    return entropy < 3.0 or max(counts.values()) > len(body) * 0.4


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


# .env-style assignment of something secret-named. The prefix also accepts a
# literal "\n" or "\t" (and the "→" of numbered file listings) so it still
# matches .env contents embedded in a JSON string.
ENV_ASSIGN = re.compile(
    r"(?:^|\\[nt]|→|[\s;\"'])(?:export\s+)?([A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?))"
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
        # Global and repo-local: a repo may commit as a noreply address while
        # the global config still holds the real one.
        for scope in ("--global", None):
            for key in ("user.email", "user.name"):
                args = ["git", "config", *([scope] if scope else []), "--get", key]
                try:
                    val = subprocess.run(args, capture_output=True, text=True, timeout=3, cwd=cwd).stdout.strip()
                except Exception:
                    val = ""
                if val and key == "user.email" and val not in ident.emails:
                    ident.emails.append(val)
                elif val and key == "user.name" and " " in val and not ident.full_name:
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
    placeholder: bool = False  # looks like a docs/fixture value, not a live one
    # Hash of the raw value, for de-duplication in memory. Never written to disk.
    fp: str = field(default="", repr=False, compare=False)

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


@functools.lru_cache(maxsize=256)
def mask_digits(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    return "•" * (len(digits) - 2) + digits[-2:]


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
        if not any(h in text for h in SECRET_HINTS[kind]):
            continue
        for m in pat.finditer(text):
            if any(s <= m.start() < e for s, e in seen_spans):
                continue
            seen_spans.append(m.span())
            v = m.group(0)
            ph = kind != "Private key block" and looks_placeholder(v)
            out.append(Finding("secret", kind, where, mask(v, "secret"), "medium" if expected else "high", expected, ph, fingerprint(v)))
    if "=" in text:
        for m in ENV_ASSIGN.finditer(text):
            val_start = m.start(2)
            v = m.group(2).strip(".,;:)]}>|`")
            if any(s <= val_start < e for s, e in seen_spans) or NOT_A_VALUE.search(v) or NAME_LIKE.fullmatch(v):
                continue
            out.append(Finding("secret", f".env-style {m.group(1)}", where, mask(v, "secret"), "high", False,
                               looks_placeholder(v), fingerprint(v)))
    for val in ident.dotenv_values:
        if val in text and not any(f.sample == mask(val, "secret") for f in out):
            out.append(Finding("secret", "value from your .env", where, mask(val, "secret"), "medium" if expected else "high",
                               expected, False, fingerprint(val)))

    own_emails = {e.lower() for e in ident.emails}
    if "@" in text:
        for m in EMAIL.finditer(text):
            addr = m.group(0)
            if addr.lower() in own_emails:
                out.append(Finding("personal", "your email", where, mask(addr, "personal"), "high", fp=fingerprint(addr.lower())))
            elif not BORING_EMAIL.search(addr):
                out.append(Finding("personal", "email address", where, mask(addr, "personal"), "medium",
                                   fp=fingerprint(addr.lower())))

    if "Users" in text or "/home/" in text:
        for m in HOME_PATH.finditer(text):
            user = m.group(1)
            if user.lower() in BORING_HOME_USERS:
                continue
            sev = "high" if header or where in ("query", "path") else "medium"
            out.append(Finding("personal", "home directory path", where, mask(m.group(0), "personal"), sev,
                               fp=fingerprint(m.group(0))))

    for m in PHONE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if len(set(digits)) > 3:  # 555-555-5555 style filler
            out.append(Finding("personal", "phone number", where, mask_digits(m.group(0)), "medium", fp=fingerprint(digits)))
    if " " in text:
        for m in STREET.finditer(text):
            out.append(Finding("personal", "street address", where, mask(m.group(0), "personal"), "medium",
                               fp=fingerprint(m.group(0))))

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

    uniq: dict[tuple, Finding] = {}  # one finding per masked value and place
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


# First match wins: telemetry before model API so statsig.anthropic.com lands right.
HOST_CATEGORIES: list[tuple[str, tuple[str, ...]]] = [
    ("telemetry", ("statsig.anthropic.com", "statsig.com", "featuregates.org", "datadoghq.com", "sentry.io",
                   "segment.io", "amplitude.com", "mixpanel.com", "posthog.com", "honeycomb.io", "growthbook.io")),
    ("model API", ("anthropic.com", "claude.ai", "api.openai.com", "chatgpt.com", "generativelanguage.googleapis.com",
                   "openrouter.ai", "api.mistral.ai", "api.groq.com", "api.x.ai")),
    ("packages & code", ("registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "github.com",
                         "githubusercontent.com", "crates.io", "storage.googleapis.com")),
]


def host_category(host: str) -> str:
    host = host.lower()
    for cat, domains in HOST_CATEGORIES:
        if any(host == d or host.endswith("." + d) for d in domains):
            return cat
    return "web"
