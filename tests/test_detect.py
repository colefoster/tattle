from conftest import FAKE_ANTHROPIC, FAKE_AWS, FAKE_GITHUB

from tattle.detect import host_category, mask, scan, scrub


def kinds(findings):
    return {f.kind for f in findings}


def test_planted_key_in_body(ident):
    fs = scan('{"note": "use ' + FAKE_ANTHROPIC + ' for this"}', "body", ident)
    assert "Anthropic API key" in kinds(fs)
    f = next(f for f in fs if f.kind == "Anthropic API key")
    assert f.severity == "high" and not f.expected
    assert FAKE_ANTHROPIC not in f.sample and f.sample.startswith("sk-a")


def test_key_in_auth_header_is_expected(ident):
    fs = scan("Bearer " + FAKE_ANTHROPIC, "header:authorization", ident)
    assert fs and all(f.expected for f in fs)


def test_many_secret_kinds(ident):
    text = f"{FAKE_GITHUB} {FAKE_AWS} -----BEGIN RSA PRIVATE KEY-----"
    assert {"GitHub token", "AWS access key", "Private key block"} <= kinds(scan(text, "body", ident))


def test_dotenv_contents_inside_json_string(ident):
    body = '{"content": "PORT=3000\\nSTRIPE_SECRET_KEY=abcd1234efgh5678\\nDEBUG=1"}'
    assert ".env-style STRIPE_SECRET_KEY" in kinds(scan(body, "body", ident))


def test_value_from_local_dotenv(ident):
    assert "value from your .env" in kinds(scan("pw=s3cr3t-db-password-123", "body", ident))


def test_planted_email_your_own_vs_other(ident):
    fs = scan("contact jane.doe@example-mail.net or bob@corp.io", "query", ident)
    assert {"your email", "email address"} <= kinds(fs)
    assert all("jane.doe" not in f.sample for f in fs)


def test_boring_emails_ignored(ident):
    assert not scan("Co-Authored-By: Claude <noreply@anthropic.com> x@example.com", "body", ident)


def test_identity_in_user_agent(ident):
    fs = scan("my-agent/1.0 (Jane Doe; janes-laptop; jdoe)", "header:user-agent", ident)
    assert {"your full name", "your machine name", "your login name"} <= kinds(fs)
    assert all(f.severity == "high" for f in fs)


def test_home_path(ident):
    fs = scan("open /Users/jdoe/projects/app/.env", "body", ident)
    assert "home directory path" in kinds(fs)
    assert "/Users/j•••/" in {f.sample for f in fs}


def test_username_not_flagged_as_substring(ident):
    assert "your login name" not in kinds(scan("jdoez and xjdoe", "header:x-foo", ident))


def test_clean_text_has_no_findings(ident):
    assert scan("GET /index.html?page=2&q=weather", "query", ident) == []


def test_watch_list(ident):
    assert "watched string" in kinds(scan("re: project nightjar launch", "body", ident))


def test_scrub_masks_everything(ident):
    out = scrub(f"/Users/jdoe/x?k={FAKE_GITHUB}&e=jane.doe@example-mail.net&n=Jane Doe", ident)
    for raw in ("jdoe", FAKE_GITHUB, "jane.doe@", "Jane Doe"):
        assert raw not in out


def test_mask_shapes():
    assert mask("abcdefgh12345", "secret") == "abcd…(13 chars)"
    assert mask("jane@example.com", "personal") == "j•••@e•••.com"


def test_host_category():
    assert host_category("api.anthropic.com") == "model API"
    assert host_category("o123.ingest.sentry.io") == "telemetry"
    assert host_category("example.com") == "web"


def test_dotenv_in_numbered_file_listing(ident):
    body = '{"text": "     1\\tAPI_TOKEN=abcd1234efgh5678\\n     2→DB_PASSWORD=zzzzyyyyxxxx"}'
    ks = kinds(scan(body, "body", ident))
    assert {".env-style API_TOKEN", ".env-style DB_PASSWORD"} <= ks
