import pytest

from tattle.detect import Identity

# Fixture identity: invented values only.
FAKE = Identity(username="jdoe", full_name="Jane Doe", hostname="janes-laptop",
                emails=["jane.doe@example-mail.net"], extra=["Project Nightjar"],
                dotenv_values=["s3cr3t-db-password-123"])

# Built at runtime so no scanner flags this repo for shipping a real-looking key.
FAKE_ANTHROPIC = "sk-ant-" + "api03-" + "FAKEFAKEFAKE0123456789abcdefghijklmnop"
FAKE_GITHUB = "ghp_" + "A" * 36
FAKE_AWS = "AKIA" + "IOSFODNN7EXAMPLE"


@pytest.fixture
def ident():
    return FAKE
