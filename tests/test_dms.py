import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "admin"))

from dms import DMSClient  # noqa: E402


def test_rejects_bad_email():
    client = DMSClient()
    try:
        client.add_account("bad;rm -rf /", "123456789012")
    except ValueError:
        pass
    else:
        raise AssertionError("invalid email accepted")


@patch("dms.subprocess.run")
def test_uses_argv_not_shell(run):
    run.return_value.returncode = 0
    run.return_value.stdout = "ok"
    run.return_value.stderr = ""
    DMSClient().add_alias("a@example.com", "b@example.com")
    args = run.call_args.args[0]
    assert args == [
        "docker",
        "exec",
        "mailserver",
        "setup",
        "alias",
        "add",
        "a@example.com",
        "b@example.com",
    ]
