import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "admin"))

from dms import DMSClient


def test_rejects_bad_email():
    with pytest.raises(ValueError):
        DMSClient().add_account("bad;rm -rf /", "123456789012")


def test_rejects_unmanaged_domain():
    with pytest.raises(ValueError):
        DMSClient().add_account("user@example.com", "123456789012")


@patch("dms.subprocess.run")
def test_uses_narrow_helper(run):
    run.return_value.returncode = 0
    run.return_value.stdout = "ok"
    run.return_value.stderr = ""
    DMSClient().add_alias("a@mv3.cn", "b@cn2.io")
    args = run.call_args.args[0]
    assert args == [
        "/usr/bin/sudo",
        "-n",
        "/usr/local/sbin/dms-admin-helper",
        "add-alias",
        "a@mv3.cn",
        "b@cn2.io",
    ]


@patch("dms.subprocess.run")
def test_password_is_stdin_not_argv(run):
    run.return_value.returncode = 0
    run.return_value.stdout = "ok"
    run.return_value.stderr = ""
    password = "very-secret-password"
    DMSClient().add_account("a@mv3.cn", password)
    args = run.call_args.args[0]
    assert password not in args
    assert run.call_args.kwargs["input"] == password
