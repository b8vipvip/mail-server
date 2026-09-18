import json
import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "admin"))

from dms import DMSClient, DMSError


def test_rejects_bad_email():
    with pytest.raises(ValueError):
        DMSClient().add_account("bad;rm -rf /", "123456789012")


def test_rejects_unmanaged_domain():
    with pytest.raises(ValueError):
        DMSClient().add_account("user@example.com", "123456789012")


@patch("dms.socket.socket")
def test_uses_unix_socket(socket_factory):
    sock = socket_factory.return_value.__enter__.return_value
    sock.recv.side_effect = [json.dumps({"ok": True, "output": "ok"}).encode(), b""]
    DMSClient().add_alias("a@mv3.cn", "b@cn2.io")
    sock.connect.assert_called_once_with("/run/dms-admin/helper.sock")
    payload = sock.sendall.call_args.args[0]
    request = json.loads(payload)
    assert request["action"] == "add-alias"
    assert request["args"] == ["a@mv3.cn", "b@cn2.io"]


@patch("dms.socket.socket")
def test_password_is_socket_payload_not_process_argv(socket_factory):
    sock = socket_factory.return_value.__enter__.return_value
    sock.recv.side_effect = [json.dumps({"ok": True, "output": "ok"}).encode(), b""]
    password = "very-secret-password"
    DMSClient().add_account("a@mv3.cn", password)
    request = json.loads(sock.sendall.call_args.args[0])
    assert request["secret"] == password


@patch("dms.socket.socket")
def test_helper_failure_is_generic(socket_factory):
    sock = socket_factory.return_value.__enter__.return_value
    sock.recv.side_effect = [json.dumps({"ok": False}).encode(), b""]
    with pytest.raises(DMSError, match="Mail operation failed"):
        DMSClient().list_accounts()


@patch("dms.DMSClient.list_accounts")
def test_parses_account_rows(list_accounts):
    list_accounts.return_value = """* noreply@cn2.io ( 5.0K / ~ ) [0%]
    [ aliases -> postmaster@cn2.io ]

* admin@cn2.io ( 0 / ~ ) [0%]

* gptwork@mv3.cn ( 1.0K / ~ ) [0%]
    [ aliases -> postmaster@mv3.cn ]"""
    rows = DMSClient().account_rows()
    assert rows == [
        {"email": "noreply@cn2.io", "used": "5.0K", "quota": "~", "usage": "0%", "aliases": "postmaster@cn2.io"},
        {"email": "admin@cn2.io", "used": "0", "quota": "~", "usage": "0%", "aliases": ""},
        {"email": "gptwork@mv3.cn", "used": "1.0K", "quota": "~", "usage": "0%", "aliases": "postmaster@mv3.cn"},
    ]


@patch("dms.DMSClient.list_aliases")
def test_parses_alias_rows(list_aliases):
    list_aliases.return_value = """* postmaster@cn2.io noreply@cn2.io

* postmaster@mv3.cn gptwork@mv3.cn"""
    assert DMSClient().alias_rows() == [
        {"alias": "postmaster@cn2.io", "recipient": "noreply@cn2.io"},
        {"alias": "postmaster@mv3.cn", "recipient": "gptwork@mv3.cn"},
    ]
