import importlib.util
import json
from pathlib import Path
from unittest.mock import patch

HELPER_PATH = Path(__file__).resolve().parents[1] / "deploy" / "dms-admin-helper.py"
SPEC = importlib.util.spec_from_file_location("dms_admin_helper", HELPER_PATH)
helper = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(helper)


def _proc(stdout="", returncode=0):
    class Result:
        pass
    result = Result()
    result.stdout = stdout
    result.returncode = returncode
    return result


def test_service_status_detects_real_ss_listeners():
    ss_output = """LISTEN 0 100 0.0.0.0:465 0.0.0.0:*
LISTEN 0 100 0.0.0.0:993 0.0.0.0:*
LISTEN 0 100 0.0.0.0:25 0.0.0.0:*
LISTEN 0 100 0.0.0.0:587 0.0.0.0:*
LISTEN 0 100 [::]:465 [::]:*
LISTEN 0 100 [::]:993 [::]:*
LISTEN 0 100 [::]:25 [::]:*
LISTEN 0 100 [::]:587 [::]:*
"""
    with patch.object(helper.subprocess, "run", side_effect=[_proc("true\n"), _proc(ss_output)]):
        status = json.loads(helper.dispatch({"action": "service-status", "args": []}))

    assert status == {
        "mailserver": True,
        "smtp25": True,
        "submission587": True,
        "smtps465": True,
        "imap993": True,
    }


def test_service_status_does_not_match_port_prefixes():
    ss_output = "LISTEN 0 100 0.0.0:2587 0.0.0.0:*\nLISTEN 0 100 0.0.0:2465 0.0.0.0:*\n"
    with patch.object(helper.subprocess, "run", side_effect=[_proc("true\n"), _proc(ss_output)]):
        status = json.loads(helper.dispatch({"action": "service-status", "args": []}))

    assert status["smtp25"] is False
    assert status["submission587"] is False
    assert status["smtps465"] is False
    assert status["imap993"] is False
