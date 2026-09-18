#!/usr/bin/python3
"""Root-only local broker for a fixed set of Docker Mailserver operations."""

from __future__ import annotations

import grp
import json
import os
import re
import shutil
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path

CONTAINER = "mailserver"
SOCKET_PATH = Path("/run/dms-admin/helper.sock")
CONFIG_DIR = Path("/opt/mail-cn2/docker-data/dms/config")
BACKUP_DIR = Path("/var/backups/dms-admin")
HELPER_LOG = Path("/var/log/mail-server/helper.log")
ALLOWED_DOMAINS = {"cn2.io", "mv3.cn"}
ALLOWED_ACTIONS = {
    "list-accounts",
    "add-account",
    "update-password",
    "delete-account",
    "list-aliases",
    "add-alias",
    "delete-alias",
    "set-quota",
    "restrict",
    "service-status",
    "list-restrictions",
}
EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
QUOTA_RE = re.compile(r"\d+[KMGTP]?")


class RequestError(ValueError):
    pass


def validate_email(value: object) -> str:
    if not isinstance(value, str):
        raise RequestError("invalid email")
    value = value.strip().lower()
    if not EMAIL_RE.fullmatch(value) or value.rsplit("@", 1)[1] not in ALLOWED_DOMAINS:
        raise RequestError("invalid email")
    return value


def backup() -> None:
    if not CONFIG_DIR.is_dir():
        raise RequestError("DMS config directory missing")
    BACKUP_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    target = BACKUP_DIR / f"config-{stamp}"
    shutil.copytree(CONFIG_DIR, target)
    for old in sorted(BACKUP_DIR.glob("config-*"), reverse=True)[20:]:
        shutil.rmtree(old)


def run_dms(*args: str, stdin: str | None = None) -> str:
    cmd = ["/usr/bin/docker", "exec"]
    if stdin is not None:
        cmd.append("-i")
    cmd.extend([CONTAINER, "setup", *args])
    proc = subprocess.run(
        cmd,
        input=stdin,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
    )
    if proc.returncode:
        raise RequestError("DMS command failed")
    return proc.stdout


def dispatch(request: object) -> str:
    if not isinstance(request, dict):
        raise RequestError("invalid request")
    if set(request) - {"action", "args", "secret"}:
        raise RequestError("unexpected request fields")
    action = request.get("action")
    args = request.get("args", [])
    secret = request.get("secret")
    if action not in ALLOWED_ACTIONS or not isinstance(args, list):
        raise RequestError("unsupported action")
    if not all(isinstance(item, str) and len(item) <= 320 for item in args):
        raise RequestError("invalid arguments")

    if action == "list-accounts" and not args and secret is None:
        return run_dms("email", "list")
    if action == "list-aliases" and not args and secret is None:
        return run_dms("alias", "list")
    if action == "list-restrictions" and not args and secret is None:
        send = run_dms("email", "restrict", "list", "send")
        receive = run_dms("email", "restrict", "list", "receive")
        return json.dumps({"send": send, "receive": receive})
    if action == "service-status" and not args and secret is None:
        running = subprocess.run(
            ["/usr/bin/docker", "inspect", "-f", "{{.State.Running}}", CONTAINER],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5, check=False,
        )
        listeners = subprocess.run(
            ["/usr/bin/docker", "exec", CONTAINER, "ss", "-lntH"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5, check=False,
        )
        listening = listeners.stdout if listeners.returncode == 0 else ""
        def port_open(port: int) -> bool:
            return bool(re.search(rf":{port}\\s", listening))
        status = {
            "mailserver": running.returncode == 0 and running.stdout.strip() == "true",
            "smtp25": port_open(25),
            "submission587": port_open(587),
            "smtps465": port_open(465),
            "imap993": port_open(993),
        }
        return json.dumps(status)
    if action in {"add-account", "update-password"} and len(args) == 1:
        address = validate_email(args[0])
        if not isinstance(secret, str) or len(secret) < 12 or len(secret) > 1024:
            raise RequestError("invalid password")
        if "\n" in secret or "\r" in secret:
            raise RequestError("invalid password")
        backup()
        subcommand = "add" if action == "add-account" else "update"
        return run_dms("email", subcommand, address, stdin=f"{secret}\n{secret}\n")
    if secret is not None:
        raise RequestError("unexpected secret")
    if action == "delete-account" and len(args) == 1:
        address = validate_email(args[0])
        backup()
        return run_dms("email", "del", address)
    if action in {"add-alias", "delete-alias"} and len(args) == 2:
        alias = validate_email(args[0])
        recipient = validate_email(args[1])
        backup()
        subcommand = "add" if action == "add-alias" else "del"
        return run_dms("alias", subcommand, alias, recipient)
    if action == "set-quota" and len(args) == 2:
        address = validate_email(args[0])
        quota = args[1].upper()
        if not QUOTA_RE.fullmatch(quota):
            raise RequestError("invalid quota")
        backup()
        return run_dms("quota", "set", address, quota)
    if action == "restrict" and len(args) == 3:
        mode, direction, raw_address = args
        address = validate_email(raw_address)
        if mode not in {"add", "del"} or direction not in {"send", "receive"}:
            raise RequestError("invalid restriction")
        backup()
        return run_dms("email", "restrict", mode, direction, address)
    raise RequestError("unsupported action or arguments")


def helper_log(message: str) -> None:
    HELPER_LOG.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    safe = message.replace("\\n", " ")[:1000]
    with HELPER_LOG.open("a", encoding="utf-8") as handle:
        handle.write(f"{datetime.now(timezone.utc).isoformat()} level=ERROR component=helper {safe}\\n")


def handle(conn: socket.socket) -> None:
    data = bytearray()
    while True:
        chunk = conn.recv(65536)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > 65536:
            raise RequestError("request too large")
    request = json.loads(data)
    output = dispatch(request)
    conn.sendall(json.dumps({"ok": True, "output": output}).encode())


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("helper server must run as root")
    SOCKET_PATH.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    if SOCKET_PATH.exists() or SOCKET_PATH.is_socket():
        SOCKET_PATH.unlink()
    old_umask = os.umask(0o007)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(SOCKET_PATH))
            group = os.environ.get("MAILADMIN_GROUP", "mailadmin")
            os.chown(SOCKET_PATH, 0, grp.getgrnam(group).gr_gid)
            os.chmod(SOCKET_PATH, 0o660)
            server.listen(16)
            while True:
                conn, _ = server.accept()
                with conn:
                    try:
                        handle(conn)
                    except (RequestError, json.JSONDecodeError, OSError, subprocess.TimeoutExpired) as exc:
                        action = "unknown"
                        try:
                            if isinstance(locals().get("request"), dict):
                                action = str(locals()["request"].get("action", "unknown"))
                        except Exception:
                            pass
                        helper_log(f"action={action} error={type(exc).__name__}: {exc}")
                        try:
                            conn.sendall(json.dumps({"ok": False}).encode())
                        except OSError:
                            pass
    finally:
        os.umask(old_umask)
        SOCKET_PATH.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
