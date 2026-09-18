#!/usr/bin/python3
"""Narrow privileged bridge between the unprivileged web UI and DMS setup CLI."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

CONTAINER = "mailserver"
CONFIG_DIR = Path("/opt/mail-cn2/docker-data/dms/config")
BACKUP_DIR = Path("/var/backups/dms-admin")
ALLOWED_DOMAINS = {"cn2.io", "mv3.cn"}
EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
QUOTA_RE = re.compile(r"\d+[KMGTP]?")


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(2)


def email(value: str) -> str:
    value = value.strip().lower()
    if not EMAIL_RE.fullmatch(value) or value.rsplit("@", 1)[1] not in ALLOWED_DOMAINS:
        fail("invalid email")
    return value


def backup() -> None:
    if not CONFIG_DIR.is_dir():
        fail("DMS config directory missing")
    BACKUP_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = BACKUP_DIR / f"config-{stamp}"
    shutil.copytree(CONFIG_DIR, target)
    backups = sorted(BACKUP_DIR.glob("config-*"), reverse=True)
    for old in backups[20:]:
        shutil.rmtree(old)


def run(*args: str, stdin: str | None = None) -> None:
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
        print(proc.stderr or proc.stdout or "DMS command failed", file=sys.stderr)
        raise SystemExit(proc.returncode)
    print(proc.stdout, end="")


def password_from_stdin() -> str:
    value = sys.stdin.read(4096).rstrip("\r\n")
    if len(value) < 12 or "\n" in value or "\r" in value:
        fail("invalid password")
    return value


def main() -> None:
    if os.geteuid() != 0:
        fail("helper must run as root")
    if len(sys.argv) < 2:
        fail("missing action")
    action, args = sys.argv[1], sys.argv[2:]

    if action == "list-accounts" and not args:
        run("email", "list")
    elif action == "list-aliases" and not args:
        run("alias", "list")
    elif action in {"add-account", "update-password"} and len(args) == 1:
        address = email(args[0])
        password = password_from_stdin()
        backup()
        # DMS prompts for the password twice when it is omitted from argv.
        run("email", "add" if action == "add-account" else "update", address, stdin=f"{password}\n{password}\n")
    elif action == "delete-account" and len(args) == 1:
        backup()
        run("email", "del", email(args[0]))
    elif action in {"add-alias", "delete-alias"} and len(args) == 2:
        alias, recipient = email(args[0]), email(args[1])
        backup()
        run("alias", "add" if action == "add-alias" else "del", alias, recipient)
    elif action == "set-quota" and len(args) == 2:
        address, quota = email(args[0]), args[1].upper()
        if not QUOTA_RE.fullmatch(quota):
            fail("invalid quota")
        backup()
        run("quota", "set", address, quota)
    elif action == "restrict" and len(args) == 3:
        mode, direction, address = args[0], args[1], email(args[2])
        if mode not in {"add", "del"} or direction not in {"send", "receive"}:
            fail("invalid restriction")
        backup()
        run("email", "restrict", mode, direction, address)
    else:
        fail("unsupported action or arguments")


if __name__ == "__main__":
    main()
