from __future__ import annotations

import json
import re
import socket
from dataclasses import dataclass

EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
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
}


class DMSError(RuntimeError):
    pass


@dataclass
class DMSClient:
    socket_path: str = "/run/dms-admin/helper.sock"
    timeout: int = 25
    allowed_domains: tuple[str, ...] = ("cn2.io", "mv3.cn")

    def _validate_email(self, value: str) -> str:
        value = value.strip().lower()
        if not EMAIL_RE.fullmatch(value):
            raise ValueError("Invalid email address")
        domain = value.rsplit("@", 1)[1]
        if domain not in self.allowed_domains:
            raise ValueError("Domain is not managed by this administrator")
        return value

    def _run(self, action: str, *args: str, secret: str | None = None) -> str:
        if action not in ALLOWED_ACTIONS:
            raise ValueError("Unsupported administrator action")
        request = {"action": action, "args": list(args)}
        if secret is not None:
            request["secret"] = secret
        payload = json.dumps(request, separators=(",", ":")).encode() + b"\n"
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect(self.socket_path)
                sock.sendall(payload)
                sock.shutdown(socket.SHUT_WR)
                chunks = []
                total = 0
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > 1024 * 1024:
                        raise DMSError("Mail administrator helper returned too much data")
                    chunks.append(chunk)
        except (OSError, TimeoutError) as exc:
            raise DMSError("Mail administrator helper is unavailable") from exc
        try:
            response = json.loads(b"".join(chunks))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise DMSError("Mail administrator helper returned an invalid response") from exc
        if not response.get("ok"):
            raise DMSError("Mail operation failed")
        return str(response.get("output", "")).strip()

    def list_accounts(self) -> str:
        return self._run("list-accounts")

    def account_rows(self) -> list[dict[str, str]]:
        return self.account_rows_from_output(self.list_accounts())

    def account_rows_from_output(self, output: str) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        current: dict[str, str] | None = None
        account_re = re.compile(
            r"^\*\s+(\S+@\S+)\s+\(\s*(.*?)\s*/\s*(.*?)\s*\)\s*\[(.*?)\]\s*$"
        )
        alias_re = re.compile(r"^\[\s*aliases\s*->\s*(.*?)\s*\]$")

        for raw_line in output.splitlines():
            line = raw_line.strip()
            match = account_re.match(line)
            if match:
                current = {
                    "email": match.group(1),
                    "used": match.group(2),
                    "quota": match.group(3),
                    "usage": match.group(4),
                    "aliases": "",
                }
                rows.append(current)
                continue
            alias_match = alias_re.match(line)
            if alias_match and current is not None:
                current["aliases"] = alias_match.group(1).strip()

        return rows

    def add_account(self, email: str, password: str) -> str:
        email = self._validate_email(email)
        if len(password) < 12:
            raise ValueError("Password must be at least 12 characters")
        return self._run("add-account", email, secret=password)

    def update_password(self, email: str, password: str) -> str:
        email = self._validate_email(email)
        if len(password) < 12:
            raise ValueError("Password must be at least 12 characters")
        return self._run("update-password", email, secret=password)

    def delete_account(self, email: str) -> str:
        return self._run("delete-account", self._validate_email(email))

    def list_aliases(self) -> str:
        return self._run("list-aliases")

    def alias_rows(self) -> list[dict[str, str]]:
        return self.alias_rows_from_output(self.list_aliases())

    def alias_rows_from_output(self, output: str) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line.startswith("* "):
                continue
            parts = line[2:].split()
            if len(parts) >= 2:
                rows.append({"alias": parts[0], "recipient": parts[1]})
        return rows

    def add_alias(self, alias: str, recipient: str) -> str:
        return self._run(
            "add-alias", self._validate_email(alias), self._validate_email(recipient)
        )

    def delete_alias(self, alias: str, recipient: str) -> str:
        return self._run(
            "delete-alias", self._validate_email(alias), self._validate_email(recipient)
        )

    def set_quota(self, email: str, quota: str) -> str:
        email = self._validate_email(email)
        quota = quota.upper()
        if not re.fullmatch(r"\d+[KMGTP]?", quota):
            raise ValueError("Invalid quota")
        return self._run("set-quota", email, quota)

    def restrict(self, email: str, direction: str, enabled: bool) -> str:
        email = self._validate_email(email)
        if direction not in {"send", "receive"}:
            raise ValueError("Invalid restriction direction")
        return self._run("restrict", "add" if enabled else "del", direction, email)
