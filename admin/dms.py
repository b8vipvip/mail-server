from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass

EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


class DMSError(RuntimeError):
    pass


@dataclass
class DMSClient:
    container: str = "mailserver"
    timeout: int = 20

    def _validate_email(self, value: str) -> str:
        value = value.strip()
        if not EMAIL_RE.fullmatch(value):
            raise ValueError("Invalid email address")
        return value

    def _run(self, *args: str) -> str:
        cmd = ["docker", "exec", self.container, "setup", *args]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DMSError(str(exc)) from exc
        if result.returncode != 0:
            raise DMSError((result.stderr or result.stdout or "DMS command failed").strip())
        return result.stdout.strip()

    def list_accounts(self) -> str:
        return self._run("email", "list")

    def add_account(self, email: str, password: str) -> str:
        email = self._validate_email(email)
        if len(password) < 12:
            raise ValueError("Password must be at least 12 characters")
        return self._run("email", "add", email, password)

    def update_password(self, email: str, password: str) -> str:
        email = self._validate_email(email)
        if len(password) < 12:
            raise ValueError("Password must be at least 12 characters")
        return self._run("email", "update", email, password)

    def delete_account(self, email: str) -> str:
        return self._run("email", "del", self._validate_email(email))

    def list_aliases(self) -> str:
        return self._run("alias", "list")

    def add_alias(self, alias: str, recipient: str) -> str:
        return self._run("alias", "add", self._validate_email(alias), self._validate_email(recipient))

    def delete_alias(self, alias: str, recipient: str) -> str:
        return self._run("alias", "del", self._validate_email(alias), self._validate_email(recipient))

    def set_quota(self, email: str, quota: str) -> str:
        email = self._validate_email(email)
        if not re.fullmatch(r"\d+[KMGTP]?", quota.upper()):
            raise ValueError("Invalid quota")
        return self._run("quota", "set", email, quota.upper())
