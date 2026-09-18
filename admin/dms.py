from __future__ import annotations

import re
import subprocess
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
    helper: str = "/usr/bin/sudo"
    helper_program: str = "/usr/local/sbin/dms-admin-helper"
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
        cmd = [self.helper, "-n", self.helper_program, action, *args]
        try:
            result = subprocess.run(
                cmd,
                input=secret,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
                env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DMSError("Mail administrator helper is unavailable") from exc
        if result.returncode != 0:
            raise DMSError("Mail operation failed")
        return result.stdout.strip()

    def list_accounts(self) -> str:
        return self._run("list-accounts")

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
