from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import shutil
import time
from collections import defaultdict, deque
from functools import wraps
from logging.handlers import RotatingFileHandler

from dms import DMSClient, DMSError
from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash


class PrefixMiddleware:
    def __init__(self, app, prefix: str):
        self.app = app
        self.prefix = prefix.rstrip("/")

    def __call__(self, environ, start_response):
        environ["SCRIPT_NAME"] = self.prefix
        return self.app(environ, start_response)


def create_app() -> Flask:
    app = Flask(__name__)
    secret = os.environ.get("ADMIN_SECRET_KEY")
    password_hash = os.environ.get("ADMIN_PASSWORD_HASH")
    if not secret or not password_hash:
        raise RuntimeError("ADMIN_SECRET_KEY and ADMIN_PASSWORD_HASH are required")

    prefix = os.environ.get("ADMIN_URL_PREFIX", "/admin").rstrip("/")
    allowed_domains = tuple(
        d.strip().lower()
        for d in os.environ.get("DMS_ALLOWED_DOMAINS", "cn2.io,mv3.cn").split(",")
        if d.strip()
    )
    app.secret_key = secret
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_PATH=f"{prefix}/",
        MAX_CONTENT_LENGTH=64 * 1024,
        PERMANENT_SESSION_LIFETIME=1800,
    )
    app.wsgi_app = PrefixMiddleware(app.wsgi_app, prefix)
    dms = DMSClient(allowed_domains=allowed_domains)

    audit = logging.getLogger("mail-admin-audit")
    if not audit.handlers:
        handler = RotatingFileHandler(
            os.environ.get("AUDIT_LOG", "/var/log/mail-server/audit.log"),
            maxBytes=2_000_000,
            backupCount=5,
        )
        handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        audit.addHandler(handler)
        audit.setLevel(logging.INFO)

    failures: dict[str, deque[float]] = defaultdict(deque)

    def client_key() -> str:
        value = request.remote_addr or "unknown"
        return hashlib.sha256(value.encode()).hexdigest()[:16]

    def audit_event(action: str, target: str = "", result: str = "ok") -> None:
        audit.info(
            "ip=%s action=%s target=%r result=%s",
            client_key(),
            action,
            target,
            result,
        )

    def login_required(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not session.get("admin"):
                return redirect(url_for("login"))
            return fn(*args, **kwargs)

        return wrapped

    def csrf_token() -> str:
        token = session.get("csrf")
        if not token:
            token = secrets.token_urlsafe(32)
            session["csrf"] = token
        return token

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def verify_request():
        if request.method == "POST":
            expected = session.get("csrf", "")
            supplied = request.form.get("_csrf", "")
            if not expected or not hmac.compare_digest(expected, supplied):
                abort(400)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            key, now = client_key(), time.monotonic()
            bucket = failures[key]
            while bucket and now - bucket[0] > 900:
                bucket.popleft()
            if len(bucket) >= 5:
                audit_event("login", result="rate-limited")
                abort(429)
            if check_password_hash(password_hash, request.form.get("password", "")):
                failures.pop(key, None)
                session.clear()
                session["admin"] = True
                session["csrf"] = secrets.token_urlsafe(32)
                session.permanent = True
                audit_event("login")
                return redirect(url_for("index"))
            bucket.append(now)
            audit_event("login", result="failed")
            flash("管理员密码错误", "error")
        return render_template("login.html")

    @app.post("/logout")
    @login_required
    def logout():
        audit_event("logout")
        session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    @login_required
    def index():
        try:
            accounts = dms.list_accounts()
            aliases = dms.list_aliases()
            account_rows = dms.account_rows_from_output(accounts)
            alias_rows = dms.alias_rows_from_output(aliases)
            service_status = dms.service_status()
            restrictions = dms.restrictions()
            disk = shutil.disk_usage("/")
            disk_status = {"used": disk.used, "total": disk.total, "percent": round(disk.used * 100 / disk.total)}
            error = None
        except DMSError:
            accounts, aliases, account_rows, alias_rows = "", "", [], []
            service_status, restrictions, disk_status = {}, {"send": "", "receive": ""}, {}
            error = "无法读取邮件服务器状态"
        return render_template(
            "index.html",
            accounts=accounts,
            aliases=aliases,
            account_rows=account_rows,
            alias_rows=alias_rows,
            error=error,
            domains=allowed_domains,
            service_status=service_status,
            restrictions=restrictions,
            disk_status=disk_status,
        )

    def mutate(action: str, target: str, fn):
        try:
            fn()
            audit_event(action, target)
            flash("操作已完成", "ok")
        except (ValueError, DMSError) as exc:
            audit_event(action, target, "failed")
            flash(str(exc), "error")
        return redirect(url_for("index"))

    @app.post("/accounts")
    @login_required
    def add_account():
        email = request.form.get("email", "")
        return mutate(
            "account-add",
            email,
            lambda: dms.add_account(email, request.form.get("password", "")),
        )

    @app.get("/audit")
    @login_required
    def audit_log():
        path = os.environ.get("AUDIT_LOG", "/var/log/mail-server/audit.log")
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                lines = list(deque(handle, maxlen=200))
        except OSError:
            lines = []
        return {"lines": [line.rstrip() for line in reversed(lines)]}

    @app.post("/accounts/password")
    @login_required
    def update_password():
        email = request.form.get("email", "")
        return mutate(
            "password-update",
            email,
            lambda: dms.update_password(email, request.form.get("password", "")),
        )

    @app.post("/accounts/delete")
    @login_required
    def delete_account():
        email = request.form.get("email", "").strip().lower()
        if request.form.get("confirm", "").strip().lower() != email:
            flash("删除确认必须完整输入邮箱地址", "error")
            return redirect(url_for("index"))
        return mutate("account-delete", email, lambda: dms.delete_account(email))

    @app.post("/aliases")
    @login_required
    def add_alias():
        alias = request.form.get("alias", "")
        recipient = request.form.get("recipient", "")
        return mutate(
            "alias-add",
            f"{alias}->{recipient}",
            lambda: dms.add_alias(alias, recipient),
        )

    @app.post("/aliases/delete")
    @login_required
    def delete_alias():
        alias = request.form.get("alias", "")
        recipient = request.form.get("recipient", "")
        return mutate(
            "alias-delete",
            f"{alias}->{recipient}",
            lambda: dms.delete_alias(alias, recipient),
        )

    @app.post("/quota")
    @login_required
    def set_quota():
        email = request.form.get("email", "")
        quota = request.form.get("quota", "")
        return mutate("quota-set", email, lambda: dms.set_quota(email, quota))

    @app.post("/restrict")
    @login_required
    def restrict():
        email = request.form.get("email", "")
        direction = request.form.get("direction", "")
        enabled = request.form.get("mode", "") == "add"
        return mutate(
            "restrict",
            email,
            lambda: dms.restrict(email, direction, enabled),
        )

    return app


app = create_app()
