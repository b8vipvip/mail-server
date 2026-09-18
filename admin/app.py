from __future__ import annotations

import hmac
import os
import secrets
from functools import wraps

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


def create_app() -> Flask:
    app = Flask(__name__)
    secret = os.environ.get("ADMIN_SECRET_KEY")
    admin_password = os.environ.get("ADMIN_PASSWORD")
    if not secret or not admin_password:
        raise RuntimeError("ADMIN_SECRET_KEY and ADMIN_PASSWORD are required")

    app.secret_key = secret
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_SAMESITE="Strict",
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    dms = DMSClient(container=os.environ.get("DMS_CONTAINER", "mailserver"))

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
    def verify_csrf():
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
            if hmac.compare_digest(request.form.get("password", ""), admin_password):
                session.clear()
                session["admin"] = True
                session["csrf"] = secrets.token_urlsafe(32)
                return redirect(url_for("index"))
            flash("管理员密码错误", "error")
        return render_template("login.html")

    @app.post("/logout")
    @login_required
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    @login_required
    def index():
        try:
            accounts = dms.list_accounts()
            aliases = dms.list_aliases()
            error = None
        except DMSError as exc:
            accounts, aliases, error = "", "", str(exc)
        return render_template("index.html", accounts=accounts, aliases=aliases, error=error)

    @app.post("/accounts")
    @login_required
    def add_account():
        try:
            dms.add_account(request.form["email"], request.form["password"])
            flash("邮箱已创建", "ok")
        except (ValueError, DMSError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("index"))

    @app.post("/accounts/password")
    @login_required
    def update_password():
        try:
            dms.update_password(request.form["email"], request.form["password"])
            flash("密码已更新", "ok")
        except (ValueError, DMSError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("index"))

    @app.post("/accounts/delete")
    @login_required
    def delete_account():
        try:
            dms.delete_account(request.form["email"])
            flash("邮箱已删除", "ok")
        except (ValueError, DMSError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("index"))

    @app.post("/aliases")
    @login_required
    def add_alias():
        try:
            dms.add_alias(request.form["alias"], request.form["recipient"])
            flash("别名已添加", "ok")
        except (ValueError, DMSError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("index"))

    @app.post("/aliases/delete")
    @login_required
    def delete_alias():
        try:
            dms.delete_alias(request.form["alias"], request.form["recipient"])
            flash("别名已删除", "ok")
        except (ValueError, DMSError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("index"))

    @app.post("/quota")
    @login_required
    def set_quota():
        try:
            dms.set_quota(request.form["email"], request.form["quota"])
            flash("容量限制已更新", "ok")
        except (ValueError, DMSError) as exc:
            flash(str(exc), "error")
        return redirect(url_for("index"))

    return app


app = create_app()
