# mail-server

Git-managed administration tooling for the existing Docker Mailserver + Roundcube deployment serving `cn2.io` and `mv3.cn`.

## Production architecture

- Docker Mailserver container: `mailserver`
- Roundcube: existing webmail, unchanged
- Admin UI: Flask + Gunicorn as dedicated `mailadmin`, loopback-only on `127.0.0.1:8089`
- Nginx exposes the UI only at `https://mail.mv3.cn/admin/`
- The web process has no Docker-group membership and no direct Docker access
- A root-owned `/usr/local/sbin/dms-admin-helper` is the only sudo target and accepts a fixed action set
- Managed mailbox domains are restricted to `cn2.io` and `mv3.cn`
- DMS config is backed up before mutations

## Security boundaries

Never commit mailbox passwords, production environment files, account databases, DKIM/TLS private keys, Certbot credentials, Roundcube data, or mail state.

The admin service requires `ADMIN_SECRET_KEY` and `ADMIN_PASSWORD_HASH`. The administrator password itself is not stored in the environment file. Login attempts are rate-limited in-process, mutations require CSRF protection, destructive mailbox deletion requires typed confirmation, and actions are written to a rotating audit log.

Mailbox passwords are passed from the web process to the helper over stdin rather than command-line arguments. The helper invokes the DMS `setup` CLI and never accepts arbitrary shell commands.

## Development

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r admin/requirements-dev.txt
ruff check admin tests
pytest -q
python -m compileall -q admin
python -m py_compile deploy/dms-admin-helper.py
```

GitHub Actions runs lint, tests and compilation for pull requests and pushes to `main`.

## Production deployment

Deployment remains manual so GitHub Actions does not receive SSH/root credentials for the mail host. Install the helper root-owned and mode 0755, install the sudoers rule with mode 0440, create the unprivileged `mailadmin` account and audit-log directory, install the systemd unit, then add the Nginx location after local health and helper tests pass.

Do not replace or restart the existing DMS/Roundcube compose stack merely to deploy the administrator UI.
