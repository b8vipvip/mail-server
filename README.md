# mail-server

Git-managed infrastructure and administration tooling for the existing Docker Mailserver + Roundcube deployment serving `cn2.io` and `mv3.cn`.

## Current production architecture

- Docker Mailserver container: `mailserver`
- Roundcube: existing webmail, unchanged
- Admin UI: Flask + Gunicorn, loopback-only on `127.0.0.1:8090`
- Nginx exposes the admin UI under `https://mail.mv3.cn/admin/`
- Account mutations call the official DMS `setup` CLI through argv-based `docker exec`

## Security boundaries

The repository must never contain production secrets or mail state. In particular, do not commit mailbox passwords, `postfix-accounts.cf`, DKIM private keys, TLS private keys, Certbot/Cloudflare credentials, Roundcube database contents, or mail data.

The admin service requires `ADMIN_SECRET_KEY` and `ADMIN_PASSWORD` from `/etc/mail-server/admin.env`. It listens only on loopback and is intended to be exposed through the existing TLS-enabled Nginx vhost.

## Development

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r admin/requirements-dev.txt
ruff check admin tests
pytest -q
```

GitHub Actions runs lint, tests and Python bytecode compilation for pull requests and pushes to `main`. Workflow concurrency cancels superseded runs for the same ref.

## Production deployment

Deployment is intentionally manual for v1 so GitHub Actions does not receive SSH/root credentials for the mail host. After CI passes and the PR is merged, the server pulls the tagged/merged commit, installs dependencies into a venv, installs `deploy/dms-admin.service`, creates the local secret environment file, and adds `deploy/nginx-admin.location.conf` to the existing mail vhost.

Do not replace the existing DMS/Roundcube compose stack during the admin v1 deployment.
