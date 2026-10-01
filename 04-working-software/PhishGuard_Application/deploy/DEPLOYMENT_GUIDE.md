# PhishGuard single-server deployment

This deployment profile runs one PhishGuard organization on one Linux server. Caddy terminates HTTPS and renews the public certificate automatically. The application, SMTP settings, audit log, media, recipients, quiz results, and persistent dispatch queue live in the `phishguard_data` Docker volume.

## Prerequisites

- Written authorization for the simulation, recipient population, sender, dates, and client domains.
- A Linux server with Docker Engine and the Docker Compose plugin.
- A dedicated DNS name whose A/AAAA record points to the server.
- Inbound TCP 80 and 443 open to Caddy, and approved outbound SMTP connectivity.
- A dedicated approved training mailbox or relay credential. Confirm provider quotas before changing the default 60-message-per-minute rate.

## First deployment

1. Extract the build into a permanent directory on the server.
2. Copy `.env.production.example` to `.env.production`.
3. Replace `PHISHGUARD_DOMAIN`, `BASE_URL`, `SECRET_KEY`, `ADMIN_PASSWORD`, sender identity, organization name, and the authorized client-domain allowlist. `BASE_URL` must be `https://` plus the same public domain.
4. Keep `ENABLE_SMTP=false` for the initial start.
5. Run `docker compose config` and review the resolved configuration. Never paste its output into tickets because it may contain credentials.
6. Run `docker compose up -d --build`.
7. Check `docker compose ps`, then open `https://<PHISHGUARD_DOMAIN>/health` and `/ready`.
8. Sign in, change or create named Administrator accounts, configure the exact recipient domains, and upload the training media and five-question quiz.
9. In **SMTP settings**, enter the dedicated mailbox credential and the real HTTPS training URL. Save and run the connection test. Send the optional harmless test only to an authorized address.
10. Enable live delivery only after readiness shows no issues. Start with a small internal pilot, verify delivery and training completion, then queue the approved client campaign.

## Real-time and restart behavior

Dispatch creates a persistent job and returns immediately. One background worker checkpoints each recipient as sent or failed. The campaign page polls aggregate status every 2.5 seconds. A process restart returns an interrupted job and any in-progress recipient to the queue; already-sent recipients in that job are not sent again.

The worker uses one SMTP connection per job and applies `DISPATCH_RATE_PER_MINUTE`. Only one application container should run with this SQLite profile. Do not scale the `app` service above one replica. Multi-server operation requires a shared production database and distributed queue and is outside this build profile.

## Backups

Create an online-consistent backup while the application is running:

```bash
mkdir -p backups
docker compose exec -T app python scripts/backup_instance.py /backups
```

The resulting archive includes the SQLite database, audit log, SMTP settings, allowlist, uploaded media, and preview outbox when present. It can contain SMTP credentials, recipient information, and training results. Encrypt it, restrict access, apply the approved retention period, and store a copy outside the server.

For restoration, stop the stack, preserve the current volume as a rollback copy, and restore the archive contents into `/app/instance` using an approved change procedure. Validate ownership, start one app replica, then check `/ready` before reopening access. Practice this procedure on a non-production server first.

## Updates

1. Take and verify a backup.
2. Preserve `.env.production` and the Docker volumes.
3. Replace application files with the approved build.
4. Run `docker compose up -d --build`.
5. Check `/ready`, sign in, review the audit log, and run the packaged tests.

Schema creation and additive migrations run at startup. Settings and campaign data remain in the persistent volume rather than the container image.

## Operating guardrails

- Keep the exact client allowlist; never use `*` for live SMTP.
- Keep Caddy ports 80/443 public and do not publish application port 8000.
- Protect `.env.production`, the Docker socket, backups, and the persistent volume.
- Review SPF, DKIM, DMARC, sender alignment, Gmail/Workspace limits, bounce handling, and help-desk escalation with the mail administrator.
- Use a dedicated training domain and mailbox; do not request or collect client credentials.
- Monitor `docker compose logs app caddy`, the in-app audit log, and campaign status during a release.
- Delete campaign data under the approved retention schedule.

## Large training-video uploads

PhishGuard does not impose an application-level size cap on MP4/WebM training videos. The packaged Waitress command is configured with a practical-maximum request-body value so Waitress's normal 1 GB default does not become the limiting factor. Ensure the deployment host has sufficient disk space and verify any external load balancer, CDN, WAF, or reverse proxy has compatible upload limits. Image uploads remain subject to the PB-21 image-size setting.
