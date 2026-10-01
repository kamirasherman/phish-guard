# PhishGuard — Landing Page Integrated Trainer

A safety-bounded Flask application for authorized annual phishing-awareness exercises.

## Default training-domain simulation identity

Administrators can configure a **Default training domain** in **SMTP Settings**. New campaigns automatically generate a randomized simulation identity such as `account-a1b2c3@training.example.org`. The campaign designer also records the **Live sender email**, which must match the approved SMTP From address.

For live delivery, PhishGuard keeps the authenticated sender address in the actual `From` header and uses the randomized address as the display identity. This provides a realistic training cue without forging an arbitrary third-party sender domain. If a custom training domain is configured, the administrator must confirm that the organization controls or is authorized to use it. The packaged default `training.example.org` is a reserved example domain.


## Integrated landing experience

This build merges the **PhishGuard Group Demo** landing experience into the Python/Flask phishing-awareness trainer. Only one local server is required.

- `/` is the public PhishGuard awareness landing page.
- `/demo/reveal` is the harmless standalone awareness reveal from the group demo.
- `/login` opens the named-user sign-in page.
- `/dashboard` and `/admin` open the campaign console after authentication and enforce role-based access.
- `/users` is available only to Administrators for account and role management.
- `/system-tests` is available only to Administrators and runs the packaged automated suite with isolated test data.
- `/t/<token>` is the individualized simulated-phishing click destination. It records the click and opens the Rickroll reveal plus required training-video page. After the training video finishes, the participant continues to `/t/<token>/lesson` for the individualized lesson/quiz and completion step.

The original Next.js/Cloudflare landing page was ported to native Flask templates and static CSS so Windows users do not need Node.js or a second web server.


## New interface features

- Enter recipient email addresses in a prominent **To:** field while composing the campaign message, or add more later from the campaign page.
- Continue to import recipients with a CSV file.
- Generate editable phishing-awareness drafts from six approved workplace scenarios.
- Select basic, intermediate, or advanced training difficulty.
- Upload an educational image or video for the page shown after a simulated click.
- Update or remove campaign media after campaign creation.
- Review delivery, click, and training-completion results.
- Configure and verify SMTP delivery from an Administrator-only interface.
- Use Microsoft 365, Google Workspace/Gmail, or custom SMTP presets.
- Send an optional harmless configuration-test email before releasing a campaign.
- Start the packaged automated tests from an Administrator-only page and review the captured pass/fail output in the browser.
- Queue large campaigns without holding the browser request open, preserve per-recipient dispatch progress across restarts, and watch aggregate results update automatically.

The automated draft feature uses a local, fixed scenario library. It does not contact a generative-AI service, invent arbitrary sender identities, create credential forms, add external links, or produce attachments.


## Role-based access control (RBAC)

This build uses named user accounts and four fixed roles to support least privilege:

- **Administrator** — full access, including users and roles, recipient-domain settings, campaigns, dispatch, results, system tests, and campaign deletion.
- **Campaign Manager** — create and manage campaigns, recipients, media, and dispatch; cannot administer users, global settings, or delete campaign data.
- **Analyst** — read-only access to campaign details and recipient training results.
- **Viewer** — least-privilege access to dashboard-level campaign summaries only.

The first account is bootstrapped as `admin` (or the value of `ADMIN_USERNAME`) using the existing `ADMIN_PASSWORD`/`ADMIN_PASSWORD_HASH` configuration. Administrators can then create named users, change roles, activate/deactivate accounts, and reset passwords from **Users & roles**. The application prevents the currently signed-in Administrator from removing their own Administrator access and prevents disabling or demoting the last active Administrator.

## Built-in safeguards

- SMTP is **off by default**. Dispatch creates `.eml` preview files.
- Preview mode initially accepts syntactically valid recipient domains. Live SMTP dispatch requires a specific authorized client-domain allowlist; the wildcard is blocked.
- Live SMTP dispatch also requires a public HTTPS training URL and a connection test completed after the most recent settings change.
- Campaign copy is plain text. External links and HTML anchors are blocked.
- The application adds only its own training link.
- The sender identity is configured by the administrator and cannot be changed in the campaign interface.
- No credential forms, tracking pixels, message-open tracking, IP logging, or browser fingerprinting.
- Link tokens are stored as SHA-256 digests rather than raw values.
- Reporting is limited to delivered, clicked, and completed events.
- Uploaded media is limited to JPG, PNG, GIF, WebP, MP4, and WebM. MP4/WebM video uploads have no PhishGuard application-level size cap. Images retain the packaged 500 MB PB-21 limit, adjustable with `MAX_TRAINING_MEDIA_MB`.
- Media uploads are copied to disk in chunks rather than loaded into application memory, and video responses support HTTP byte ranges for seeking and reliable long-form playback.
- **PB-21 secure media upload validation** permits only the configured image/video types and size. It cross-checks the sanitized filename extension, browser-declared MIME type, binary format signature, and stored-file signature before publishing the media.
- Campaign Managers and Administrators can upload a bounded five-question JSON quiz. Participants must meet the configured passing score before training completion is recorded.
- Quiz results show the latest score, pass/retry status, and attempt count without collecting passwords, browser fingerprints, or open-tracking data.
- SVG and executable formats are blocked. Rejected uploads are audited without recording filenames or file contents.
- Campaign deletion removes associated recipients, events, quizzes, dispatch jobs, and uploaded media.

## Client simulation workflow

Each authorized recipient receives a unique training link. Opening the link records the simulated failure (`clicked`) and immediately presents the assigned educational message, MP4, and five-question quiz. If a quiz is assigned, completion is recorded only after the participant meets its passing score; unsuccessful attempts show explanations and allow a retry. The campaign page reports delivered, clicked/failed, quiz, and completed results.

Dispatch is restart-safe on the included single-server profile. Pressing **Send campaign** creates a persistent queue record and returns immediately. The worker checkpoints each recipient as sent or failed, prevents a second dispatch while the campaign has an active job, and resumes unprocessed work after a process restart. Already-sent recipients in the interrupted job are not resent. The live status panel polls aggregate counts every 2.5 seconds without returning recipient addresses.

## Quick start

### Windows one-click launcher

1. Extract the entire ZIP to a permanent folder. Do not run the application from inside the ZIP.
2. Double-click `Quick_Start.bat`.
3. The launcher begins in preview mode. The browser opens the public PhishGuard landing page; choose **Training console** to sign in and manage campaigns.
4. The launcher creates `.venv`, installs the required packages when needed, selects an unused local port, starts the application with Waitress, and opens the resulting local address in the default browser.
5. The demonstration administrator username is `admin` unless `ADMIN_USERNAME` is set. The demonstration password is `training-demo-only` unless `ADMIN_PASSWORD` is set.
6. Keep the launcher window open. Press `CTRL+C` in that window to stop the application.

The launcher uses local-only networking and keeps SMTP disabled by default. Change the administrator password before organizational use. To send to client recipients, deploy the application at a public HTTPS URL before enabling live SMTP.

The packaged deployment defaults use `https://training.example.org` as an intentionally non-live HTTPS placeholder and the Google Workspace/Gmail SMTP preset (`smtp.gmail.com`, port 587, STARTTLS). Live delivery remains disabled. Quick Start substitutes its selected local URL so preview links work on the test computer. For deployment, copy `deployment_defaults.env` into the approved hosting configuration, replace every placeholder, set a strong secret, and then complete the in-application SMTP verification.

### Windows PowerShell (manual method)

```powershell
cd phishing_awareness_trainer
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:SECRET_KEY = "replace-with-a-long-random-value"
$env:ADMIN_USERNAME = "admin"
$env:ADMIN_PASSWORD = "replace-with-a-strong-password"
$env:ALLOW_ALL_RECIPIENT_DOMAINS = "true"
$env:ALLOWED_RECIPIENT_DOMAINS = "*"
py -m waitress --listen=127.0.0.1:5000 app:app
```

### macOS or Linux

```bash
cd phishing_awareness_trainer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="replace-with-a-long-random-value"
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="replace-with-a-strong-password"
export ALLOW_ALL_RECIPIENT_DOMAINS="true"
export ALLOWED_RECIPIENT_DOMAINS="*"
flask --app app run
```

Open the address used in your manual Waitress command (for the example above, `http://127.0.0.1:5000`), sign in, and create a campaign.

The default dispatch mode writes messages to `instance/outbox`. Open a generated `.eml` file in a mail client to test the training link.

## Real-time single-server deployment

The package includes `Dockerfile`, `compose.yaml`, `.env.production.example`, and `deploy/Caddyfile`. This profile runs one application container behind Caddy, which obtains and renews the public HTTPS certificate. The named `phishguard_data` volume persists the SQLite database, dispatch queue, SMTP settings, allowlist, audit log, media, quizzes, and results when containers are rebuilt or restarted.

Use [deploy/DEPLOYMENT_GUIDE.md](deploy/DEPLOYMENT_GUIDE.md) for the complete rollout, verification, backup, and update procedure. In outline: point a dedicated DNS name at the server, copy `.env.production.example` to `.env.production`, replace all security/domain placeholders, keep SMTP off, run `docker compose up -d --build`, verify `/health` and `/ready`, then complete the in-app SMTP test and a small authorized pilot before releasing the client campaign.

The included queue is deliberately a one-server design. Run one `app` replica only. Moving beyond one host requires a shared production database and a distributed queue; do not horizontally scale this SQLite build.

## Recipient entry

On **Create training campaign**, use the **To: recipient email addresses** field located directly above the campaign subject and message body. You can also add recipients later from the campaign detail page. Supported entry formats include:

```text
alex@yourcompany.example
jordan@yourcompany.example,Jordan
Taylor Morgan <taylor@yourcompany.example>
alex@yourcompany.example; jordan@yourcompany.example
```

Use a new line or semicolon between recipients. Preview mode can accept any syntactically valid domain. Live SMTP delivery requires each client domain to be listed explicitly under **Domain mode**.

When creating a campaign, you may select:

> **I confirm that I am authorized to test these recipients. Add the domains found in the To: field...**

The confirmation documents that the recipients are authorized for the exercise. Invalid email formats are still rejected.

### If an email is rejected

The message now identifies the cause:

- `invalid email format` means the address syntax needs correction.

The quick-start build remains in preview mode. **Generate preview messages** creates `.eml` files in `instance/outbox`; it does not send real email until authorized SMTP settings are configured.

## CSV format

```csv
email,first_name
alex@yourcompany.example,Alex
```

A campaign accepts up to 5,000 recipients.

## Failure-page media

Campaign administrators can upload an image or video that appears immediately after a recipient clicks the simulated training link.

Supported formats:

```text
.jpg .jpeg .png .gif .webp .mp4 .webm
```

MP4 and WebM training videos no longer have a PhishGuard application-level upload-size limit. PB-21 still verifies the declared type, filename extension, binary signature, and stored-file integrity. Images retain a packaged 500 MB ceiling; set `MAX_TRAINING_MEDIA_MB` from 1 through 2048 to change the image limit. The packaged Waitress launch commands raise its request-body ceiling to a practical maximum so its normal 1 GB default does not block large training videos. Available disk space, operating-system constraints, reverse proxies outside the packaged Caddy configuration, or hosting-platform limits can still impose physical/infrastructure limits.

Uploads are streamed to a temporary server-side file in 1 MB chunks and atomically promoted only after the expected byte count is written. This avoids holding a large MP4 entirely in application memory. Uploaded files receive randomized server-side names and are served with `X-Content-Type-Options: nosniff`. The media endpoints support HTTP range responses so browsers can seek within longer videos without downloading the full file first.

### PB-21 secure media validation

PB-21 applies the following checks before an upload becomes campaign content:

- The sanitized filename must be valid, no longer than 255 characters, and end in `.jpg`, `.jpeg`, `.png`, `.gif`, `.webp`, `.mp4`, or `.webm`.
- The browser-declared MIME type must match the permitted MIME type for that extension.
- JPEG, PNG, GIF, and WebP files must have the expected opening structure and complete-format ending or declared container length.
- MP4 files must contain a structurally valid `ftyp` box and an approved compatible brand.
- WebM files must contain the EBML signature and WebM document-type marker.
- MP4/WebM video size is not capped by PhishGuard. Image byte size must not exceed `MAX_TRAINING_MEDIA_MB`, which remains 500 MB by default.
- After chunked storage, the exact byte count and binary signature are verified again before the temporary file is atomically published.

These checks reduce common extension/MIME spoofing and truncated-file risks. They do not replace malware scanning or media transcoding; those remain recommended production controls.

## Five-question training quizzes

The package includes a video-aligned starter quiz at `sample_quizzes/phishing_awareness_5_question_quiz.json` and the supplied 2:54 training video at `sample_training_media/Cyber_Awareness_Phishing_Kokoro_Replaced.mp4`. The quiz covers social-engineering pressure, sender/domain mismatches, bypass requests, the Stop-Inspect-Verify-Report workflow, and early reporting.

To assign the quiz:

1. Create or open a campaign.
2. Upload the included MP4 in **Click-response media**.
3. In **Training quiz**, download or select the included JSON starter quiz and upload it.
4. Add recipients and dispatch the campaign.

Quiz uploads are limited to valid UTF-8 `.json` files no larger than 256 KB. Each quiz must contain exactly five unique multiple-choice questions, 2–5 unique choices per question, one zero-based `correct_index`, a concise explanation, and a passing score from 50 through 100. Unknown or duplicate JSON fields, malformed indexes, oversized text fields, invalid MIME declarations, and invalid file structures are rejected. Replacing or deleting a campaign quiz also removes attempts associated with the earlier quiz version.

Participants receive answer explanations after an unsuccessful attempt and may retry. A passing attempt records the existing `completed` event. Staff with results access can review the latest score, pass status, and number of attempts on the campaign page.

## Administrator SMTP setup

Do not enable sending until the exercise has written authorization, an approved recipient population, a help-desk communication plan, and a retention policy.

1. Sign in as an Administrator and open **SMTP settings**.
2. Choose Microsoft 365, Google Workspace/Gmail, or Custom SMTP.
3. Enter the approved sender identity and dedicated mailbox credentials.
   - Choose **Google Workspace / Gmail** to use the packaged `smtp.gmail.com`, port 587, STARTTLS preset for an approved Gmail sender account.
4. Enter the public HTTPS URL where recipients can reach PhishGuard.
5. Save the settings.
6. Open **Domain mode** and replace `*` with the specifically authorized client domain or domains.
7. Return to **SMTP settings** and verify the connection. Optionally send a harmless test email to an address in the authorized domain.
8. Review the Ready status before dispatching a campaign.

The SMTP password is masked in the interface, excluded from audit records, and stored in `instance/smtp_settings.json` with restrictive file permissions where the operating system supports them. Protect the application folder and use a dedicated app password or relay credential. Environment variables remain supported for initial configuration.

For an authorized simulation using personal `@gmail.com` recipients, select **Authorize gmail.com recipients** on the SMTP settings page. Saving replaces preview wildcard mode with the explicit `gmail.com` allowlist entry while retaining any other specific domains. This does not bypass SMTP verification, the public-HTTPS requirement, or written-authorization expectations. Remove `gmail.com` from **Domain mode** after the approved simulation window ends.

The placeholder `https://training.example.org` is rejected by live-delivery preflight until it is replaced with the real recipient-accessible HTTPS deployment URL.

Set these values in the environment:

```text
ENABLE_SMTP=true
BASE_URL=https://training.example.org
ALLOWED_RECIPIENT_DOMAINS=yourcompany.example
SMTP_HOST=smtp.yourcompany.example
SMTP_PORT=587
SMTP_USERNAME=...
SMTP_PASSWORD=...
SMTP_ENCRYPTION=starttls
COOKIE_SECURE=true
BACKGROUND_DISPATCH_ENABLED=true
SYNCHRONOUS_DISPATCH=false
DISPATCH_RATE_PER_MINUTE=60
```

The sender identity is Administrator-managed and cannot be changed by Campaign Managers. Changing the server, credentials, or sender invalidates the previous connection verification.

For Microsoft 365, the preset uses `smtp.office365.com`, port 587, and STARTTLS. Microsoft documents that SMTP AUTH may be disabled and recommends Modern Authentication or another supported delivery method; this preset should be used only when username/password SMTP AUTH has been explicitly approved and enabled for the designated mailbox. See [Microsoft's application email guidance](https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/how-to-set-up-a-multifunction-device-or-application-to-send-email-using-microsoft-365-or-office-365).

## Tests

```bash
pytest -q
```

On Windows, `Run_Tests.bat` remains available for direct use. An Administrator can also select **Run tests** in the application header and press **Start automated tests**. The in-app launcher invokes the same batch suite on Windows, prevents concurrent runs, captures the result, and records `SYSTEM_TEST_RUN_STARTED` and `SYSTEM_TEST_RUN_COMPLETED` audit events. It uses isolated temporary database, media, outbox, SMTP-settings, domain-settings, and audit paths; live SMTP is forced off during the run. The command and arguments are fixed and cannot be supplied through the browser.

## Production checklist

- Use the packaged Caddy HTTPS profile or an equivalently reviewed reverse proxy; do not expose application port 8000 publicly.
- Replace the default administrator password and set a persistent random `SECRET_KEY`.
- Use only recipient addresses covered by written organizational authorization.
- Replace wildcard recipient-domain mode with the specific approved client domains before enabling SMTP.
- Verify SPF, DKIM, DMARC, sender alignment, and provider sending limits with the mail administrator.
- Use a dedicated training subdomain and approved sender mailbox.
- Review templates and uploaded training content with legal, HR, security, accessibility, and labor stakeholders.
- Avoid sensitive themes involving health, payroll loss, disciplinary action, immigration, or personal emergencies.
- Document who can access results and when campaign data will be deleted.
- Add malware scanning and media transcoding before permitting broad production uploads.
- Do not use Flask's built-in development server for production.
- Back up the persistent instance volume with `scripts/backup_instance.py`; encrypt the archive because it can contain SMTP credentials and recipient results.

## Scope

This is an educational starter application, not a replacement for a security-reviewed enterprise platform. Conduct a code review, threat model, privacy review, accessibility review, and deployment hardening before organizational use.


## Build identification and port behavior

This integrated build shows **Landing Integrated + RBAC + Audit + SMTP + PB-21 + Training Quiz + Persistent Dispatch + HTTPS 2026.09.02** in the administrator page header. Its quick-start launcher selects an unused local TCP port, so an older copy already running on port 5000 cannot be mistaken for this build. Preview mode accepts syntactically valid recipient domains; live SMTP requires a specific authorized-domain allowlist.

## Default PhishGuard Test Users group

This build includes a separate **PhishGuard Test Users** group for people who are targets of authorized awareness simulations. This is not a fifth staff RBAC role. The four staff roles remain Administrator, Campaign Manager, Analyst, and Viewer.

Test users have no staff-portal permissions and cannot sign in to campaign administration. Administrators can create them from **Users & Roles** by choosing the **PhishGuard Test Users** group. A test-user password is optional because the account is a participant-directory record rather than a staff login. Campaign Managers and Administrators can add all active test users with email addresses to a campaign using **Add test-user group**. Recipient-domain authorization rules still apply.

## Audit logging and login protection

The supplied `audit_logger (2).py` module is integrated into the Flask application as `audit_logger.py`. Its JSON event structure and username-based three-failure/five-minute lockout behavior are preserved. Application-required safety and review features are retained around that core behavior. The integration provides:

- Structured JSON-lines audit records in `instance/audit.log` by default.
- Authentication auditing for successful logins, failed logins, portal-access denials, lockout blocks, and logout.
- A username-based brute-force tracker that locks an account for five minutes after three consecutive failed sign-in attempts.
- Administrator-action auditing for user creation, role/group/status changes, password resets, recipient-domain settings, campaign creation, recipient changes, test-group additions, training-media changes, dispatch, and campaign purge.
- PB-21 auditing for rejected media uploads, including the control identifier and validation reason without the filename or file contents.
- Quiz auditing for rejected uploads, quiz assignment/replacement/removal, and participant submissions. Audit metadata contains counts and scores rather than quiz answers or individualized training tokens.
- Automatic redaction of password, secret, token, and raw-IP style fields if they are accidentally supplied to the audit logger.
- Safe request context containing only the HTTP method, Flask endpoint, and matched route pattern. Raw paths and query strings are excluded so individualized training tokens are not written to the audit log.
- An Administrator-only **Audit log** page at `/audit` for reviewing recent events.

The lockout tracker is intentionally in memory, matching the supplied module design. Restarting the application clears the current failed-attempt counters. Audit records remain on disk.
