# PhishGuard RBAC + Audit Logger v2 + SMTP — Testing Guide

## Start the application
1. Extract the full ZIP to a normal folder. Do not run it from inside the ZIP.
2. Double-click `Quick_Start.bat`.
3. On first run, the launcher creates `.venv` and installs the packages in `requirements.txt`.
4. The browser opens to a loopback address such as `http://127.0.0.1:<random-port>`.
5. Default local testing credentials are `admin` / `training-demo-only` unless environment variables override them.

## Verify the audit integration
1. Sign in successfully, then open **Audit log** in the header. Confirm a `LOGIN_SUCCESS` record exists.
2. Sign out. Confirm `LOGOUT` is recorded.
3. Enter the wrong password three times for the same username. Confirm `LOGIN_FAILED` records and `SECURITY_ALERT_BRUTE_FORCE_DETECTED` appear.
4. Attempt a fourth sign-in before five minutes pass. Confirm the request is blocked and `LOGIN_BLOCKED_LOCKOUT` appears.
5. After five minutes, sign in with the correct password and confirm the failure counter resets.

## Verify Administrator events
As Administrator, create a staff user, change a role, create a test participant, reset a staff password, create a campaign, add recipients, dispatch in preview mode, and purge a disposable campaign. Review `/audit` after each action.

Expected event names include `USER_CREATED`, `USER_ACCESS_UPDATED`, `USER_PASSWORD_RESET`, `CAMPAIGN_CREATED`, `CAMPAIGN_RECIPIENTS_UPDATED`, `CAMPAIGN_TEST_GROUP_ADDED`, `CAMPAIGN_DISPATCH_QUEUED`, `CAMPAIGN_DISPATCH_COMPLETED`, and `CAMPAIGN_PURGED`.

## Verify least privilege
- Administrator: full console plus Users & roles, Domain mode, Audit log, and Run tests.
- Campaign Manager: campaign management/dispatch; no user management, global settings, purge, or audit viewer.
- Analyst: campaign/results read-only access.
- Viewer: dashboard summary only.
- PhishGuard Test Users: no staff portal access.

## Run the automated test suite
Choose either method:

1. **In the application:** sign in as an Administrator, select **Run tests**, and press **Start automated tests**. Use **Refresh status** until the state becomes PASSED, FAILED, or ERROR. The page captures the complete result and exit code.
2. **From Windows:** double-click `Run_Tests.bat`. The script creates/reuses `.venv`, installs requirements when necessary, and executes `pytest -q`.

The in-app runner starts only one suite at a time, has a ten-minute timeout, uses isolated temporary runtime paths, and forces live SMTP off. It does not modify the active campaign database, media directory, preview outbox, saved SMTP settings, recipient-domain settings, or primary audit file. Starting and completing a run creates `SYSTEM_TEST_RUN_STARTED` and `SYSTEM_TEST_RUN_COMPLETED` events in the primary audit log; captured pytest output remains visible only on the Administrator page and resets when the application restarts.

The earlier completion regression test now checks the stable completion sentence rather than the visually split `<h1>` text. The heading intentionally renders `Training<br><em>complete.</em>`, so a byte-level search for the contiguous phrase `Training complete` was not a valid application check.

## Verify SMTP delivery controls

1. Keep live SMTP disabled while checking campaign previews.
2. Sign in as an Administrator and open **SMTP settings**.
3. Save the approved provider, sender account, public HTTPS training URL, and dedicated SMTP credential.
4. Replace wildcard Domain mode with the specifically authorized client domain.
5. Return to SMTP settings and run **Verify SMTP connection** without a recipient first.
6. If approved, enter one test address from the allowlisted client domain and repeat the verification to send the harmless configuration-test message.
7. Confirm the page reports **Ready for authorized SMTP delivery** before testing campaign dispatch.

The application blocks live campaign dispatch when the connection is unverified, the training URL is local or non-HTTPS, or the recipient-domain wildcard remains active.

## Audit file
The default persistent audit file is `instance/audit.log`. It uses one JSON object per line. The application does not intentionally log raw passwords, password hashes, training tokens, SMTP secrets, or raw IP-address fields; the audit module also redacts these key names if a caller accidentally supplies them. Request context is limited to the HTTP method, Flask endpoint, and matched route pattern. Confirm that individualized recipient tokens and query strings do not appear in audit records.

## Verify longer MP4 training media

1. Create a disposable campaign and select an MP4 longer than five minutes.
2. For MP4/WebM, no PhishGuard application-level size cap is applied. Images retain the displayed PB-21 limit (500 MB by default).
3. Upload the video, open the campaign page, and confirm playback begins and seeking works in the Administrator preview.
4. Dispatch the campaign in preview mode, open its training link, and confirm playback and seeking also work on the recipient training page.
5. If a different image limit is required, set `MAX_TRAINING_MEDIA_MB` to a value from 1 through 2048 before starting PhishGuard. This setting does not cap MP4/WebM videos.

The duration supported depends on the MP4 bitrate rather than minutes alone. The upload is written to disk in chunks, and playback uses browser byte-range requests so the full video does not need to be transferred before seeking.

## Verify PB-21 secure media validation

1. Upload a permitted media file whose extension, MIME type, and binary format agree; confirm it is accepted.
2. Rename a harmless non-media test file to `.mp4`; confirm PB-21 rejects the binary signature.
3. Submit a PNG while declaring `video/mp4`; confirm PB-21 rejects the MIME/extension mismatch.
4. Submit a deliberately truncated test image; confirm PB-21 rejects the missing format ending.
5. Temporarily set `MAX_TRAINING_MEDIA_MB=1`, restart, and confirm an image over 1 MB receives a size-limit rejection; confirm a structurally valid MP4/WebM is not rejected solely because it exceeds 1 MB.
6. Review `/audit` and confirm `MEDIA_UPLOAD_REJECTED` records contain `PB-21` and a reason but do not contain the client filename or file contents.

Use only harmless test files created for validation. Do not upload malware to test this control. PB-21 validates media format/signature and image size; MP4/WebM videos have no PhishGuard application-level size cap. Production malware scanning remains a separate recommended control.

## Verify five-question training quizzes

1. Create a disposable campaign and upload `sample_training_media/Cyber_Awareness_Phishing_Kokoro_Replaced.mp4` as the click-response media.
2. In **Training quiz**, upload `sample_quizzes/phishing_awareness_5_question_quiz.json` and confirm the page reports five questions with an 80% passing score.
3. Add a test recipient, dispatch in preview mode, and open the generated training link.
4. Confirm the video is followed by the five-question quiz and that every question requires one answer.
5. Submit fewer than four correct answers. Confirm the attempt is recorded, explanations appear, retry is required, and training is not marked complete.
6. Retry with at least four correct answers. Confirm the completion page displays the score and the campaign report displays Passed, the latest score, and the total attempt count.
7. Attempt to bypass the quiz with the legacy `/complete` endpoint. Confirm the application rejects the request while a quiz is assigned.
8. Upload a malformed JSON file, a quiz with other than five questions, or a file larger than 256 KB. Confirm it is rejected and `QUIZ_UPLOAD_REJECTED` appears in the audit log without question content.
9. Replace the quiz and confirm attempts from the earlier quiz version are removed.

The included quiz is aligned to the supplied 2:54 Cyber Awareness video. Its answer key is stored server-side and is not rendered before submission.

## Verify Gmail simulation delivery settings

1. Sign in as an Administrator and open **SMTP settings**.
2. Choose **Google Workspace / Gmail** when the approved sender account uses Gmail. Confirm the displayed preset resolves to `smtp.gmail.com`, port 587, and STARTTLS after saving.
3. Select the explicit `gmail.com` recipient authorization only when the named test recipients are covered by written simulation approval.
4. Save and confirm `gmail.com` appears in **Domain mode** without a wildcard. Existing specifically authorized domains should remain.
5. Verify the SMTP connection, optionally using one approved Gmail test address.
6. Confirm live dispatch remains blocked until the public HTTPS URL, sender settings, explicit domain list, and saved-settings verification all pass.
7. Review the audit log for `SMTP_SETTINGS_UPDATED` and `RECIPIENT_DOMAIN_ALLOWLIST_UPDATED`. Confirm it records the Gmail-domain authorization but not the SMTP password or full test-recipient address.

## Verify packaged HTTPS and SMTP defaults

1. Confirm `deployment_defaults.env` contains `BASE_URL=https://training.example.org`, `ENABLE_SMTP=false`, the Google Workspace/Gmail provider, `smtp.gmail.com`, port 587, and STARTTLS.
2. Start with `Quick_Start.bat` and confirm preview links use the selected local application URL rather than the deployment placeholder.
3. Open **SMTP settings** and confirm live delivery is disabled and the Google Workspace/Gmail server defaults are populated when no saved SMTP settings exist.
4. Enable live delivery without replacing `https://training.example.org`; confirm preflight reports that the placeholder must be replaced.
5. Replace it only with the real public HTTPS deployment URL approved for the simulation, then complete the remaining SMTP and recipient-domain checks.

## Verify persistent dispatch and live status

1. Keep preview mode active, create a disposable campaign, and add several authorized recipients.
2. Select **Generate preview messages**. Confirm the browser returns immediately with a queued-job message.
3. In **Live campaign status**, confirm processed, sent, and failed counts update and the progress bar reaches the recipient total.
4. Confirm a second dispatch is blocked while the first job is queued or running.
5. Open `instance/outbox` and confirm one `.eml` file exists for each successful preview recipient.
6. Open one training link and confirm **Clicked / failed** updates. Complete the required quiz and confirm **Training complete** updates.
7. On a disposable non-live job, stop the process while recipients remain queued, restart it, and confirm the job resumes. Do not perform this interruption test against a live client release.
8. Review the audit log for queued, completed, recovered (when applicable), or failed dispatch events. Confirm SMTP credentials and raw training tokens are absent.

Automated coverage also verifies dispatch-job persistence, duplicate-job blocking, restart recovery, and the authenticated no-cache JSON status endpoint.

## Verify the Docker HTTPS profile

Follow `deploy/DEPLOYMENT_GUIDE.md` on a non-production server first. Confirm `docker compose ps` reports both services healthy/running, Caddy serves a valid certificate for the configured DNS name, `/health` returns `ok`, and `/ready` returns `ready`. Rebuild the application container and confirm campaigns, settings, audit records, uploaded media, quizzes, and dispatch history remain in the named volume.

## Important deployment note
The supplied brute-force tracker is in memory. Restarting the application clears current failed-login counters. The audit file remains on disk. For a multi-instance production deployment, move lockout state to a shared persistence layer before relying on it as an enterprise-wide control.
