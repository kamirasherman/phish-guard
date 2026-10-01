# PhishGuard Landing Page Integration Notes

## Source packages

This package integrates the Flask-based phishing-awareness trainer with the visual landing experience supplied in `PhishGuard_Group_Demo.zip`.

## Integration approach

The group demo was originally implemented as a Next.js/Vinext application. Its public awareness page and campaign-reveal design were ported into Flask/Jinja templates and static CSS. This avoids running a separate Node.js server and keeps the trainer's existing `Quick_Start.bat` workflow intact.

## Routes

- `/` — public PhishGuard awareness landing page
- `/demo/reveal` — standalone awareness-test reveal from the group demo
- `/login` — administrator login
- `/dashboard` and `/admin` — authenticated campaign dashboard
- `/campaigns/...` — existing campaign management workflow
- `/quiz-template` — authenticated download of the five-question JSON starter quiz
- `/system-tests` — Administrator-only automated test-suite status and output
- `/system-tests/run` — CSRF-protected start action for the fixed packaged test command
- `/t/<token>` — individualized tracked click destination; activates the Rickroll reveal and training-video flow
- `/t/<token>/lesson` — individualized lesson/quiz page shown after the reveal training video
- `/t/<token>/quiz` — individualized quiz scoring and completion endpoint

## Preserved application behavior

- Preview mode can accept syntactically valid email domains. Live SMTP delivery requires an explicit authorized-domain allowlist.
- SMTP remains disabled by default; dispatch creates `.eml` previews.
- Recipient tokens remain hashed in the database.
- Campaign messages cannot contain arbitrary external links or HTML anchors.
- Uploaded failure-page media remains limited to approved image/video types.
- Delivery, click, and completion events continue to use the existing SQLite data model.
- Campaign quizzes and quiz attempts use related SQLite tables with cascade deletion.

## Additional corrections

- The training completion form now sends and server-validates an explicit acknowledgment value.
- The Content Security Policy keeps training media self-hosted; the standalone reveal uses the bundled local MP4 and does not require an external iframe.
- The admin header and login page now link back to the public awareness landing page.
- The Windows launcher identifies the build as `Landing Integrated + RBAC + Audit + SMTP + PB-21 + Training Quiz + Persistent Dispatch + HTTPS 2026.09.02`.
- A five-question quiz aligned to the supplied Cyber Awareness MP4 is included. Campaign Managers and Administrators can securely upload or replace it from the campaign page.
- The Administrator SMTP page retains the Google Workspace/Gmail sender preset and can explicitly add `gmail.com` to the live-delivery recipient allowlist for an authorized simulation. This does not bypass the existing public-HTTPS or SMTP-verification preflight.
- The stale completion-page test assertion now checks the stable confirmation sentence because the styled heading separates “Training” and “complete” with HTML markup.
- Administrators can start the packaged Windows test suite from **Run tests**. The fixed command runs in the background with isolated runtime paths, live SMTP disabled, one-run-at-a-time protection, bounded output, a ten-minute timeout, and start/completion audit events.

## Deployment note

The standalone `/demo/reveal` page uses a bundled local MP4 Rickroll reveal. The HTML5 player fills the reserved video box, loops continuously, requests autoplay with audio enabled at full volume, and provides a start button only when a browser blocks sound-on autoplay. Individualized campaign training pages continue to use administrator-supplied local image/video media when provided.

### 2026-09-05 — Default training-domain identity
- Added administrator-configurable `DEFAULT_TRAINING_DOMAIN` with reserved default `training.example.org`.
- Campaign Designer now records the approved live sender and generates a randomized simulation alias under the configured training domain.
- Live SMTP delivery keeps the authenticated sender address intact while using the simulation alias as the display identity.
- Campaign detail shows both identities for auditability.
- Custom training domains require an administrator confirmation that the organization controls or is authorized to use the domain.
