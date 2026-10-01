import re
from email import policy
from email.parser import BytesParser
from pathlib import Path

import pytest

import app as app_module
from app import create_app


@pytest.fixture()
def app(tmp_path: Path):
    return create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-secret",
            "ADMIN_PASSWORD": "test-password",
            "DATABASE": str(tmp_path / "test.sqlite"),
            "OUTBOX_DIR": str(tmp_path / "outbox"),
            "MEDIA_DIR": str(tmp_path / "media"),
            "BASE_URL": "http://localhost",
            "ALLOWED_RECIPIENT_DOMAINS": {"example.org"},
            "DOMAIN_ALLOWLIST_FILE": str(tmp_path / "allowed_domains.txt"),
            "AUDIT_LOG_FILE": str(tmp_path / "audit.log"),
            "SMTP_SETTINGS_FILE": str(tmp_path / "smtp_settings.json"),
            "ENABLE_SMTP": False,
        }
    )


@pytest.fixture()
def client(app):
    return app.test_client()


def csrf(client) -> str:
    with client.session_transaction() as sess:
        return sess["csrf_token"]


def login(client):
    client.get("/login")
    response = client.post(
        "/login",
        data={"password": "test-password", "csrf_token": csrf(client)},
        follow_redirects=True,
    )
    assert response.status_code == 200


def create_campaign(client, **overrides) -> int:
    data = {
        "csrf_token": csrf(client),
        "action": "create",
        "name": "Annual Training",
        "subject": "Review notice",
        "body": "Hello {{first_name}},\nPlease review the notice.",
        "failure_message": "Pause and review the warning signs.",
        "scenario": "account_notice",
        "difficulty": "basic",
    }
    data.update(overrides)
    response = client.post("/campaigns/new", data=data, follow_redirects=False)
    assert response.status_code == 302
    return int(response.headers["Location"].rstrip("/").split("/")[-1])


def quiz_bytes() -> bytes:
    return (
        Path(app_module.__file__).with_name("sample_quizzes")
        / "phishing_awareness_5_question_quiz.json"
    ).read_bytes()


def upload_quiz(client, campaign_id: int, content: bytes | None = None):
    return client.post(
        f"/campaigns/{campaign_id}/quiz",
        data={
            "csrf_token": csrf(client),
            "quiz_file": (
                io_bytes(content if content is not None else quiz_bytes()),
                "training-quiz.json",
                "application/json",
            ),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )


def extract_training_path(tmp_path: Path) -> str:
    eml_files = list((tmp_path / "outbox").glob("*.eml"))
    assert len(eml_files) == 1
    message = BytesParser(policy=policy.default).parsebytes(eml_files[0].read_bytes())
    html = message.get_body(preferencelist=("html",)).get_content()
    match = re.search(r'href="(http://localhost/t/[^"]+)"', html)
    assert match
    return match.group(1).replace("http://localhost", "")


def test_campaign_preview_and_training_completion(app, client, tmp_path: Path):
    login(client)
    campaign_id = create_campaign(client)

    response = client.post(
        f"/campaigns/{campaign_id}/import",
        data={
            "csrf_token": csrf(client),
            "recipients": (io_bytes(b"email,first_name\nalex@example.org,Alex\n"), "recipients.csv"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Imported or updated 1 recipient" in response.data

    response = client.post(
        f"/campaigns/{campaign_id}/dispatch",
        data={"csrf_token": csrf(client)},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"preview outbox" in response.data

    training_path = extract_training_path(tmp_path)
    response = client.get(training_path)
    assert response.status_code == 200
    assert b"This was a phishing awareness test" in response.data

    response = client.post(
        training_path + "/complete",
        data={"csrf_token": csrf(client), "acknowledged": "yes"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Your completion was recorded" in response.data


def test_dispatch_job_is_persistent_and_live_status_reports_progress(app, client):
    login(client)
    campaign_id = create_campaign(client)
    client.post(
        f"/campaigns/{campaign_id}/recipients/add",
        data={"csrf_token": csrf(client), "recipient_entries": "alex@example.org,Alex"},
    )
    response = client.post(
        f"/campaigns/{campaign_id}/dispatch",
        data={"csrf_token": csrf(client)},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Live campaign status" in response.data

    with app.app_context():
        job = app_module.get_db().execute(
            "SELECT * FROM dispatch_jobs WHERE campaign_id = ? ORDER BY id DESC LIMIT 1",
            (campaign_id,),
        ).fetchone()
        assert job["status"] == "completed"
        assert job["total_recipients"] == 1
        assert job["processed_recipients"] == 1
        assert job["sent_recipients"] == 1
        assert job["failed_recipients"] == 0

    status = client.get(f"/campaigns/{campaign_id}/status")
    assert status.status_code == 200
    payload = status.get_json()
    assert payload["campaign_status"] == "sent"
    assert payload["metrics"]["recipients"] == 1
    assert payload["metrics"]["delivered"] == 1
    assert payload["dispatch_job"]["status"] == "completed"
    assert status.headers["Cache-Control"] == "no-store"


def test_duplicate_dispatch_is_blocked_while_job_is_queued(app, client):
    app.config["SYNCHRONOUS_DISPATCH"] = False
    app.config["BACKGROUND_DISPATCH_ENABLED"] = False
    login(client)
    campaign_id = create_campaign(client)
    client.post(
        f"/campaigns/{campaign_id}/recipients/add",
        data={"csrf_token": csrf(client), "recipient_entries": "alex@example.org,Alex"},
    )
    first = client.post(
        f"/campaigns/{campaign_id}/dispatch",
        data={"csrf_token": csrf(client)},
        follow_redirects=True,
    )
    assert b"Queued 1 message" in first.data
    second = client.post(
        f"/campaigns/{campaign_id}/dispatch",
        data={"csrf_token": csrf(client)},
        follow_redirects=True,
    )
    assert b"already has a queued or running dispatch job" in second.data


def test_interrupted_dispatch_is_requeued_on_restart(app, client):
    login(client)
    campaign_id = create_campaign(client)
    client.post(
        f"/campaigns/{campaign_id}/recipients/add",
        data={"csrf_token": csrf(client), "recipient_entries": "alex@example.org,Alex"},
    )
    with app.app_context():
        db = app_module.get_db()
        recipient_id = db.execute(
            "SELECT id FROM recipients WHERE campaign_id = ?", (campaign_id,)
        ).fetchone()["id"]
        cursor = db.execute(
            """
            INSERT INTO dispatch_jobs
                (campaign_id, requested_by_user_id, mode, status, total_recipients, created_at, started_at)
            VALUES (?, 1, 'preview', 'running', 1, ?, ?)
            """,
            (campaign_id, app_module.utc_now(), app_module.utc_now()),
        )
        job_id = int(cursor.lastrowid)
        db.execute(
            "INSERT INTO dispatch_job_recipients (job_id, recipient_id, status) VALUES (?, ?, 'processing')",
            (job_id, recipient_id),
        )
        db.commit()

    app_module.recover_interrupted_dispatches(app)
    with app.app_context():
        db = app_module.get_db()
        job = db.execute("SELECT status, last_error FROM dispatch_jobs WHERE id = ?", (job_id,)).fetchone()
        item = db.execute(
            "SELECT status FROM dispatch_job_recipients WHERE job_id = ?", (job_id,)
        ).fetchone()
        assert job["status"] == "queued"
        assert "restart" in job["last_error"]
        assert item["status"] == "queued"


def test_administrator_can_view_in_app_test_runner(app, client):
    login(client)
    response = client.get("/system-tests")
    assert response.status_code == 200
    assert b"Automated system tests" in response.data
    assert b"Start automated tests" in response.data
    assert b"Live SMTP is forced off" in response.data

    runner = app.extensions["test_runner"]
    with runner["lock"]:
        runner.update(
            {
                "status": "passed",
                "started_at": "2026-09-02T19:47:41+00:00",
                "finished_at": "2026-09-02T19:47:54+00:00",
                "exit_code": 0,
                "output": "33 passed in 13.81s",
            }
        )
    response = client.get("/system-tests")
    assert response.status_code == 200
    assert b"PASSED" in response.data
    assert b"33 passed in 13.81s" in response.data


def test_in_app_test_runner_starts_one_fixed_background_job(app, client, monkeypatch):
    started = []

    class FakeThread:
        def __init__(self, *, target, args, daemon, name):
            started.append(
                {"target": target, "args": args, "daemon": daemon, "name": name}
            )

        def start(self):
            started[-1]["started"] = True

    monkeypatch.setattr(app_module.threading, "Thread", FakeThread)
    login(client)
    response = client.post(
        "/system-tests/run",
        data={"csrf_token": csrf(client)},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"automated test suite started" in response.data
    assert len(started) == 1
    assert started[0]["target"] is app_module.run_test_suite_in_background
    assert started[0]["args"][0] is app
    assert started[0]["daemon"] is True
    assert started[0]["name"] == "phishguard-system-tests"
    assert started[0]["started"] is True
    assert app.extensions["test_runner"]["status"] == "running"

    response = client.post(
        "/system-tests/run",
        data={"csrf_token": csrf(client)},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"already running" in response.data
    assert len(started) == 1


def test_in_app_test_runner_rejects_non_administrator_role(app, client):
    login(client)
    with app.app_context():
        app_module.get_db().execute(
            "UPDATE users SET role = 'campaign_manager' WHERE username = 'admin'"
        )
        app_module.get_db().commit()
    response = client.get("/system-tests")
    assert response.status_code == 403


def test_five_question_quiz_scoring_completion_and_reporting(app, client, tmp_path: Path):
    login(client)
    campaign_id = create_campaign(client)
    response = upload_quiz(client, campaign_id)
    assert response.status_code == 200
    assert b"Quiz uploaded with 5 questions" in response.data

    response = client.post(
        f"/campaigns/{campaign_id}/import",
        data={
            "csrf_token": csrf(client),
            "recipients": (io_bytes(b"email,first_name\nalex@example.org,Alex\n"), "recipients.csv"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert response.status_code == 200
    response = client.post(
        f"/campaigns/{campaign_id}/dispatch",
        data={"csrf_token": csrf(client)},
        follow_redirects=True,
    )
    assert response.status_code == 200

    training_path = extract_training_path(tmp_path)
    response = client.get(training_path)
    assert response.status_code == 200
    assert b"Identifying Email Phishing Attempts" in response.data
    assert response.data.count(b'class="quiz-question"') == 5

    bypass = client.post(
        training_path + "/complete",
        data={"csrf_token": csrf(client), "acknowledged": "yes"},
    )
    assert bypass.status_code == 400

    wrong_answers = {f"question_{index}": "3" for index in range(5)}
    wrong_answers["csrf_token"] = csrf(client)
    response = client.post(training_path + "/quiz", data=wrong_answers)
    assert response.status_code == 200
    assert b"try again" in response.data.lower()
    with app.app_context():
        completed = app_module.get_db().execute(
            "SELECT COUNT(*) AS count FROM events WHERE event_type = 'completed'"
        ).fetchone()["count"]
        assert completed == 0

    correct_answers = {
        "csrf_token": csrf(client),
        "question_0": "0",
        "question_1": "1",
        "question_2": "0",
        "question_3": "1",
        "question_4": "2",
    }
    response = client.post(training_path + "/quiz", data=correct_answers)
    assert response.status_code == 200
    assert b"score of <strong>100%</strong>" in response.data

    report = client.get(f"/campaigns/{campaign_id}")
    assert report.status_code == 200
    assert b"100%" in report.data
    assert b"Passed" in report.data
    assert b">2<" in report.data


def test_quiz_upload_rejects_invalid_question_count_and_records_audit(app, client):
    login(client)
    campaign_id = create_campaign(client)
    document = __import__("json").loads(quiz_bytes())
    document["questions"] = document["questions"][:4]
    response = upload_quiz(
        client,
        campaign_id,
        __import__("json").dumps(document).encode("utf-8"),
    )
    assert response.status_code == 200
    assert b"exactly 5 questions" in response.data
    audit_text = Path(app.config["AUDIT_LOG_FILE"]).read_text(encoding="utf-8")
    assert "QUIZ_UPLOAD_REJECTED" in audit_text
    assert "What should you do" not in audit_text


def save_test_smtp_settings(client, **overrides):
    data = {
        "csrf_token": csrf(client),
        "enabled": "yes",
        "provider": "custom",
        "host": "smtp.example.org",
        "port": "587",
        "encryption": "starttls",
        "sender_name": "Security Awareness Team",
        "sender_email": "security-training@example.org",
        "base_url": "http://localhost",
        "organization_name": "Example Organization",
        "username": "smtp-user@example.org",
        "password": "app-password-value",
        "authorization_confirmed": "yes",
    }
    data.update(overrides)
    return client.post(
        "/settings/smtp",
        data=data,
        follow_redirects=True,
    )


def test_administrator_can_save_masked_smtp_settings(app, client, tmp_path: Path):
    login(client)
    response = save_test_smtp_settings(client)
    assert response.status_code == 200
    assert b"SMTP settings were saved" in response.data
    assert b"app-password-value" not in response.data
    settings_file = tmp_path / "smtp_settings.json"
    assert settings_file.exists()
    assert app.config["SMTP_HOST"] == "smtp.example.org"
    assert app.config["ENABLE_SMTP"] is True


def test_gmail_provider_and_explicit_gmail_recipient_authorization(app, client, tmp_path: Path):
    login(client)
    app.config["ALLOWED_RECIPIENT_DOMAINS"] = {"*"}
    response = save_test_smtp_settings(
        client,
        provider="google_workspace",
        sender_email="approved.sender@gmail.com",
        username="approved.sender@gmail.com",
        authorize_gmail_recipients="yes",
    )
    assert response.status_code == 200
    assert b"gmail.com was added" in response.data
    assert app.config["SMTP_HOST"] == "smtp.gmail.com"
    assert app.config["SMTP_PORT"] == 587
    assert app.config["SMTP_ENCRYPTION"] == "starttls"
    assert app.config["ALLOWED_RECIPIENT_DOMAINS"] == {"gmail.com"}
    assert (tmp_path / "allowed_domains.txt").read_text(encoding="utf-8") == "gmail.com"
    audit_text = Path(app.config["AUDIT_LOG_FILE"]).read_text(encoding="utf-8")
    assert '"gmail_simulation_enabled": true' in audit_text
    assert '"gmail_recipient_domain_authorized": true' in audit_text


def test_safe_https_and_gmail_defaults_do_not_enable_live_delivery(tmp_path: Path, monkeypatch):
    smtp_file = tmp_path / "new-smtp-settings.json"
    monkeypatch.setenv("SMTP_SETTINGS_FILE", str(smtp_file))
    for key in (
        "BASE_URL",
        "ENABLE_SMTP",
        "SMTP_PROVIDER",
        "SMTP_HOST",
        "SMTP_PORT",
        "SMTP_ENCRYPTION",
    ):
        monkeypatch.delenv(key, raising=False)
    default_app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "default-test",
            "DATABASE": str(tmp_path / "default.sqlite"),
            "OUTBOX_DIR": str(tmp_path / "default-outbox"),
            "MEDIA_DIR": str(tmp_path / "default-media"),
            "DOMAIN_ALLOWLIST_FILE": str(tmp_path / "default-domains.txt"),
            "AUDIT_LOG_FILE": str(tmp_path / "default-audit.log"),
        }
    )
    assert default_app.config["BASE_URL"] == "https://training.example.org"
    assert default_app.config["SMTP_PROVIDER"] == "google_workspace"
    assert default_app.config["SMTP_HOST"] == "smtp.gmail.com"
    assert default_app.config["SMTP_PORT"] == 587
    assert default_app.config["SMTP_ENCRYPTION"] == "starttls"
    assert default_app.config["ENABLE_SMTP"] is False


def test_live_dispatch_is_blocked_until_smtp_is_verified(app, client):
    login(client)
    save_test_smtp_settings(client)
    campaign_id = create_campaign(client)
    client.post(
        f"/campaigns/{campaign_id}/recipients/add",
        data={"csrf_token": csrf(client), "recipient_entries": "alex@example.org,Alex"},
        follow_redirects=True,
    )
    response = client.post(
        f"/campaigns/{campaign_id}/dispatch",
        data={"csrf_token": csrf(client)},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Live delivery is not ready" in response.data


def test_smtp_verification_can_send_harmless_test_message(app, client, monkeypatch):
    class FakeSmtp:
        def __init__(self):
            self.messages = []

        def send_message(self, message):
            self.messages.append(message)

        def quit(self):
            return None

    fake_smtp = FakeSmtp()
    monkeypatch.setattr(app_module, "open_smtp_connection", lambda configured_app: fake_smtp)
    login(client)
    save_test_smtp_settings(client)
    response = client.post(
        "/settings/smtp/test",
        data={"csrf_token": csrf(client), "test_recipient": "alex@example.org"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"connection verified" in response.data
    assert len(fake_smtp.messages) == 1
    assert app.config["SMTP_VERIFIED_AT"]



def test_recipients_can_be_typed_during_campaign_creation(app, client):
    login(client)
    response = client.post(
        "/campaigns/new",
        data={
            "csrf_token": csrf(client),
            "action": "create",
            "name": "Typed Recipient Campaign",
            "subject": "Review notice",
            "body": "Hello {{first_name}}, please review the notice.",
            "failure_message": "Review the warning signs.",
            "scenario": "account_notice",
            "difficulty": "basic",
            "recipient_entries": "alex@example.org,Alex\noutsider@other.test,Pat",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Campaign created with 1 recipient" in response.data
    assert b"Rejected 1 recipient" in response.data
    assert b"alex@example.org" in response.data

    import sqlite3
    with sqlite3.connect(app.config["DATABASE"]) as db:
        rows = db.execute(
            "SELECT email, first_name FROM recipients ORDER BY email"
        ).fetchall()
    assert rows == [("alex@example.org", "Alex")]

def test_to_field_accepts_semicolons_and_display_names(app, client):
    login(client)
    response = client.post(
        "/campaigns/new",
        data={
            "csrf_token": csrf(client),
            "action": "create",
            "name": "Message Composer Recipients",
            "subject": "Review notice",
            "body": "Hello {{first_name}}, please review the notice.",
            "failure_message": "Review the warning signs.",
            "scenario": "account_notice",
            "difficulty": "basic",
            "recipient_entries": (
                "Alex Morgan <alex@example.org>; "
                "jordan@example.org,Jordan\ncasey@example.org; drew@example.org"
            ),
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Campaign created with 4 recipient" in response.data

    import sqlite3
    with sqlite3.connect(app.config["DATABASE"]) as db:
        rows = db.execute(
            "SELECT email, first_name FROM recipients ORDER BY email"
        ).fetchall()
    assert rows == [
        ("alex@example.org", "Alex Morgan"),
        ("casey@example.org", ""),
        ("drew@example.org", ""),
        ("jordan@example.org", "Jordan"),
    ]


def test_manual_recipient_entry_enforces_allowlist(app, client):
    login(client)
    campaign_id = create_campaign(client)

    response = client.post(
        f"/campaigns/{campaign_id}/recipients/add",
        data={
            "csrf_token": csrf(client),
            "recipient_entries": "alex@example.org,Alex\noutsider@other.test,Pat",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Added or updated 1 recipient" in response.data
    assert b"Rejected 1 entry" in response.data
    assert b"alex@example.org" in response.data

    import sqlite3
    with sqlite3.connect(app.config["DATABASE"]) as db:
        addresses = [row[0] for row in db.execute("SELECT email FROM recipients").fetchall()]
    assert addresses == ["alex@example.org"]


def test_safe_draft_generator_populates_copy(client):
    login(client)
    response = client.post(
        "/campaigns/new",
        data={
            "csrf_token": csrf(client),
            "action": "generate",
            "name": "Generated Campaign",
            "scenario": "shared_document",
            "difficulty": "intermediate",
            "failure_message": "Review the clues.",
        },
    )
    assert response.status_code == 200
    assert b"workplace document" in response.data.lower()
    assert b"{{first_name}}" in response.data
    assert b"safe training draft was generated" in response.data.lower()


def test_uploaded_image_is_displayed_after_click(client, tmp_path: Path):
    login(client)
    png = (
        b"\x89PNG\r\n\x1a\n"
        + b"\x00\x00\x00\rIHDR"
        + (b"\x00" * 17)
        + b"\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    response = client.post(
        "/campaigns/new",
        data={
            "csrf_token": csrf(client),
            "action": "create",
            "name": "Media Campaign",
            "subject": "Review notice",
            "body": "Hello {{first_name}}, please review.",
            "failure_message": "This image explains the warning signs.",
            "scenario": "account_notice",
            "difficulty": "basic",
            "failure_media": (io_bytes(png), "lesson.png"),
        },
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert response.status_code == 302
    campaign_id = int(response.headers["Location"].rstrip("/").split("/")[-1])

    client.post(
        f"/campaigns/{campaign_id}/recipients/add",
        data={"csrf_token": csrf(client), "recipient_entries": "alex@example.org,Alex"},
    )
    client.post(
        f"/campaigns/{campaign_id}/dispatch",
        data={"csrf_token": csrf(client)},
    )
    training_path = extract_training_path(tmp_path)

    response = client.get(training_path)
    assert response.status_code == 200
    assert b"This image explains the warning signs" in response.data
    assert (training_path + "/media").encode() in response.data

    media_response = client.get(training_path + "/media")
    assert media_response.status_code == 200
    assert media_response.mimetype == "image/png"
    assert media_response.data == png
    assert media_response.headers["X-Content-Type-Options"] == "nosniff"


def test_rejects_unsafe_media_type(client):
    login(client)
    response = client.post(
        "/campaigns/new",
        data={
            "csrf_token": csrf(client),
            "action": "create",
            "name": "Unsafe Media",
            "subject": "Review notice",
            "body": "Hello {{first_name}}, please review.",
            "failure_media": (io_bytes(b"<svg></svg>"), "lesson.svg"),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert b"Allowed media formats" in response.data


def test_pb21_rejects_declared_mime_mismatch(client):
    png = (
        b"\x89PNG\r\n\x1a\n"
        + b"\x00\x00\x00\rIHDR"
        + (b"\x00" * 17)
        + b"\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    login(client)
    response = client.post(
        "/campaigns/new",
        data={
            "csrf_token": csrf(client),
            "action": "create",
            "name": "MIME Mismatch",
            "subject": "Review notice",
            "body": "Hello {{first_name}}, please review.",
            "failure_media": (io_bytes(png), "lesson.png", "video/mp4"),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert b"PB-21 validation failed" in response.data
    assert b"declared media type" in response.data


def test_pb21_rejects_spoofed_mp4_signature(app, client):
    login(client)
    response = client.post(
        "/campaigns/new",
        data={
            "csrf_token": csrf(client),
            "action": "create",
            "name": "Spoofed Video",
            "subject": "Review notice",
            "body": "Hello {{first_name}}, please review.",
            "failure_media": (io_bytes(b"not-an-mp4-container"), "lesson.mp4", "video/mp4"),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert b"binary file signature" in response.data
    audit_text = Path(app.config["AUDIT_LOG_FILE"]).read_text(encoding="utf-8")
    assert "MEDIA_UPLOAD_REJECTED" in audit_text
    assert '"control": "PB-21"' in audit_text
    assert "lesson.mp4" not in audit_text
    assert "not-an-mp4-container" not in audit_text


def test_pb21_rejects_truncated_png(client):
    login(client)
    response = client.post(
        "/campaigns/new",
        data={
            "csrf_token": csrf(client),
            "action": "create",
            "name": "Truncated Image",
            "subject": "Review notice",
            "body": "Hello {{first_name}}, please review.",
            "failure_media": (
                io_bytes(b"\x89PNG\r\n\x1a\ntruncated"),
                "lesson.png",
                "image/png",
            ),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert b"binary file signature" in response.data


def test_accepts_mp4_above_legacy_limit_and_supports_range_playback(app, client, tmp_path: Path):
    login(client)
    legacy_limit = 20 * 1024 * 1024
    mp4_header = b"\x00\x00\x00\x18ftypmp42"
    mp4 = mp4_header + (b"\x00" * (legacy_limit + 1024 - len(mp4_header)))

    response = client.post(
        "/campaigns/new",
        data={
            "csrf_token": csrf(client),
            "action": "create",
            "name": "Long Video Campaign",
            "subject": "Review notice",
            "body": "Hello {{first_name}}, please review.",
            "failure_message": "Review the training video.",
            "scenario": "account_notice",
            "difficulty": "basic",
            "failure_media": (io_bytes(mp4), "long-training.mp4"),
        },
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert response.status_code == 302
    campaign_id = int(response.headers["Location"].rstrip("/").split("/")[-1])
    stored_files = list((tmp_path / "media").glob("*.mp4"))
    assert len(stored_files) == 1
    assert stored_files[0].stat().st_size == len(mp4)

    range_response = client.get(
        f"/campaigns/{campaign_id}/media",
        headers={"Range": "bytes=0-11"},
    )
    assert range_response.status_code == 206
    assert range_response.data == mp4_header
    assert range_response.headers["Content-Range"].startswith("bytes 0-11/")


def test_video_upload_has_no_application_size_cap(app):
    from werkzeug.datastructures import FileStorage

    app.config["MAX_TRAINING_MEDIA_MB"] = 1
    app.config["MAX_TRAINING_MEDIA_BYTES"] = 1024 * 1024
    mp4_header = b"\x00\x00\x00\x18ftypmp42"
    upload = FileStorage(
        stream=io_bytes(mp4_header + (b"\x00" * (1024 * 1024))),
        filename="large-training.mp4",
        content_type="video/mp4",
    )
    prepared = app_module.prepare_media_upload(app, upload)
    assert prepared is not None
    assert prepared[3] > 1024 * 1024


def test_image_upload_limit_remains_configurable(app):
    from werkzeug.datastructures import FileStorage

    app.config["MAX_TRAINING_MEDIA_MB"] = 1
    app.config["MAX_TRAINING_MEDIA_BYTES"] = 1024 * 1024
    # The size check occurs before signature validation, so a PNG signature is
    # sufficient to prove the image ceiling is still enforced.
    upload = FileStorage(
        stream=io_bytes(b"\x89PNG\r\n\x1a\n" + (b"\x00" * (1024 * 1024))),
        filename="too-large.png",
        content_type="image/png",
    )
    with pytest.raises(ValueError, match="image files must be 1 MB or smaller"):
        app_module.prepare_media_upload(app, upload)


def test_rejects_external_links(client):
    login(client)
    response = client.post(
        "/campaigns/new",
        data={
            "csrf_token": csrf(client),
            "action": "create",
            "name": "Unsafe copy",
            "subject": "Review notice",
            "body": "Visit https://example.com",
        },
    )
    assert response.status_code == 400
    assert b"External links" in response.data


def io_bytes(value: bytes):
    import io

    return io.BytesIO(value)



def test_authorized_domain_can_be_added_during_message_creation(app, client, tmp_path: Path):
    login(client)
    response = client.post(
        "/campaigns/new",
        data={
            "csrf_token": csrf(client),
            "action": "create",
            "name": "Authorized External Domain Test",
            "subject": "Review notice",
            "body": "Hello {{first_name}}, please review the notice.",
            "failure_message": "Review the warning signs.",
            "scenario": "account_notice",
            "difficulty": "basic",
            "recipient_entries": "Alex Tester <alex@authorized-test.net>",
            "authorize_recipient_domains": "yes",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Campaign created with 1 recipient" in response.data
    assert b"authorized-test.net" in response.data
    assert "authorized-test.net" in app.config["ALLOWED_RECIPIENT_DOMAINS"]
    assert (tmp_path / "allowed_domains.txt").read_text() == "authorized-test.net,example.org"

    campaign_id = int(response.request.path.rstrip("/").split("/")[-1])
    dispatch = client.post(
        f"/campaigns/{campaign_id}/dispatch",
        data={"csrf_token": csrf(client)},
        follow_redirects=True,
    )
    assert dispatch.status_code == 200
    assert b"preview outbox" in dispatch.data
    assert len(list((tmp_path / "outbox").glob("*.eml"))) == 1


def test_recipient_domain_settings_page_updates_allowlist(app, client, tmp_path: Path):
    login(client)
    response = client.post(
        "/settings/recipient-domains",
        data={
            "csrf_token": csrf(client),
            "domains": "college.edu; training.example",
            "authorization_confirmed": "yes",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Recipient domain allowlist saved" in response.data
    assert app.config["ALLOWED_RECIPIENT_DOMAINS"] == {"college.edu", "training.example"}
    assert (tmp_path / "allowed_domains.txt").read_text() == "college.edu,training.example"


def test_rejection_message_explains_unapproved_domain(app, client):
    login(client)
    response = client.post(
        "/campaigns/new",
        data={
            "csrf_token": csrf(client),
            "action": "create",
            "name": "Rejected Domain Explanation",
            "subject": "Review notice",
            "body": "Hello, please review the notice.",
            "failure_message": "Review the warning signs.",
            "scenario": "account_notice",
            "difficulty": "basic",
            "recipient_entries": "alex@not-approved.net",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"domain not-approved.net is not approved" in response.data


def test_all_domain_mode_accepts_unrelated_valid_domains(app, client):
    app.config["ALLOWED_RECIPIENT_DOMAINS"] = {"*"}
    login(client)
    response = client.post(
        "/campaigns/new",
        data={
            "csrf_token": csrf(client),
            "action": "create",
            "name": "All Domains Test",
            "subject": "Training review",
            "body": "Hello {{first_name}}, please review this training message.",
            "failure_message": "Review the warning signs.",
            "scenario": "account_notice",
            "difficulty": "basic",
            "recipient_entries": (
                "Alex <alex@gmail.com>; Pat <pat@yahoo.com>; "
                "Jordan <jordan@college.edu>"
            ),
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Campaign created with 3 recipient" in response.data

    import sqlite3
    with sqlite3.connect(app.config["DATABASE"]) as db:
        addresses = [
            row[0]
            for row in db.execute(
                "SELECT email FROM recipients ORDER BY email"
            ).fetchall()
        ]
    assert addresses == ["alex@gmail.com", "jordan@college.edu", "pat@yahoo.com"]


def test_desktop_build_forces_all_domains(tmp_path: Path):
    desktop_app = create_app(
        {
            "TESTING": False,
            "SECRET_KEY": "desktop-test",
            "ADMIN_PASSWORD": "test-password",
            "DATABASE": str(tmp_path / "desktop.sqlite"),
            "OUTBOX_DIR": str(tmp_path / "desktop-outbox"),
            "MEDIA_DIR": str(tmp_path / "desktop-media"),
            "DOMAIN_ALLOWLIST_FILE": str(tmp_path / "desktop-domains.txt"),
            "AUDIT_LOG_FILE": str(tmp_path / "desktop-audit.log"),
            "ALLOWED_RECIPIENT_DOMAINS": {"example.org"},
            "FORCE_ALLOW_ALL_DOMAINS": True,
        }
    )
    assert desktop_app.config["ALLOWED_RECIPIENT_DOMAINS"] == {"*"}


def test_public_landing_page_links_to_demo_and_console(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Pause." in response.data
    assert b"Test the link" in response.data
    assert b"Training console" in response.data
    assert b"/demo/reveal" in response.data
    assert b"/login" in response.data


def test_demo_reveal_uses_local_looping_rickroll_video(client):
    response = client.get("/demo/reveal")
    assert response.status_code == 200
    assert b"This was a phishing awareness test" in response.data
    assert b'id="phishguard-rickroll"' in response.data
    assert b"autoplay" in response.data
    assert b"loop" in response.data
    assert b"media/rr.mp4" in response.data
    assert b"youtube" not in response.data.lower()


def test_training_page_uses_integrated_phishguard_visual_language(app, client, tmp_path: Path):
    login(client)
    campaign_id = create_campaign(client)
    client.post(
        f"/campaigns/{campaign_id}/recipients/add",
        data={"csrf_token": csrf(client), "recipient_entries": "alex@example.org,Alex"},
    )
    client.post(
        f"/campaigns/{campaign_id}/dispatch",
        data={"csrf_token": csrf(client)},
    )
    training_path = extract_training_path(tmp_path)
    response = client.get(training_path)
    assert response.status_code == 200
    assert b"PHISH" in response.data
    assert b"This was a phishing awareness test" in response.data
    assert b"Complete training" in response.data


def test_audit_logger_records_success_and_administrator_can_view(app, client, tmp_path: Path):
    app.config["AUDIT_LOG_FILE"] = str(tmp_path / "audit.log")
    # Reconfigure the module handler for this test's path.
    from audit_logger import configure_audit_logging
    configure_audit_logging(app.config["AUDIT_LOG_FILE"])

    login(client)
    audit_file = tmp_path / "audit.log"
    assert audit_file.exists()
    content = audit_file.read_text(encoding="utf-8")
    assert '"action": "LOGIN_SUCCESS"' in content
    assert '"target": {"username": "admin"}' in content

    response = client.get("/audit")
    assert response.status_code == 200
    assert b"Security audit log" in response.data
    assert b"LOGIN_SUCCESS" in response.data


def test_login_lockout_after_three_failures(app, client, tmp_path: Path):
    app.config["AUDIT_LOG_FILE"] = str(tmp_path / "lockout-audit.log")
    from audit_logger import configure_audit_logging, reset_login_failure_tracker
    configure_audit_logging(app.config["AUDIT_LOG_FILE"])
    reset_login_failure_tracker()

    client.get("/login")
    for _ in range(3):
        response = client.post(
            "/login",
            data={"username": "admin", "password": "wrong-password", "csrf_token": csrf(client)},
        )
        assert response.status_code == 200

    response = client.post(
        "/login",
        data={"username": "admin", "password": "wrong-password", "csrf_token": csrf(client)},
    )
    assert response.status_code == 429
    log_text = (tmp_path / "lockout-audit.log").read_text(encoding="utf-8")
    assert "SECURITY_ALERT_BRUTE_FORCE_DETECTED" in log_text
    assert "LOGIN_BLOCKED_LOCKOUT" in log_text


def test_audit_sanitizes_sensitive_fields(app, tmp_path: Path):
    import json
    from flask import g
    from audit_logger import configure_audit_logging, log_audit_event

    audit_file = tmp_path / "sanitized.log"
    configure_audit_logging(audit_file)
    with app.test_request_context("/audit-test"):
        g.user_id = 99
        g.user_role = "administrator"
        log_audit_event(
            "SANITIZE_TEST",
            target={"user_id": 7, "token": "do-not-store-this"},
            metadata={
                "password": "never-store-this",
                "raw_ip": "192.0.2.1",
                "path": "/t/never-store-this-token",
                "request": {"path": "/caller-supplied-unsafe-path"},
                "safe": "kept",
            },
        )

    event = json.loads(audit_file.read_text(encoding="utf-8").splitlines()[-1])
    assert event["target"]["token"] == "[REDACTED]"
    assert event["metadata"]["password"] == "[REDACTED]"
    assert event["metadata"]["raw_ip"] == "[REDACTED]"
    assert event["metadata"]["path"] == "[REDACTED]"
    assert event["metadata"]["safe"] == "kept"
    assert event["metadata"]["request"] == {
        "endpoint": "unmatched",
        "method": "GET",
        "route": "unmatched",
    }


def test_audit_records_route_pattern_without_training_token(app, tmp_path: Path):
    import json
    from flask import request
    from audit_logger import configure_audit_logging, log_audit_event

    audit_file = tmp_path / "route-context.log"
    configure_audit_logging(audit_file)
    secret_training_token = "private-training-token-value"
    with app.test_request_context(f"/t/{secret_training_token}", method="GET"):
        matched_rule, _ = app.url_map.bind("").match(
            f"/t/{secret_training_token}", method="GET", return_rule=True
        )
        request.url_rule = matched_rule
        log_audit_event("ROUTE_CONTEXT_TEST")

    event = json.loads(audit_file.read_text(encoding="utf-8").splitlines()[-1])
    serialized = json.dumps(event)
    assert secret_training_token not in serialized
    assert event["metadata"]["request"]["method"] == "GET"
    assert event["metadata"]["request"]["route"] == "/t/<token>"

def test_test_user_password_reset_is_blocked(app, client):
    login(client)
    import sqlite3
    from werkzeug.security import generate_password_hash
    with sqlite3.connect(app.config["DATABASE"]) as db:
        cursor = db.execute(
            """
            INSERT INTO users
              (username, display_name, email, password_hash, role, account_group, active, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'viewer', 'phishguard_test_users', 1, ?, ?)
            """,
            ("participant.one", "Participant One", "participant@example.org", generate_password_hash("unused-password-123"), "2026-08-22T00:00:00+00:00", "2026-08-22T00:00:00+00:00"),
        )
        user_id = cursor.lastrowid
        db.commit()

    response = client.post(
        f"/users/{user_id}/password",
        data={"csrf_token": csrf(client), "password": "new-password-12345"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"do not have staff portal passwords" in response.data
