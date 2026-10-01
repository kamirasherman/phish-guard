from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import smtplib
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formataddr, parseaddr
from functools import wraps
from html import escape
from pathlib import Path
from typing import Any, Callable, Iterable

from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.datastructures import FileStorage
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename

from audit_logger import (
    check_account_lockout,
    configure_audit_logging,
    log_audit_event,
    read_recent_audit_events,
    record_login_failure,
    record_login_success,
    reset_login_failure_tracker,
)

EMAIL_RE = re.compile(r"^[^@\s<>]+@(?:[A-Z0-9-]+\.)+[A-Z0-9-]{2,63}$", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"^(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}$",
    re.IGNORECASE,
)
MAX_RECIPIENTS_PER_CAMPAIGN = 5000
DEFAULT_MAX_TRAINING_MEDIA_MB = 500
MAX_CONFIGURABLE_TRAINING_MEDIA_MB = 2048
STANDARD_MAX_REQUEST_BYTES = 25 * 1024 * 1024
MEDIA_UPLOAD_CONTROL_ID = "PB-21"
MEDIA_SIGNATURE_HEADER_BYTES = 4096
MEDIA_SIGNATURE_TAIL_BYTES = 32
QUIZ_UPLOAD_MAX_BYTES = 256 * 1024
QUIZ_QUESTION_COUNT = 5
QUIZ_ALLOWED_MIME_TYPES = {"application/json", "text/json"}
TEST_RUNNER_TIMEOUT_SECONDS = 600
TEST_RUNNER_OUTPUT_LIMIT = 200_000
DEFAULT_DISPATCH_RATE_PER_MINUTE = 60
MAX_DISPATCH_RATE_PER_MINUTE = 600
FORBIDDEN_BODY_MARKERS = ("http://", "https://", "<a ", "<a>", "javascript:")
ALLOWED_MEDIA_EXTENSIONS = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".mp4": "video/mp4",
    ".webm": "video/webm",
}
ALLOWED_MEDIA_MIME_TYPES = {
    ".jpg": {"image/jpeg"},
    ".jpeg": {"image/jpeg"},
    ".png": {"image/png"},
    ".gif": {"image/gif"},
    ".webp": {"image/webp"},
    ".mp4": {"video/mp4"},
    ".webm": {"video/webm"},
}
VIDEO_MEDIA_EXTENSIONS = {".mp4", ".webm"}
MP4_ALLOWED_BRANDS = {
    b"isom", b"iso2", b"iso3", b"iso4", b"iso5", b"iso6",
    b"avc1", b"mp41", b"mp42", b"M4V ", b"MSNV", b"dash", b"qt  ",
}

SAFE_SCENARIOS = {
    "account_notice": "Account activity notice",
    "shared_document": "Shared document invitation",
    "it_maintenance": "IT maintenance notice",
    "event_invitation": "Workplace event invitation",
    "package_notice": "Office package notice",
    "policy_review": "Policy review request",
}

USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,39}$")
SMTP_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")

DEFAULT_TRAINING_DOMAIN = "training.example.org"

SMTP_PROVIDER_PRESETS = {
    "microsoft_365": {
        "label": "Microsoft 365",
        "host": "smtp.office365.com",
        "port": 587,
        "encryption": "starttls",
    },
    "google_workspace": {
        "label": "Google Workspace / Gmail",
        "host": "smtp.gmail.com",
        "port": 587,
        "encryption": "starttls",
    },
    "custom": {
        "label": "Custom SMTP server",
        "host": "",
        "port": 587,
        "encryption": "starttls",
    },
}
SMTP_ENCRYPTION_OPTIONS = {"starttls", "ssl", "none"}

ROLE_DEFINITIONS = {
    "administrator": {
        "label": "Administrator",
        "description": "Full control, including user administration, settings, campaigns, training quizzes, dispatch, results, system tests, and deletion.",
        "permissions": {
            "view_dashboard", "view_results", "manage_campaigns", "dispatch_campaigns",
            "manage_settings", "manage_users", "delete_campaigns", "view_audit_log",
            "run_system_tests",
        },
    },
    "campaign_manager": {
        "label": "Campaign Manager",
        "description": "Creates and manages campaigns, recipients, media, training quizzes, and dispatch without security-administration access.",
        "permissions": {"view_dashboard", "view_results", "manage_campaigns", "dispatch_campaigns"},
    },
    "analyst": {
        "label": "Analyst",
        "description": "Read-only access to campaign details and training results for reporting and analysis.",
        "permissions": {"view_dashboard", "view_results"},
    },
    "viewer": {
        "label": "Viewer",
        "description": "Least-privilege summary access to the campaign dashboard only.",
        "permissions": {"view_dashboard"},
    },
}

USER_GROUP_DEFINITIONS = {
    "application_staff": {
        "label": "Application Staff",
        "description": "Staff accounts governed by one of the four least-privilege RBAC roles.",
    },
    "phishguard_test_users": {
        "label": "PhishGuard Test Users",
        "description": "Non-privileged test participants who can be added to authorized phishing simulations but cannot access the staff portal.",
    },
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def parse_bool(value: str | bool | None, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def parse_bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return min(max(parsed, minimum), maximum)


def load_smtp_settings(path: str | Path) -> dict[str, Any]:
    settings_path = Path(path)
    if not settings_path.exists():
        return {}
    try:
        data = json.loads(settings_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def smtp_fingerprint(values: dict[str, Any]) -> str:
    material = "\n".join(
        str(values.get(key, ""))
        for key in (
            "provider", "host", "port", "encryption", "username", "password",
            "sender_name", "sender_email",
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def smtp_config_values(app: Flask) -> dict[str, Any]:
    return {
        "enabled": bool(app.config.get("ENABLE_SMTP")),
        "provider": str(app.config.get("SMTP_PROVIDER", "custom")),
        "host": str(app.config.get("SMTP_HOST", "")),
        "port": int(app.config.get("SMTP_PORT", 587)),
        "encryption": str(app.config.get("SMTP_ENCRYPTION", "starttls")),
        "username": str(app.config.get("SMTP_USERNAME", "")),
        "password": str(app.config.get("SMTP_PASSWORD", "")),
        "sender_name": str(app.config.get("SENDER_NAME", "Security Awareness Team")),
        "sender_email": str(app.config.get("SENDER_EMAIL", "")),
        "base_url": str(app.config.get("BASE_URL", "")),
        "organization_name": str(app.config.get("ORGANIZATION_NAME", "")),
        "training_domain": str(app.config.get("DEFAULT_TRAINING_DOMAIN", DEFAULT_TRAINING_DOMAIN)),
        "verified_at": str(app.config.get("SMTP_VERIFIED_AT", "")),
        "verified_fingerprint": str(app.config.get("SMTP_VERIFIED_FINGERPRINT", "")),
    }


def save_smtp_settings(app: Flask, values: dict[str, Any]) -> None:
    settings_path = Path(app.config["SMTP_SETTINGS_FILE"])
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = settings_path.with_suffix(settings_path.suffix + ".tmp")
    temporary_path.write_text(json.dumps(values, indent=2, sort_keys=True), encoding="utf-8")
    try:
        os.chmod(temporary_path, 0o600)
    except OSError:
        pass
    temporary_path.replace(settings_path)
    try:
        os.chmod(settings_path, 0o600)
    except OSError:
        pass

    app.config.update(
        ENABLE_SMTP=bool(values["enabled"]),
        SMTP_PROVIDER=values["provider"],
        SMTP_HOST=values["host"],
        SMTP_PORT=int(values["port"]),
        SMTP_ENCRYPTION=values["encryption"],
        SMTP_STARTTLS=values["encryption"] == "starttls",
        SMTP_USERNAME=values["username"],
        SMTP_PASSWORD=values["password"],
        SENDER_NAME=values["sender_name"],
        SENDER_EMAIL=values["sender_email"],
        BASE_URL=values["base_url"].rstrip("/"),
        ORGANIZATION_NAME=values["organization_name"],
        DEFAULT_TRAINING_DOMAIN=values.get("training_domain", DEFAULT_TRAINING_DOMAIN),
        SMTP_VERIFIED_AT=values.get("verified_at", ""),
        SMTP_VERIFIED_FINGERPRINT=values.get("verified_fingerprint", ""),
    )


def smtp_readiness_issues(app: Flask) -> list[str]:
    if not app.config.get("ENABLE_SMTP"):
        return ["Live SMTP delivery is disabled."]

    values = smtp_config_values(app)
    issues: list[str] = []
    if not values["host"]:
        issues.append("SMTP host is missing.")
    if not 1 <= int(values["port"]) <= 65535:
        issues.append("SMTP port must be between 1 and 65535.")
    if values["encryption"] not in SMTP_ENCRYPTION_OPTIONS:
        issues.append("Select a supported SMTP encryption mode.")
    if values["username"] and not values["password"]:
        issues.append("An SMTP password or app password is required for the configured username.")
    if not EMAIL_RE.fullmatch(values["sender_email"]):
        issues.append("A valid approved sender email address is required.")

    base_url = str(app.config.get("BASE_URL", ""))
    local_base_url = base_url.startswith(("http://127.0.0.1", "http://localhost"))
    placeholder_base_url = base_url.rstrip("/") == "https://training.example.org"
    if not app.config.get("TESTING") and (not base_url.startswith("https://") or local_base_url):
        issues.append("BASE_URL must be a public HTTPS address that recipients can reach.")
    elif not app.config.get("TESTING") and placeholder_base_url:
        issues.append("Replace the default HTTPS placeholder with the deployed training site address.")

    allowed_domains = app.config.get("ALLOWED_RECIPIENT_DOMAINS", set())
    if not allowed_domains or "*" in allowed_domains:
        issues.append("Replace the all-domain setting with the specifically authorized client domain(s).")

    expected_fingerprint = smtp_fingerprint(values)
    if values["verified_fingerprint"] != expected_fingerprint or not values["verified_at"]:
        issues.append("Test and verify the saved SMTP connection after the most recent settings change.")
    return issues


def smtp_connection_issues(app: Flask) -> list[str]:
    values = smtp_config_values(app)
    issues: list[str] = []
    if not values["host"] or not SMTP_HOST_RE.fullmatch(values["host"]):
        issues.append("Enter a valid SMTP host name.")
    if not 1 <= int(values["port"]) <= 65535:
        issues.append("SMTP port must be between 1 and 65535.")
    if values["encryption"] not in SMTP_ENCRYPTION_OPTIONS:
        issues.append("Select a supported SMTP encryption mode.")
    if values["username"] and not values["password"]:
        issues.append("Enter the SMTP password or app password for the configured username.")
    if not EMAIL_RE.fullmatch(values["sender_email"]):
        issues.append("Enter a valid approved sender email address.")
    return issues


def smtp_port(value: Any, default: int = 587) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return default
    return port if 1 <= port <= 65535 else default


def parse_domains(value: str | Iterable[str] | None) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        items = re.split(r"[,;\s]+", value)
    else:
        items = value
    return {item.strip().lower().lstrip("@") for item in items if item.strip()}


def validate_domains(domains: Iterable[str]) -> tuple[set[str], list[str]]:
    valid: set[str] = set()
    invalid: list[str] = []
    for raw_domain in domains:
        domain = raw_domain.strip().lower().lstrip("@")
        if not domain:
            continue
        if domain == "*" or DOMAIN_RE.fullmatch(domain):
            valid.add(domain)
        else:
            invalid.append(raw_domain)
    return valid, invalid


def recipient_domains(rows: Iterable[tuple[str, str]]) -> set[str]:
    domains: set[str] = set()
    for email, _ in rows:
        if EMAIL_RE.fullmatch(email):
            domains.add(email.rsplit("@", 1)[1].lower())
    return domains


def normalize_training_domain(value: str | None) -> str:
    domain = (value or "").strip().lower().lstrip("@")
    return domain


def generate_simulation_alias(domain: str, scenario: str = "notice") -> str:
    safe_domain = normalize_training_domain(domain) or DEFAULT_TRAINING_DOMAIN
    scenario_prefix = {
        "account_notice": "account",
        "shared_document": "share",
        "it_maintenance": "it-notice",
        "event_invitation": "events",
        "package_notice": "delivery",
        "policy_review": "policy",
    }.get(scenario, "notice")
    return f"{scenario_prefix}-{secrets.token_hex(3)}@{safe_domain}"


def valid_simulation_alias(alias: str, domain: str) -> bool:
    normalized_alias = (alias or "").strip().lower()
    normalized_domain = normalize_training_domain(domain)
    return bool(
        EMAIL_RE.fullmatch(normalized_alias)
        and normalized_domain
        and normalized_alias.rsplit("@", 1)[-1] == normalized_domain
    )


def save_allowed_domains(app: Flask, domains: Iterable[str]) -> None:
    cleaned, invalid = validate_domains(domains)
    if invalid:
        raise ValueError(f"Invalid domain value: {invalid[0]}")
    path = Path(app.config["DOMAIN_ALLOWLIST_FILE"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(",".join(sorted(cleaned)), encoding="utf-8")
    app.config["ALLOWED_RECIPIENT_DOMAINS"] = cleaned


def authorize_recipient_domains(
    app: Flask, rows: Iterable[tuple[str, str]], confirmed: bool
) -> set[str]:
    if not confirmed or "*" in app.config["ALLOWED_RECIPIENT_DOMAINS"]:
        return set()
    added = recipient_domains(rows) - app.config["ALLOWED_RECIPIENT_DOMAINS"]
    if added:
        save_allowed_domains(
            app, app.config["ALLOWED_RECIPIENT_DOMAINS"] | added
        )
    return added


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    default_db = str(Path(app.instance_path) / "trainer.sqlite")
    default_outbox = str(Path(app.instance_path) / "outbox")
    default_media = str(Path(app.instance_path) / "campaign_media")
    smtp_settings_file = os.getenv(
        "SMTP_SETTINGS_FILE", str(Path(app.instance_path) / "smtp_settings.json")
    )
    saved_smtp = load_smtp_settings(smtp_settings_file)
    legacy_encryption = (
        "starttls" if parse_bool(os.getenv("SMTP_STARTTLS"), True) else "none"
    )
    max_training_media_mb = parse_bounded_int(
        os.getenv("MAX_TRAINING_MEDIA_MB"),
        DEFAULT_MAX_TRAINING_MEDIA_MB,
        1,
        MAX_CONFIGURABLE_TRAINING_MEDIA_MB,
    )

    domain_allowlist_file = os.getenv(
        "DOMAIN_ALLOWLIST_FILE", str(Path(app.instance_path) / "allowed_domains.txt")
    )
    allow_all_setting = os.getenv("ALLOW_ALL_RECIPIENT_DOMAINS")
    allow_all_recipient_domains = parse_bool(allow_all_setting, True)
    configured_domains = os.getenv("ALLOWED_RECIPIENT_DOMAINS")
    if configured_domains is None and Path(domain_allowlist_file).exists():
        configured_domains = Path(domain_allowlist_file).read_text(encoding="utf-8").strip()
        allow_all_recipient_domains = "*" in parse_domains(configured_domains)
    elif configured_domains is None and allow_all_recipient_domains:
        configured_domains = "*"

    app.config.from_mapping(
        TESTING=parse_bool(os.getenv("PHISHGUARD_TEST_MODE"), False),
        SECRET_KEY=os.getenv("SECRET_KEY", secrets.token_hex(32)),
        DATABASE=os.getenv("DATABASE", default_db),
        OUTBOX_DIR=os.getenv("OUTBOX_DIR", default_outbox),
        MEDIA_DIR=os.getenv("MEDIA_DIR", default_media),
        DOMAIN_ALLOWLIST_FILE=domain_allowlist_file,
        BASE_URL=str(saved_smtp.get("base_url", os.getenv("BASE_URL", "https://training.example.org"))).rstrip("/"),
        ORGANIZATION_NAME=str(saved_smtp.get("organization_name", os.getenv("ORGANIZATION_NAME", "Example Organization"))),
        DEFAULT_TRAINING_DOMAIN=normalize_training_domain(str(saved_smtp.get("training_domain", os.getenv("DEFAULT_TRAINING_DOMAIN", DEFAULT_TRAINING_DOMAIN)))) or DEFAULT_TRAINING_DOMAIN,
        ALLOWED_RECIPIENT_DOMAINS=parse_domains(configured_domains or "*"),
        ALLOW_ALL_RECIPIENT_DOMAINS=allow_all_recipient_domains,
        FORCE_ALLOW_ALL_DOMAINS=parse_bool(os.getenv("FORCE_ALLOW_ALL_DOMAINS"), False),
        BUILD_LABEL=os.getenv("BUILD_LABEL", "Landing Integrated + RBAC + Audit + SMTP + Default Training Domain + Uncapped Video Upload + PB-21 + Training Quiz + Persistent Dispatch + HTTPS 2026.09.05"),
        AUDIT_LOG_FILE=os.getenv("AUDIT_LOG_FILE", str(Path(app.instance_path) / "audit.log")),
        SMTP_SETTINGS_FILE=smtp_settings_file,
        ENABLE_SMTP=parse_bool(saved_smtp.get("enabled", os.getenv("ENABLE_SMTP")), False),
        SMTP_PROVIDER=str(saved_smtp.get("provider", os.getenv("SMTP_PROVIDER", "google_workspace"))),
        SMTP_HOST=str(saved_smtp.get("host", os.getenv("SMTP_HOST", "smtp.gmail.com"))),
        SMTP_PORT=smtp_port(saved_smtp.get("port", os.getenv("SMTP_PORT", "587"))),
        SMTP_USERNAME=str(saved_smtp.get("username", os.getenv("SMTP_USERNAME", ""))),
        SMTP_PASSWORD=str(saved_smtp.get("password", os.getenv("SMTP_PASSWORD", ""))),
        SMTP_ENCRYPTION=str(saved_smtp.get("encryption", os.getenv("SMTP_ENCRYPTION", legacy_encryption))),
        SMTP_STARTTLS=str(saved_smtp.get("encryption", os.getenv("SMTP_ENCRYPTION", legacy_encryption))) == "starttls",
        SMTP_VERIFIED_AT=str(saved_smtp.get("verified_at", "")),
        SMTP_VERIFIED_FINGERPRINT=str(saved_smtp.get("verified_fingerprint", "")),
        SENDER_NAME=str(saved_smtp.get("sender_name", os.getenv("SENDER_NAME", "Security Awareness Team"))),
        SENDER_EMAIL=str(saved_smtp.get("sender_email", os.getenv("SENDER_EMAIL", "security-training@example.org"))),
        COOKIE_SECURE=parse_bool(os.getenv("COOKIE_SECURE"), False),
        MAX_TRAINING_MEDIA_MB=max_training_media_mb,
        ADMIN_USERNAME=os.getenv("ADMIN_USERNAME", "admin"),
        ADMIN_PASSWORD=os.getenv("ADMIN_PASSWORD", "training-demo-only"),
        ADMIN_PASSWORD_HASH=os.getenv("ADMIN_PASSWORD_HASH", ""),
        BACKGROUND_DISPATCH_ENABLED=parse_bool(os.getenv("BACKGROUND_DISPATCH_ENABLED"), True),
        SYNCHRONOUS_DISPATCH=parse_bool(os.getenv("SYNCHRONOUS_DISPATCH"), False),
        DISPATCH_RATE_PER_MINUTE=parse_bounded_int(
            os.getenv("DISPATCH_RATE_PER_MINUTE"),
            DEFAULT_DISPATCH_RATE_PER_MINUTE,
            1,
            MAX_DISPATCH_RATE_PER_MINUTE,
        ),
        TRUST_PROXY=parse_bool(os.getenv("TRUST_PROXY"), False),
        PRODUCTION_MODE=parse_bool(os.getenv("PRODUCTION_MODE"), False),
    )

    if test_config:
        app.config.update(test_config)

    if app.config.get("TESTING") and (
        not test_config or "SYNCHRONOUS_DISPATCH" not in test_config
    ):
        app.config["SYNCHRONOUS_DISPATCH"] = True

    app.config["DISPATCH_RATE_PER_MINUTE"] = parse_bounded_int(
        app.config.get("DISPATCH_RATE_PER_MINUTE"),
        DEFAULT_DISPATCH_RATE_PER_MINUTE,
        1,
        MAX_DISPATCH_RATE_PER_MINUTE,
    )

    app.config["MAX_TRAINING_MEDIA_MB"] = parse_bounded_int(
        app.config.get("MAX_TRAINING_MEDIA_MB"),
        DEFAULT_MAX_TRAINING_MEDIA_MB,
        1,
        MAX_CONFIGURABLE_TRAINING_MEDIA_MB,
    )
    app.config["MAX_TRAINING_MEDIA_BYTES"] = (
        app.config["MAX_TRAINING_MEDIA_MB"] * 1024 * 1024
    )
    # Video uploads are intentionally not capped by PhishGuard. The retained
    # byte limit is applied only to image media by PB-21 below.
    app.config["MAX_CONTENT_LENGTH"] = None

    app.config["ALLOWED_RECIPIENT_DOMAINS"] = parse_domains(
        app.config.get("ALLOWED_RECIPIENT_DOMAINS")
    )
    # The desktop training build intentionally accepts every syntactically valid
    # email domain. Test configurations may still provide a restricted allowlist.
    if app.config.get("FORCE_ALLOW_ALL_DOMAINS") and not app.config.get("TESTING"):
        app.config["ALLOW_ALL_RECIPIENT_DOMAINS"] = True
        app.config["ALLOWED_RECIPIENT_DOMAINS"] = {"*"}
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=parse_bool(app.config.get("COOKIE_SECURE"), False),
    )

    if app.config.get("TRUST_PROXY"):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    if app.config.get("PRODUCTION_MODE"):
        production_errors: list[str] = []
        configured_secret = os.getenv("SECRET_KEY") or (
            str(test_config.get("SECRET_KEY", "")) if test_config else ""
        )
        if not configured_secret:
            production_errors.append("SECRET_KEY must be explicitly configured")
        if str(app.config.get("ADMIN_PASSWORD", "")) == "training-demo-only" and not app.config.get("ADMIN_PASSWORD_HASH"):
            production_errors.append("ADMIN_PASSWORD must be replaced or ADMIN_PASSWORD_HASH must be configured")
        if len(str(app.config.get("SECRET_KEY", ""))) < 32:
            production_errors.append("SECRET_KEY must contain at least 32 characters")
        if not str(app.config.get("BASE_URL", "")).startswith("https://"):
            production_errors.append("BASE_URL must use HTTPS")
        if str(app.config.get("BASE_URL", "")).rstrip("/") == "https://training.example.org":
            production_errors.append("BASE_URL must replace the training.example.org placeholder")
        if not app.config.get("COOKIE_SECURE"):
            production_errors.append("COOKIE_SECURE must be true")
        if production_errors:
            raise RuntimeError("Unsafe production configuration: " + "; ".join(production_errors))

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    Path(app.config["OUTBOX_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(app.config["MEDIA_DIR"]).mkdir(parents=True, exist_ok=True)
    configure_audit_logging(app.config["AUDIT_LOG_FILE"])
    app.extensions["test_runner"] = {
        "lock": threading.Lock(),
        "status": "idle",
        "started_at": "",
        "finished_at": "",
        "exit_code": None,
        "output": "",
        "requested_by_user_id": None,
    }
    app.extensions["dispatch_worker"] = {
        "wake": threading.Event(),
        "stop": threading.Event(),
        "thread": None,
    }
    if app.config.get("TESTING"):
        reset_login_failure_tracker()

    register_db(app)
    register_security(app)
    register_routes(app)

    with app.app_context():
        init_db()

    recover_interrupted_dispatches(app)
    if app.config.get("BACKGROUND_DISPATCH_ENABLED") and not app.config.get("TESTING"):
        start_dispatch_worker(app)

    return app


def register_db(app: Flask) -> None:
    def get_db_connection() -> sqlite3.Connection:
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
            g.db.execute("PRAGMA journal_mode = WAL")
            g.db.execute("PRAGMA synchronous = NORMAL")
            g.db.execute("PRAGMA busy_timeout = 5000")
        return g.db

    def close_db(_: BaseException | None = None) -> None:
        db = g.pop("db", None)
        if db is not None:
            db.close()

    app.teardown_appcontext(close_db)
    app.extensions["get_db"] = get_db_connection


def get_db() -> sqlite3.Connection:
    return current_app_get_db()()


def current_app_get_db() -> Callable[[], sqlite3.Connection]:
    from flask import current_app

    return current_app.extensions["get_db"]


def init_db() -> None:
    db = get_db()
    schema_path = Path(__file__).with_name("schema.sql")
    db.executescript(schema_path.read_text(encoding="utf-8"))

    # Lightweight migration support for databases created by the first release.
    columns = {row["name"] for row in db.execute("PRAGMA table_info(campaigns)")}
    additions = {
        "failure_message": "TEXT",
        "media_filename": "TEXT",
        "media_original_name": "TEXT",
        "media_mime": "TEXT",
        "live_sender_email": "TEXT",
        "simulation_alias": "TEXT",
    }
    for column, column_type in additions.items():
        if column not in columns:
            db.execute(f"ALTER TABLE campaigns ADD COLUMN {column} {column_type}")

    user_columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
    if "account_group" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN account_group TEXT NOT NULL DEFAULT 'application_staff'")

    # Bootstrap the first named administrator account for existing installations.
    # The prior shared ADMIN_PASSWORD setting remains the initial credential only.
    user_count = db.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
    if user_count == 0:
        from flask import current_app

        username = str(current_app.config.get("ADMIN_USERNAME", "admin")).strip() or "admin"
        if not USERNAME_RE.fullmatch(username):
            username = "admin"
        stored_hash = str(current_app.config.get("ADMIN_PASSWORD_HASH", "")).strip()
        if not stored_hash:
            stored_hash = generate_password_hash(str(current_app.config.get("ADMIN_PASSWORD", "training-demo-only")))
        db.execute(
            """
            INSERT INTO users (username, display_name, email, password_hash, role, account_group, active, created_at, updated_at)
            VALUES (?, ?, '', ?, 'administrator', 'application_staff', 1, ?, ?)
            """,
            (username, "Administrator", stored_hash, utc_now(), utc_now()),
        )
    db.commit()


def register_security(app: Flask) -> None:
    @app.before_request
    def load_current_user() -> None:
        g.current_user = None
        g.user_id = "system/anonymous"
        g.user_role = "unknown"
        user_id = session.get("user_id")
        if not user_id:
            return
        user = get_db().execute(
            "SELECT id, username, display_name, email, role, account_group, active FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if (
            user is None
            or not user["active"]
            or user["role"] not in ROLE_DEFINITIONS
            or user["account_group"] not in USER_GROUP_DEFINITIONS
        ):
            session.clear()
            return
        g.current_user = user
        g.user_id = user["id"]
        g.user_role = user["role"]

    @app.context_processor
    def inject_security_context() -> dict[str, Any]:
        return {
            "csrf_token": get_csrf_token,
            "current_user": getattr(g, "current_user", None),
            "role_definitions": ROLE_DEFINITIONS,
            "user_group_definitions": USER_GROUP_DEFINITIONS,
            "has_permission": has_permission,
            "max_training_media_mb": app.config["MAX_TRAINING_MEDIA_MB"],
            "media_upload_control_id": MEDIA_UPLOAD_CONTROL_ID,
            "quiz_question_count": QUIZ_QUESTION_COUNT,
            "quiz_upload_max_kb": QUIZ_UPLOAD_MAX_BYTES // 1024,
        }

    @app.before_request
    def enforce_request_size() -> None:
        matched_endpoint = request.url_rule.endpoint if request.url_rule is not None else ""
        media_upload_endpoints = {"campaign_new", "update_campaign_media"}
        if matched_endpoint in media_upload_endpoints:
            # Do not impose an application-level request-size cap on training
            # video uploads. PB-21 still validates allowed type/signature and
            # retains the configured size ceiling for image uploads.
            return
        if matched_endpoint == "upload_campaign_quiz":
            limit = QUIZ_UPLOAD_MAX_BYTES + (64 * 1024)
        else:
            limit = STANDARD_MAX_REQUEST_BYTES
        if request.content_length is not None and request.content_length > limit:
            raise RequestEntityTooLarge()

    @app.before_request
    def validate_csrf() -> None:
        if request.method != "POST":
            return
        expected = session.get("csrf_token", "")
        supplied = request.form.get("csrf_token", "")
        if not expected or not secrets.compare_digest(expected, supplied):
            abort(400, description="Invalid CSRF token")

    @app.after_request
    def add_security_headers(response: Any) -> Any:
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; media-src 'self'; "
            "style-src 'self' 'unsafe-inline'; form-action 'self'; "
            "frame-src 'none'; frame-ancestors 'none'",
        )
        if request.path.startswith("/t/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(RequestEntityTooLarge)
    def too_large(_: RequestEntityTooLarge) -> tuple[str, int]:
        matched_endpoint = request.url_rule.endpoint if request.url_rule is not None else ""
        if matched_endpoint in {"campaign_new", "update_campaign_media"}:
            log_audit_event(
                action="MEDIA_UPLOAD_REJECTED",
                outcome="WARNING",
                metadata={
                    "control": MEDIA_UPLOAD_CONTROL_ID,
                    "reason": "upstream_or_server_request_limit",
                },
            )
            return (
                "The upload was rejected by the active web server or infrastructure request policy. "
                "PhishGuard does not impose an application-level size limit on MP4/WebM video uploads.",
                413,
            )
        if matched_endpoint == "upload_campaign_quiz":
            campaign_id = (request.view_args or {}).get("campaign_id")
            log_audit_event(
                action="QUIZ_UPLOAD_REJECTED",
                outcome="WARNING",
                target={"campaign_id": campaign_id} if campaign_id else None,
                metadata={
                    "reason": "request_size_limit_exceeded",
                    "limit_kb": QUIZ_UPLOAD_MAX_BYTES // 1024,
                },
            )
            return "Quiz upload is too large. JSON quiz files must be 256 KB or smaller.", 413
        return "Upload is too large. The maximum request size is 25 MB.", 413


def get_csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(24)
        session["csrf_token"] = token
    return token


def has_permission(permission: str) -> bool:
    user = getattr(g, "current_user", None)
    if user is None:
        return False
    if user["account_group"] != "application_staff":
        return False
    role = ROLE_DEFINITIONS.get(user["role"], {})
    return permission in role.get("permissions", set())


def login_required(view: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        if getattr(g, "current_user", None) is None:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def permission_required(permission: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def decorator(view: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(view)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            if getattr(g, "current_user", None) is None:
                return redirect(url_for("login", next=request.path))
            if not has_permission(permission):
                abort(403, description="Your role does not have permission to perform this action.")
            return view(*args, **kwargs)

        return wrapped

    return decorator


def active_administrator_count(db: sqlite3.Connection) -> int:
    return int(
        db.execute(
            "SELECT COUNT(*) AS count FROM users WHERE role = 'administrator' AND account_group = 'application_staff' AND active = 1"
        ).fetchone()["count"]
    )


def active_dispatch_job_count(db: sqlite3.Connection, mode: str | None = None) -> int:
    query = "SELECT COUNT(*) AS count FROM dispatch_jobs WHERE status IN ('queued', 'running')"
    parameters: tuple[Any, ...] = ()
    if mode is not None:
        query += " AND mode = ?"
        parameters = (mode,)
    return int(db.execute(query, parameters).fetchone()["count"])


def allowed_email(email: str, allowed_domains: set[str]) -> bool:
    if not EMAIL_RE.fullmatch(email):
        return False
    domain = email.rsplit("@", 1)[1].lower()
    return "*" in allowed_domains or domain in allowed_domains


def recipient_rejection_reason(email: str, allowed_domains: set[str]) -> str | None:
    if not EMAIL_RE.fullmatch(email):
        return "invalid email format"
    domain = email.rsplit("@", 1)[1].lower()
    if "*" not in allowed_domains and domain not in allowed_domains:
        return f"domain {domain} is not approved"
    return None


def validate_campaign_copy(subject: str, body: str) -> str | None:
    if not subject.strip() or len(subject) > 160:
        return "Subject is required and must be 160 characters or fewer."
    if not body.strip() or len(body) > 5000:
        return "Email body is required and must be 5,000 characters or fewer."
    lowered = body.lower()
    if any(marker in lowered for marker in FORBIDDEN_BODY_MARKERS):
        return (
            "External links and HTML anchors are not allowed. "
            "The application adds the training link safely."
        )
    return None


def generate_campaign_copy(scenario: str, difficulty: str, organization_name: str) -> tuple[str, str]:
    """Create a bounded training draft from an approved scenario library."""
    scenario = scenario if scenario in SAFE_SCENARIOS else "account_notice"
    difficulty = difficulty if difficulty in {"basic", "intermediate", "advanced"} else "basic"

    templates: dict[str, tuple[str, str]] = {
        "account_notice": (
            "Review requested: recent account activity",
            "Hello {{first_name}},\n\nOur security team noticed a recent account event that needs review. "
            "Please use the review button below to confirm whether the activity is familiar.\n\n"
            "Thank you,\nSecurity Awareness Team",
        ),
        "shared_document": (
            "A workplace document is waiting for review",
            "Hello {{first_name}},\n\nA document connected to a workplace project has been shared with you. "
            "Please use the review button below to view the notice and confirm the request.\n\n"
            "Thank you,\nCollaboration Services",
        ),
        "it_maintenance": (
            "Action requested before scheduled system maintenance",
            "Hello {{first_name}},\n\nA routine system-maintenance window is being prepared. "
            "Please use the review button below to read the notice before the scheduled update.\n\n"
            "Thank you,\nIT Support",
        ),
        "event_invitation": (
            "Invitation: upcoming workplace learning event",
            "Hello {{first_name}},\n\nYou have been invited to an upcoming workplace learning event. "
            "Please use the review button below to see the invitation details.\n\n"
            "Thank you,\nLearning and Development",
        ),
        "package_notice": (
            "Office delivery notice requires review",
            "Hello {{first_name}},\n\nA delivery associated with the office could not be matched to a recipient. "
            "Please use the review button below to view the notice.\n\n"
            "Thank you,\nOffice Services",
        ),
        "policy_review": (
            "Annual policy review is ready",
            "Hello {{first_name}},\n\nThe annual workplace policy review is ready. "
            "Please use the review button below to read the notice and continue to the training page.\n\n"
            "Thank you,\nCompliance Training",
        ),
    }

    subject, body = templates[scenario]
    if difficulty == "basic":
        body = body.replace(
            "Please use the review button below",
            "This unexpected request asks you to use the review button below",
        )
    elif difficulty == "advanced":
        subject = subject.replace("Review requested", "Attention needed")
        body = body.replace("routine ", "").replace("upcoming ", "")

    # The real organization name is used only in the authorized exercise footer.
    # It is not inserted as a forged sender identity in the generated copy.
    _ = organization_name
    return subject, body


def record_event(db: sqlite3.Connection, recipient_id: int, event_type: str) -> None:
    db.execute(
        """
        INSERT INTO events (recipient_id, event_type, occurred_at)
        VALUES (?, ?, ?)
        ON CONFLICT(recipient_id, event_type)
        DO UPDATE SET occurred_at = excluded.occurred_at
        """,
        (recipient_id, event_type, utc_now()),
    )
    db.commit()


def html_email(body: str, training_url: str, organization_name: str) -> str:
    paragraphs = "".join(
        f"<p>{escape(line)}</p>" for line in body.splitlines() if line.strip()
    )
    safe_url = escape(training_url, quote=True)
    return f"""<!doctype html>
<html lang="en">
  <body style="font-family:Arial,sans-serif;line-height:1.5;color:#1f2937">
    {paragraphs}
    <p><a href="{safe_url}" style="display:inline-block;padding:10px 16px;background:#1f4f8a;color:white;text-decoration:none;border-radius:4px">Review notice</a></p>
    <p style="font-size:12px;color:#6b7280">Authorized annual security-awareness exercise for {escape(organization_name)}.</p>
  </body>
</html>"""


def build_message(app: Flask, recipient: sqlite3.Row, campaign: sqlite3.Row, token: str) -> EmailMessage:
    training_url = f"{app.config['BASE_URL']}{url_for('training', token=token)}"
    first_name = recipient["first_name"] or "colleague"
    body = campaign["body"].replace("{{first_name}}", first_name)
    plain_body = (
        f"{body}\n\nReview notice: {training_url}\n\n"
        f"Authorized annual security-awareness exercise for {app.config['ORGANIZATION_NAME']}."
    )

    message = EmailMessage()
    message["Subject"] = campaign["subject"]
    configured_sender = str(app.config["SENDER_EMAIL"]).strip().lower()
    campaign_sender = str(campaign["live_sender_email"] or configured_sender).strip().lower()
    if campaign_sender != configured_sender:
        raise RuntimeError(
            "Campaign live sender no longer matches the approved SMTP sender. "
            "Update or recreate the campaign before dispatch."
        )
    simulation_alias = str(campaign["simulation_alias"] or "").strip().lower()
    display_identity = simulation_alias if simulation_alias else str(app.config["SENDER_NAME"])
    message["From"] = formataddr((display_identity, configured_sender))
    if simulation_alias:
        message["X-PhishGuard-Simulation-Identity"] = simulation_alias
    message["To"] = recipient["email"]
    message.set_content(plain_body)
    message.add_alternative(
        html_email(body, training_url, app.config["ORGANIZATION_NAME"]),
        subtype="html",
    )
    return message


def open_smtp_connection(app: Flask) -> smtplib.SMTP:
    host = app.config["SMTP_HOST"]
    if not host:
        raise RuntimeError("SMTP_HOST is not configured.")

    context = ssl.create_default_context()
    encryption = app.config.get("SMTP_ENCRYPTION", "starttls")
    if encryption == "ssl":
        smtp: smtplib.SMTP = smtplib.SMTP_SSL(
            host, app.config["SMTP_PORT"], timeout=20, context=context
        )
    else:
        smtp = smtplib.SMTP(host, app.config["SMTP_PORT"], timeout=20)
        smtp.ehlo()
        if encryption == "starttls":
            smtp.starttls(context=context)
            smtp.ehlo()
    try:
        username = app.config["SMTP_USERNAME"]
        if username:
            smtp.login(username, app.config["SMTP_PASSWORD"])
        return smtp
    except Exception:
        smtp.close()
        raise


def close_smtp_connection(smtp: smtplib.SMTP) -> None:
    try:
        smtp.quit()
    except (OSError, smtplib.SMTPException):
        smtp.close()


def send_live_message(app: Flask, message: EmailMessage) -> None:
    smtp = open_smtp_connection(app)
    try:
        smtp.send_message(message)
    finally:
        close_smtp_connection(smtp)


def send_or_preview(app: Flask, message: EmailMessage, recipient_id: int) -> None:
    if not app.config["ENABLE_SMTP"]:
        write_preview_message(app, message, recipient_id)
        return
    send_live_message(app, message)


def write_preview_message(app: Flask, message: EmailMessage, recipient_id: int) -> None:
    outbox = Path(app.config["OUTBOX_DIR"])
    outbox.mkdir(parents=True, exist_ok=True)
    filename = outbox / f"recipient-{recipient_id}-{secrets.token_hex(4)}.eml"
    filename.write_bytes(message.as_bytes())


def open_dispatch_database(app: Flask) -> sqlite3.Connection:
    db = sqlite3.connect(app.config["DATABASE"], timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA journal_mode = WAL")
    db.execute("PRAGMA synchronous = NORMAL")
    db.execute("PRAGMA busy_timeout = 5000")
    return db


def recover_interrupted_dispatches(app: Flask) -> None:
    """Return interrupted work to the queue after a process or host restart."""
    db = open_dispatch_database(app)
    try:
        interrupted = [
            int(row["id"])
            for row in db.execute(
                "SELECT id FROM dispatch_jobs WHERE status = 'running'"
            ).fetchall()
        ]
        if interrupted:
            placeholders = ",".join("?" for _ in interrupted)
            db.execute(
                f"UPDATE dispatch_job_recipients SET status = 'queued' "
                f"WHERE status = 'processing' AND job_id IN ({placeholders})",
                interrupted,
            )
            db.execute(
                f"UPDATE dispatch_jobs SET status = 'queued', started_at = NULL, "
                f"last_error = 'Recovered after application restart' "
                f"WHERE id IN ({placeholders})",
                interrupted,
            )
            db.execute(
                f"UPDATE campaigns SET status = 'queued' WHERE id IN "
                f"(SELECT campaign_id FROM dispatch_jobs WHERE id IN ({placeholders}))",
                interrupted,
            )
            db.commit()
            log_audit_event(
                action="CAMPAIGN_DISPATCH_RECOVERED",
                metadata={"job_count": len(interrupted)},
            )
    finally:
        db.close()


def dispatch_job_counts(db: sqlite3.Connection, job_id: int) -> tuple[int, int, int]:
    row = db.execute(
        """
        SELECT COUNT(*) AS processed,
               SUM(CASE WHEN status = 'sent' THEN 1 ELSE 0 END) AS sent,
               SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed
        FROM dispatch_job_recipients
        WHERE job_id = ? AND status IN ('sent', 'failed')
        """,
        (job_id,),
    ).fetchone()
    return int(row["processed"] or 0), int(row["sent"] or 0), int(row["failed"] or 0)


def process_dispatch_job(app: Flask, job_id: int) -> None:
    """Process one persistent dispatch job and checkpoint every recipient."""
    db = open_dispatch_database(app)
    smtp: smtplib.SMTP | None = None
    try:
        db.execute("BEGIN IMMEDIATE")
        job = db.execute(
            "SELECT * FROM dispatch_jobs WHERE id = ? AND status = 'queued'",
            (job_id,),
        ).fetchone()
        if job is None:
            db.rollback()
            return
        db.execute(
            "UPDATE dispatch_jobs SET status = 'running', started_at = ?, last_error = '' WHERE id = ?",
            (utc_now(), job_id),
        )
        db.execute(
            "UPDATE campaigns SET status = 'sending' WHERE id = ?",
            (job["campaign_id"],),
        )
        db.commit()

        if job["mode"] == "smtp":
            current_fingerprint = smtp_fingerprint(smtp_config_values(app))
            readiness_issues = smtp_readiness_issues(app)
            if current_fingerprint != job["smtp_fingerprint"] or readiness_issues:
                reason = (
                    "SMTP settings changed after this job was queued."
                    if current_fingerprint != job["smtp_fingerprint"]
                    else "SMTP readiness checks no longer pass."
                )
                db.execute(
                    "UPDATE dispatch_jobs SET status = 'failed', last_error = ?, finished_at = ? WHERE id = ?",
                    (reason, utc_now(), job_id),
                )
                db.execute(
                    "UPDATE campaigns SET status = 'draft' WHERE id = ?",
                    (job["campaign_id"],),
                )
                db.commit()
                log_audit_event(
                    action="CAMPAIGN_DISPATCH_FAILED",
                    outcome="FAILURE",
                    target={"campaign_id": job["campaign_id"], "dispatch_job_id": job_id},
                    metadata={"reason": reason},
                )
                return
            smtp = open_smtp_connection(app)

        campaign = db.execute(
            "SELECT * FROM campaigns WHERE id = ?", (job["campaign_id"],)
        ).fetchone()
        if campaign is None:
            return

        job_recipients = db.execute(
            """
            SELECT djr.id AS job_recipient_id, r.*
            FROM dispatch_job_recipients djr
            JOIN recipients r ON r.id = djr.recipient_id
            WHERE djr.job_id = ? AND djr.status = 'queued'
            ORDER BY djr.id
            """,
            (job_id,),
        ).fetchall()

        for index, recipient in enumerate(job_recipients):
            item_id = int(recipient["job_recipient_id"])
            db.execute(
                "UPDATE dispatch_job_recipients SET status = 'processing', attempted_at = ? WHERE id = ?",
                (utc_now(), item_id),
            )
            db.commit()
            error_type = ""
            item_status = "sent"
            try:
                if not allowed_email(recipient["email"], app.config["ALLOWED_RECIPIENT_DOMAINS"]):
                    raise ValueError("RecipientDomainNotAuthorized")
                token = secrets.token_urlsafe(32)
                db.execute(
                    "UPDATE recipients SET token_digest = ? WHERE id = ?",
                    (token_digest(token), recipient["id"]),
                )
                db.commit()
                refreshed = db.execute(
                    "SELECT * FROM recipients WHERE id = ?", (recipient["id"],)
                ).fetchone()
                message = build_message(app, refreshed, campaign, token)
                if job["mode"] == "smtp":
                    assert smtp is not None
                    smtp.send_message(message)
                else:
                    write_preview_message(app, message, recipient["id"])
                db.execute(
                    """
                    INSERT INTO events (recipient_id, event_type, occurred_at)
                    VALUES (?, 'delivered', ?)
                    ON CONFLICT(recipient_id, event_type)
                    DO UPDATE SET occurred_at = excluded.occurred_at
                    """,
                    (recipient["id"], utc_now()),
                )
            except (OSError, RuntimeError, ValueError, smtplib.SMTPException) as exc:
                item_status = "failed"
                error_type = type(exc).__name__
            db.execute(
                "UPDATE dispatch_job_recipients SET status = ?, error_type = ? WHERE id = ?",
                (item_status, error_type, item_id),
            )
            processed, sent, failed = dispatch_job_counts(db, job_id)
            db.execute(
                """
                UPDATE dispatch_jobs
                SET processed_recipients = ?, sent_recipients = ?, failed_recipients = ?,
                    last_error = CASE WHEN ? <> '' THEN ? ELSE last_error END
                WHERE id = ?
                """,
                (processed, sent, failed, error_type, error_type, job_id),
            )
            db.commit()
            if (
                job["mode"] == "smtp"
                and index < len(job_recipients) - 1
                and not app.config.get("TESTING")
            ):
                time.sleep(60 / app.config["DISPATCH_RATE_PER_MINUTE"])

        processed, sent, failed = dispatch_job_counts(db, job_id)
        if failed == 0 and sent == int(job["total_recipients"]):
            final_status = "completed"
        elif sent:
            final_status = "partial"
        else:
            final_status = "failed"
        db.execute(
            """
            UPDATE dispatch_jobs
            SET status = ?, processed_recipients = ?, sent_recipients = ?,
                failed_recipients = ?, finished_at = ?
            WHERE id = ?
            """,
            (final_status, processed, sent, failed, utc_now(), job_id),
        )
        db.execute(
            "UPDATE campaigns SET status = ?, dispatched_at = ? WHERE id = ?",
            (
                "sent" if final_status == "completed" else ("partial" if sent else "draft"),
                utc_now() if sent else None,
                job["campaign_id"],
            ),
        )
        db.commit()
        log_audit_event(
            action="CAMPAIGN_DISPATCH_COMPLETED",
            outcome="SUCCESS" if final_status == "completed" else "WARNING",
            target={"campaign_id": job["campaign_id"], "dispatch_job_id": job_id},
            metadata={
                "status": final_status,
                "processed": processed,
                "sent": sent,
                "failed": failed,
                "mode": job["mode"],
            },
        )
    except Exception as exc:
        db.rollback()
        error_type = type(exc).__name__
        db.execute(
            "UPDATE dispatch_jobs SET status = 'failed', last_error = ?, finished_at = ? WHERE id = ?",
            (error_type, utc_now(), job_id),
        )
        db.execute(
            "UPDATE campaigns SET status = 'draft' WHERE id = (SELECT campaign_id FROM dispatch_jobs WHERE id = ?)",
            (job_id,),
        )
        db.commit()
        log_audit_event(
            action="CAMPAIGN_DISPATCH_FAILED",
            outcome="FAILURE",
            target={"dispatch_job_id": job_id},
            metadata={"error_type": error_type},
        )
    finally:
        if smtp is not None:
            close_smtp_connection(smtp)
        db.close()


def claim_next_dispatch_job(app: Flask) -> int | None:
    db = open_dispatch_database(app)
    try:
        row = db.execute(
            "SELECT id FROM dispatch_jobs WHERE status = 'queued' ORDER BY id LIMIT 1"
        ).fetchone()
        return int(row["id"]) if row else None
    finally:
        db.close()


def dispatch_worker_loop(app: Flask) -> None:
    state = app.extensions["dispatch_worker"]
    while not state["stop"].is_set():
        job_id = claim_next_dispatch_job(app)
        if job_id is None:
            state["wake"].wait(timeout=5)
            state["wake"].clear()
            continue
        process_dispatch_job(app, job_id)


def start_dispatch_worker(app: Flask) -> None:
    state = app.extensions["dispatch_worker"]
    existing = state.get("thread")
    if existing is not None and existing.is_alive():
        state["wake"].set()
        return
    thread = threading.Thread(
        target=dispatch_worker_loop,
        args=(app,),
        daemon=True,
        name="phishguard-dispatch-worker",
    )
    state["thread"] = thread
    thread.start()


def media_matches_extension(
    extension: str, header: bytes, tail: bytes = b"", size: int | None = None
) -> bool:
    if extension in {".jpg", ".jpeg"}:
        return header.startswith(b"\xff\xd8\xff") and tail.endswith(b"\xff\xd9")
    if extension == ".png":
        return header.startswith(b"\x89PNG\r\n\x1a\n") and tail.endswith(
            b"\x00\x00\x00\x00IEND\xaeB`\x82"
        )
    if extension == ".gif":
        return header.startswith((b"GIF87a", b"GIF89a")) and tail.endswith(b"\x3b")
    if extension == ".webp":
        if len(header) < 16 or not header.startswith(b"RIFF") or header[8:12] != b"WEBP":
            return False
        if header[12:16] not in {b"VP8 ", b"VP8L", b"VP8X"}:
            return False
        declared_size = int.from_bytes(header[4:8], "little") + 8
        return size is not None and declared_size == size
    if extension == ".mp4":
        if len(header) < 16 or header[4:8] != b"ftyp":
            return False
        box_size = int.from_bytes(header[0:4], "big")
        if box_size < 16 or box_size > len(header) or box_size % 4 != 0:
            return False
        major_brand = header[8:12]
        compatible_brands = {
            header[offset : offset + 4]
            for offset in range(16, box_size, 4)
            if len(header[offset : offset + 4]) == 4
        }
        return bool(({major_brand} | compatible_brands) & MP4_ALLOWED_BRANDS)
    if extension == ".webm":
        return header.startswith(b"\x1a\x45\xdf\xa3") and b"webm" in header.lower()
    return False


def read_media_signature_parts(stream: Any, size: int) -> tuple[bytes, bytes]:
    stream.seek(0)
    header = stream.read(MEDIA_SIGNATURE_HEADER_BYTES)
    stream.seek(max(0, size - MEDIA_SIGNATURE_TAIL_BYTES))
    tail = stream.read(MEDIA_SIGNATURE_TAIL_BYTES)
    stream.seek(0)
    return header, tail


def prepare_media_upload(
    app: Flask, upload: FileStorage | None
) -> tuple[FileStorage, str, str, int] | None:
    if upload is None or not upload.filename:
        return None
    original_name = secure_filename(upload.filename)
    if not original_name or len(original_name) > 255:
        raise ValueError(f"{MEDIA_UPLOAD_CONTROL_ID} validation failed: invalid filename.")
    extension = Path(original_name).suffix.lower()
    if extension not in ALLOWED_MEDIA_EXTENSIONS:
        raise ValueError(
            f"{MEDIA_UPLOAD_CONTROL_ID} validation failed. Allowed media formats: "
            "JPG, PNG, GIF, WebP, MP4, and WebM."
        )

    declared_mime = (upload.mimetype or "").split(";", 1)[0].strip().lower()
    if declared_mime not in ALLOWED_MEDIA_MIME_TYPES[extension]:
        raise ValueError(
            f"{MEDIA_UPLOAD_CONTROL_ID} validation failed: the declared media type "
            "does not match the filename extension."
        )

    try:
        upload.stream.seek(0, os.SEEK_END)
        size = int(upload.stream.tell())
        upload.stream.seek(0)
    except (AttributeError, OSError, ValueError) as exc:
        raise ValueError(
            f"{MEDIA_UPLOAD_CONTROL_ID} validation failed: the file could not be read safely."
        ) from exc

    if size == 0:
        raise ValueError(f"{MEDIA_UPLOAD_CONTROL_ID} validation failed: the file is empty.")
    if extension not in VIDEO_MEDIA_EXTENSIONS and size > app.config["MAX_TRAINING_MEDIA_BYTES"]:
        raise ValueError(
            f"{MEDIA_UPLOAD_CONTROL_ID} validation failed: image files must be "
            f"{app.config['MAX_TRAINING_MEDIA_MB']} MB or smaller."
        )

    header, tail = read_media_signature_parts(upload.stream, size)
    if not media_matches_extension(extension, header, tail, size):
        raise ValueError(
            f"{MEDIA_UPLOAD_CONTROL_ID} validation failed: the binary file signature "
            "does not match the permitted media format."
        )
    return upload, original_name, ALLOWED_MEDIA_EXTENSIONS[extension], size


def store_media(
    app: Flask, prepared: tuple[FileStorage, str, str, int]
) -> tuple[str, str, str]:
    upload, original_name, mime, expected_size = prepared
    extension = Path(original_name).suffix.lower()
    stored_name = f"{secrets.token_hex(24)}{extension}"
    media_dir = Path(app.config["MEDIA_DIR"])
    media_dir.mkdir(parents=True, exist_ok=True)
    destination = media_dir / stored_name
    temporary = media_dir / f"{stored_name}.uploading"
    try:
        upload.stream.seek(0)
        with temporary.open("xb") as output:
            shutil.copyfileobj(upload.stream, output, length=1024 * 1024)
        if temporary.stat().st_size != expected_size:
            raise OSError("The uploaded media was not stored completely.")
        with temporary.open("rb") as stored_stream:
            header, tail = read_media_signature_parts(stored_stream, expected_size)
        if not media_matches_extension(extension, header, tail, expected_size):
            raise OSError("PB-21 post-write media signature verification failed.")
        temporary.replace(destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return stored_name, original_name, mime


def delete_media_file(app: Flask, filename: str | None) -> None:
    if not filename:
        return
    path = Path(app.config["MEDIA_DIR"]) / Path(filename).name
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON field: {key}")
        result[key] = value
    return result


def normalize_quiz_document(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise ValueError("Quiz content must be a JSON object.")
    if set(document) != {"title", "passing_score", "questions"}:
        raise ValueError(
            "Quiz JSON must contain only title, passing_score, and questions."
        )

    title = document["title"]
    passing_score = document["passing_score"]
    questions = document["questions"]
    if not isinstance(title, str) or not title.strip() or len(title.strip()) > 120:
        raise ValueError("Quiz title is required and must be 120 characters or fewer.")
    if type(passing_score) is not int or not 50 <= passing_score <= 100:
        raise ValueError("Quiz passing_score must be a whole number from 50 through 100.")
    if not isinstance(questions, list) or len(questions) != QUIZ_QUESTION_COUNT:
        raise ValueError(f"Each training quiz must contain exactly {QUIZ_QUESTION_COUNT} questions.")

    normalized_questions: list[dict[str, Any]] = []
    seen_prompts: set[str] = set()
    for number, question in enumerate(questions, start=1):
        if not isinstance(question, dict):
            raise ValueError(f"Question {number} must be a JSON object.")
        required_fields = {"prompt", "choices", "correct_index", "explanation"}
        if set(question) != required_fields:
            raise ValueError(
                f"Question {number} must contain only prompt, choices, correct_index, and explanation."
            )

        prompt = question["prompt"]
        choices = question["choices"]
        correct_index = question["correct_index"]
        explanation = question["explanation"]
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt.strip()) > 300:
            raise ValueError(f"Question {number} prompt must be 1 through 300 characters.")
        prompt_key = prompt.strip().casefold()
        if prompt_key in seen_prompts:
            raise ValueError("Quiz question prompts must be unique.")
        seen_prompts.add(prompt_key)
        if not isinstance(choices, list) or not 2 <= len(choices) <= 5:
            raise ValueError(f"Question {number} must contain 2 through 5 choices.")
        if any(
            not isinstance(choice, str) or not choice.strip() or len(choice.strip()) > 200
            for choice in choices
        ):
            raise ValueError(
                f"Every choice for question {number} must be 1 through 200 characters."
            )
        normalized_choices = [choice.strip() for choice in choices]
        if len({choice.casefold() for choice in normalized_choices}) != len(normalized_choices):
            raise ValueError(f"Choices for question {number} must be unique.")
        if type(correct_index) is not int or not 0 <= correct_index < len(normalized_choices):
            raise ValueError(f"Question {number} correct_index is outside the choices list.")
        if (
            not isinstance(explanation, str)
            or not explanation.strip()
            or len(explanation.strip()) > 500
        ):
            raise ValueError(
                f"Question {number} explanation must be 1 through 500 characters."
            )
        normalized_questions.append(
            {
                "prompt": prompt.strip(),
                "choices": normalized_choices,
                "correct_index": correct_index,
                "explanation": explanation.strip(),
            }
        )
    return {
        "title": title.strip(),
        "passing_score": passing_score,
        "questions": normalized_questions,
    }


def prepare_quiz_upload(upload: FileStorage | None) -> tuple[dict[str, Any], str, int]:
    if upload is None or not upload.filename:
        raise ValueError("Select a JSON quiz file to upload.")
    original_name = secure_filename(upload.filename)
    if not original_name or len(original_name) > 255 or Path(original_name).suffix.lower() != ".json":
        raise ValueError("Quiz uploads must use a valid .json filename.")
    declared_mime = (upload.mimetype or "").split(";", 1)[0].strip().lower()
    if declared_mime not in QUIZ_ALLOWED_MIME_TYPES:
        raise ValueError("The quiz file must declare an application/json or text/json media type.")
    try:
        upload.stream.seek(0, os.SEEK_END)
        size = int(upload.stream.tell())
        upload.stream.seek(0)
    except (AttributeError, OSError, ValueError) as exc:
        raise ValueError("The quiz file could not be read safely.") from exc
    if size == 0:
        raise ValueError("The quiz file is empty.")
    if size > QUIZ_UPLOAD_MAX_BYTES:
        raise ValueError("Quiz JSON files must be 256 KB or smaller.")
    try:
        raw = upload.stream.read(size + 1)
        upload.stream.seek(0)
        text = raw.decode("utf-8")
        document = json.loads(text, object_pairs_hook=reject_duplicate_json_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ValueError("The quiz file must contain valid UTF-8 JSON with unique fields.") from exc
    return normalize_quiz_document(document), original_name, size


def quiz_for_participant(document: dict[str, Any]) -> dict[str, Any]:
    return {
        "title": document["title"],
        "passing_score": document["passing_score"],
        "questions": [
            {"prompt": question["prompt"], "choices": question["choices"]}
            for question in document["questions"]
        ],
    }


def score_quiz_submission(
    document: dict[str, Any], submitted: dict[str, str]
) -> tuple[list[int], int, list[dict[str, Any]]]:
    answers: list[int] = []
    feedback: list[dict[str, Any]] = []
    correct_count = 0
    for index, question in enumerate(document["questions"]):
        raw_answer = submitted.get(f"question_{index}", "")
        if not raw_answer.isdigit():
            raise ValueError("Answer every quiz question before submitting.")
        selected_index = int(raw_answer)
        if not 0 <= selected_index < len(question["choices"]):
            raise ValueError("One or more quiz answers are invalid.")
        is_correct = selected_index == question["correct_index"]
        correct_count += int(is_correct)
        answers.append(selected_index)
        feedback.append(
            {
                "is_correct": is_correct,
                "selected_index": selected_index,
                "correct_index": question["correct_index"],
                "explanation": question["explanation"],
            }
        )
    return answers, correct_count, feedback


def parse_manual_recipients(value: str) -> list[tuple[str, str]]:
    """Parse recipients entered in the message composer.

    Supported formats include one address per line, semicolon-separated addresses,
    ``email@example.org,First`` and ``First Name <email@example.org>``. A comma
    between two valid email addresses is treated as a recipient separator.
    """
    recipients: list[tuple[str, str]] = []
    normalized = value.replace(";", "\n")

    for raw_line in normalized.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        display_name, parsed_address = parseaddr(line)
        if parsed_address and "<" in line and ">" in line:
            recipients.append((parsed_address.strip().lower(), display_name.strip()[:80]))
            continue

        row = [item.strip() for item in next(csv.reader([line], skipinitialspace=True))]
        row = [item for item in row if item]
        if not row:
            continue

        # Permit familiar To-field input such as:
        # alex@example.org, jordan@example.org
        if len(row) > 1 and all(EMAIL_RE.fullmatch(item) for item in row):
            recipients.extend((item.lower(), "") for item in row)
            continue

        email = row[0].lower()
        first_name = (row[1] if len(row) > 1 else "")[:80]
        recipients.append((email, first_name))

    return recipients


def upsert_recipient_rows(
    db: sqlite3.Connection,
    campaign_id: int,
    rows: Iterable[tuple[str, str]],
    allowed_domains: set[str],
) -> tuple[int, list[str]]:
    existing = db.execute(
        "SELECT COUNT(*) AS count FROM recipients WHERE campaign_id = ?", (campaign_id,)
    ).fetchone()["count"]
    imported = 0
    rejected: list[str] = []

    for index, (email, first_name) in enumerate(rows, start=1):
        reason = recipient_rejection_reason(email, allowed_domains)
        if reason:
            rejected.append(f"entry {index}: {email or 'missing email'} ({reason})")
            continue

        already_exists = db.execute(
            "SELECT 1 FROM recipients WHERE campaign_id = ? AND email = ?",
            (campaign_id, email),
        ).fetchone()
        if not already_exists and existing >= MAX_RECIPIENTS_PER_CAMPAIGN:
            rejected.append(f"entry {index}: campaign recipient limit reached")
            break

        db.execute(
            """
            INSERT INTO recipients (campaign_id, email, first_name, token_digest, created_at)
            VALUES (?, ?, ?, NULL, ?)
            ON CONFLICT(campaign_id, email)
            DO UPDATE SET first_name = excluded.first_name
            """,
            (campaign_id, email, first_name, utc_now()),
        )
        if not already_exists:
            existing += 1
        imported += 1

    db.commit()
    return imported, rejected


def test_runner_snapshot(app: Flask) -> dict[str, Any]:
    """Return the Administrator-view state without exposing the synchronization lock."""
    runner = app.extensions["test_runner"]
    with runner["lock"]:
        return {key: value for key, value in runner.items() if key != "lock"}


def run_test_suite_in_background(app: Flask, requested_by_user_id: int) -> None:
    """Run the packaged test suite with fixed arguments and isolated runtime data."""
    runner = app.extensions["test_runner"]
    project_dir = Path(__file__).resolve().parent
    batch_file = project_dir / "Run_Tests.bat"
    started = time.monotonic()
    exit_code: int | None = None
    status = "error"
    output = ""

    try:
        with tempfile.TemporaryDirectory(prefix="phishguard-test-run-") as isolated_dir:
            isolated = Path(isolated_dir)
            environment = os.environ.copy()
            environment.update(
                {
                    "PHISHGUARD_TEST_RUNNER": "1",
                    "PHISHGUARD_TEST_MODE": "true",
                    "PYTHONIOENCODING": "utf-8",
                    "DATABASE": str(isolated / "runner.sqlite"),
                    "OUTBOX_DIR": str(isolated / "outbox"),
                    "MEDIA_DIR": str(isolated / "media"),
                    "DOMAIN_ALLOWLIST_FILE": str(isolated / "allowed_domains.txt"),
                    "AUDIT_LOG_FILE": str(isolated / "audit.log"),
                    "SMTP_SETTINGS_FILE": str(isolated / "smtp_settings.json"),
                    "ENABLE_SMTP": "false",
                    "BACKGROUND_DISPATCH_ENABLED": "false",
                    "BASE_URL": "http://localhost",
                    "COOKIE_SECURE": "false",
                    "PRODUCTION_MODE": "false",
                    "TRUST_PROXY": "false",
                    "FORCE_ALLOW_ALL_DOMAINS": "false",
                    "SECRET_KEY": secrets.token_hex(32),
                }
            )
            if os.name == "nt" and batch_file.is_file():
                command = [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", str(batch_file)]
            else:
                command = [sys.executable, "-m", "pytest", "-q"]
            completed = subprocess.run(
                command,
                cwd=project_dir,
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=TEST_RUNNER_TIMEOUT_SECONDS,
                check=False,
            )
            exit_code = completed.returncode
            output = "\n".join(
                part.strip() for part in (completed.stdout, completed.stderr) if part.strip()
            )
            status = "passed" if exit_code == 0 else "failed"
    except subprocess.TimeoutExpired as exc:
        captured = exc.stdout or ""
        if isinstance(captured, bytes):
            captured = captured.decode("utf-8", errors="replace")
        output = f"Test run exceeded the {TEST_RUNNER_TIMEOUT_SECONDS}-second limit.\n{captured}".strip()
        status = "error"
    except Exception as exc:  # Defensive boundary for the Administrator diagnostic tool.
        output = f"Unable to start the packaged test suite: {type(exc).__name__}: {exc}"
        status = "error"

    if len(output) > TEST_RUNNER_OUTPUT_LIMIT:
        output = "[Earlier output omitted]\n" + output[-TEST_RUNNER_OUTPUT_LIMIT:]
    duration_seconds = round(time.monotonic() - started, 2)
    finished_at = utc_now()
    with runner["lock"]:
        runner.update(
            {
                "status": status,
                "finished_at": finished_at,
                "exit_code": exit_code,
                "output": output or "The test command completed without output.",
            }
        )
    with app.app_context():
        log_audit_event(
            action="SYSTEM_TEST_RUN_COMPLETED",
            outcome="SUCCESS" if status == "passed" else "FAILURE",
            target={"requested_by_user_id": requested_by_user_id},
            metadata={
                "status": status,
                "exit_code": exit_code,
                "duration_seconds": duration_seconds,
                "output_characters": len(output),
            },
        )


def register_routes(app: Flask) -> None:
    @app.get("/health")
    def health() -> tuple[dict[str, str], int]:
        return {"status": "ok", "service": "phishguard"}, 200

    @app.get("/ready")
    def ready() -> tuple[dict[str, Any], int]:
        try:
            db = get_db()
            db.execute("SELECT 1").fetchone()
            db.execute("SELECT id FROM dispatch_jobs LIMIT 1").fetchone()
            return {"status": "ready"}, 200
        except sqlite3.DatabaseError:
            return {"status": "not_ready"}, 503

    @app.route("/login", methods=["GET", "POST"])
    def login() -> Any:
        if request.method == "POST":
            username = request.form.get("username", "").strip() or str(app.config.get("ADMIN_USERNAME", "admin"))
            password = request.form.get("password", "")

            if not check_account_lockout(username):
                log_audit_event(
                    action="LOGIN_BLOCKED_LOCKOUT",
                    outcome="DENIED",
                    target={"username": username},
                    metadata={"lockout_minutes": 5},
                )
                flash("Too many failed login attempts. Try again after the five-minute lockout period.", "error")
                return render_template("login.html"), 429

            user = get_db().execute(
                "SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)
            ).fetchone()
            if user is not None and user["active"] and check_password_hash(user["password_hash"], password):
                g.user_id = user["id"]
                g.user_role = user["role"]
                record_login_success(username)
                if user["account_group"] != "application_staff":
                    log_audit_event(
                        action="PORTAL_ACCESS_DENIED",
                        outcome="DENIED",
                        target={"username": username, "account_group": user["account_group"]},
                        metadata={"reason": "test participants do not have staff portal access"},
                    )
                    flash("PhishGuard Test Users are simulation participants and do not have staff portal access.", "error")
                    return render_template("login.html"), 403

                session.clear()
                session["user_id"] = user["id"]
                session["admin_authenticated"] = user["role"] == "administrator"
                session["csrf_token"] = secrets.token_urlsafe(24)
                destination = request.args.get("next", "")
                if not destination.startswith("/") or destination.startswith("//"):
                    destination = url_for("dashboard")
                return redirect(destination)

            record_login_failure(username)
            flash("Invalid username or password.", "error")
        return render_template("login.html")

    @app.post("/logout")
    def logout() -> Any:
        if getattr(g, "current_user", None) is not None:
            log_audit_event(
                action="LOGOUT",
                target={"username": g.current_user["username"]},
            )
        session.clear()
        return redirect(url_for("login"))

    @app.route("/users", methods=["GET", "POST"])
    @permission_required("manage_users")
    def users() -> Any:
        db = get_db()
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            display_name = request.form.get("display_name", "").strip()
            email = request.form.get("email", "").strip().lower()
            role = request.form.get("role", "viewer").strip()
            account_group = request.form.get("account_group", "application_staff").strip()
            password = request.form.get("password", "")
            if account_group == "phishguard_test_users":
                role = "viewer"

            error = None
            if not USERNAME_RE.fullmatch(username):
                error = "Username must be 3–40 characters and use letters, numbers, dot, underscore, or hyphen."
            elif not display_name or len(display_name) > 120:
                error = "Display name is required and must be 120 characters or fewer."
            elif email and not EMAIL_RE.fullmatch(email):
                error = "Enter a valid email address or leave the email field blank."
            elif account_group not in USER_GROUP_DEFINITIONS:
                error = "Select a supported user group."
            elif role not in ROLE_DEFINITIONS:
                error = "Select one of the four supported staff roles."
            elif account_group == "application_staff" and (len(password) < 12 or len(password) > 128):
                error = "Temporary password must be between 12 and 128 characters for staff accounts."

            if error:
                flash(error, "error")
            else:
                try:
                    db.execute(
                        """
                        INSERT INTO users
                            (username, display_name, email, password_hash, role, account_group, active, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
                        """,
                        (
                            username, display_name, email,
                            generate_password_hash(password if password else secrets.token_urlsafe(32)),
                            role, account_group, utc_now(), utc_now()
                        ),
                    )
                    db.commit()
                    created_user_id = int(db.execute("SELECT id FROM users WHERE username = ? COLLATE NOCASE", (username,)).fetchone()["id"])
                    log_audit_event(
                        action="USER_CREATED",
                        target={"user_id": created_user_id, "username": username},
                        metadata={"role": role, "account_group": account_group, "active": True},
                    )
                    if account_group == "phishguard_test_users":
                        flash(f"Test participant {username} was added to the PhishGuard Test Users group with no staff portal access.", "success")
                    else:
                        flash(f"User {username} was created with the {ROLE_DEFINITIONS[role]['label']} role.", "success")
                    return redirect(url_for("users"))
                except sqlite3.IntegrityError:
                    flash("That username already exists.", "error")

        rows = db.execute(
            "SELECT id, username, display_name, email, role, account_group, active, created_at FROM users ORDER BY account_group, username COLLATE NOCASE"
        ).fetchall()
        return render_template("users.html", users=rows)

    @app.post("/users/<int:user_id>/update")
    @permission_required("manage_users")
    def update_user(user_id: int) -> Any:
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if user is None:
            abort(404)
        role = request.form.get("role", user["role"])
        account_group = request.form.get("account_group", user["account_group"])
        active = request.form.get("active") == "yes"
        if account_group not in USER_GROUP_DEFINITIONS:
            abort(400, description="Unknown user group")
        if account_group == "phishguard_test_users":
            role = "viewer"
        if role not in ROLE_DEFINITIONS:
            abort(400, description="Unknown role")

        is_self = g.current_user is not None and user_id == g.current_user["id"]
        removing_admin = (
            user["role"] == "administrator"
            and user["account_group"] == "application_staff"
            and user["active"]
            and (role != "administrator" or account_group != "application_staff" or not active)
        )
        if is_self and (role != "administrator" or account_group != "application_staff" or not active):
            flash("You cannot remove your own Administrator access while signed in.", "error")
            return redirect(url_for("users"))
        if removing_admin and active_administrator_count(db) <= 1:
            flash("At least one active Administrator account is required.", "error")
            return redirect(url_for("users"))

        db.execute(
            "UPDATE users SET role = ?, account_group = ?, active = ?, updated_at = ? WHERE id = ?",
            (role, account_group, 1 if active else 0, utc_now(), user_id),
        )
        db.commit()
        log_audit_event(
            action="USER_ACCESS_UPDATED",
            target={"user_id": user_id, "username": user["username"]},
            metadata={
                "previous": {"role": user["role"], "account_group": user["account_group"], "active": bool(user["active"])},
                "current": {"role": role, "account_group": account_group, "active": active},
            },
        )
        flash(f"Access for {user['username']} was updated.", "success")
        return redirect(url_for("users"))

    @app.post("/users/<int:user_id>/password")
    @permission_required("manage_users")
    def reset_user_password(user_id: int) -> Any:
        db = get_db()
        user = db.execute("SELECT id, username, account_group FROM users WHERE id = ?", (user_id,)).fetchone()
        if user is None:
            abort(404)
        if user["account_group"] != "application_staff":
            flash("PhishGuard Test Users do not have staff portal passwords to reset.", "error")
            return redirect(url_for("users"))
        password = request.form.get("password", "")
        if len(password) < 12 or len(password) > 128:
            flash("New password must be between 12 and 128 characters.", "error")
            return redirect(url_for("users"))
        db.execute(
            "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
            (generate_password_hash(password), utc_now(), user_id),
        )
        db.commit()
        log_audit_event(
            action="USER_PASSWORD_RESET",
            target={"user_id": user_id, "username": user["username"]},
            metadata={"performed_by_administrator": True},
        )
        flash(f"Password for {user['username']} was reset.", "success")
        return redirect(url_for("users"))

    @app.get("/audit")
    @permission_required("view_audit_log")
    def audit_log() -> Any:
        limit_raw = request.args.get("limit", "250")
        try:
            limit = max(25, min(int(limit_raw), 1000))
        except ValueError:
            limit = 250
        events = read_recent_audit_events(app.config["AUDIT_LOG_FILE"], limit=limit)
        return render_template(
            "audit_log.html",
            events=events,
            limit=limit,
            audit_filename=Path(app.config["AUDIT_LOG_FILE"]).name,
        )

    @app.get("/system-tests")
    @permission_required("run_system_tests")
    def system_tests() -> Any:
        return render_template(
            "system_tests.html",
            test_state=test_runner_snapshot(app),
            timeout_minutes=TEST_RUNNER_TIMEOUT_SECONDS // 60,
        )

    @app.post("/system-tests/run")
    @permission_required("run_system_tests")
    def start_system_tests() -> Any:
        runner = app.extensions["test_runner"]
        user_id = int(g.current_user["id"])
        with runner["lock"]:
            if runner["status"] == "running":
                flash("The automated test suite is already running.", "error")
                return redirect(url_for("system_tests"))
            runner.update(
                {
                    "status": "running",
                    "started_at": utc_now(),
                    "finished_at": "",
                    "exit_code": None,
                    "output": "",
                    "requested_by_user_id": user_id,
                }
            )
        log_audit_event(
            action="SYSTEM_TEST_RUN_STARTED",
            target={"requested_by_user_id": user_id},
            metadata={"command": "Run_Tests.bat", "live_smtp_disabled": True},
        )
        thread = threading.Thread(
            target=run_test_suite_in_background,
            args=(app, user_id),
            daemon=True,
            name="phishguard-system-tests",
        )
        thread.start()
        flash("The automated test suite started. Use Refresh status to view progress.", "success")
        return redirect(url_for("system_tests"))

    @app.get("/")
    def landing() -> Any:
        return render_template("landing.html")

    @app.get("/demo/reveal")
    def demo_reveal() -> Any:
        return render_template("demo_reveal.html")

    @app.get("/admin")
    @app.get("/dashboard")
    @permission_required("view_dashboard")
    def dashboard() -> Any:
        db = get_db()
        campaigns = db.execute(
            """
            SELECT c.*,
                   COUNT(DISTINCT r.id) AS recipients,
                   COUNT(DISTINCT CASE WHEN e.event_type = 'delivered' THEN r.id END) AS delivered,
                   COUNT(DISTINCT CASE WHEN e.event_type = 'clicked' THEN r.id END) AS clicked,
                   COUNT(DISTINCT CASE WHEN e.event_type = 'completed' THEN r.id END) AS completed
            FROM campaigns c
            LEFT JOIN recipients r ON r.campaign_id = c.id
            LEFT JOIN events e ON e.recipient_id = r.id
            GROUP BY c.id
            ORDER BY c.id DESC
            """
        ).fetchall()
        return render_template("dashboard.html", campaigns=campaigns)

    @app.route("/campaigns/new", methods=["GET", "POST"])
    @permission_required("manage_campaigns")
    def new_campaign() -> Any:
        values = {
            "name": request.form.get("name", "").strip(),
            "subject": request.form.get("subject", "").strip(),
            "body": request.form.get("body", "").strip(),
            "scenario": request.form.get("scenario", "account_notice"),
            "difficulty": request.form.get("difficulty", "basic"),
            "recipient_entries": request.form.get("recipient_entries", "").strip(),
            "authorize_recipient_domains": request.form.get("authorize_recipient_domains") == "yes",
            "failure_message": request.form.get("failure_message", "").strip(),
            "live_sender_email": request.form.get(
                "live_sender_email", str(app.config["SENDER_EMAIL"])
            ).strip().lower(),
            "simulation_alias": request.form.get("simulation_alias", "").strip().lower(),
        }
        if not values["simulation_alias"]:
            values["simulation_alias"] = generate_simulation_alias(
                app.config["DEFAULT_TRAINING_DOMAIN"], values["scenario"]
            )

        if request.method == "POST" and request.form.get("action") == "regenerate_alias":
            values["live_sender_email"] = values["live_sender_email"] or str(app.config["SENDER_EMAIL"]).strip().lower()
            values["simulation_alias"] = generate_simulation_alias(
                app.config["DEFAULT_TRAINING_DOMAIN"], values["scenario"]
            )
            flash("A new simulation alias was generated.", "success")
            return render_template(
                "campaign_new.html",
                values=values,
                scenarios=SAFE_SCENARIOS,
                allowed_domains=sorted(app.config["ALLOWED_RECIPIENT_DOMAINS"]),
                training_domain=app.config["DEFAULT_TRAINING_DOMAIN"],
                approved_sender=app.config["SENDER_EMAIL"],
            )

        if request.method == "POST" and request.form.get("action") == "generate":
            values["subject"], values["body"] = generate_campaign_copy(
                values["scenario"], values["difficulty"], app.config["ORGANIZATION_NAME"]
            )
            flash("A safe training draft was generated. Review and edit it before creating the campaign.", "success")
            return render_template(
                "campaign_new.html",
                values=values,
                scenarios=SAFE_SCENARIOS,
                allowed_domains=sorted(app.config["ALLOWED_RECIPIENT_DOMAINS"]),
                training_domain=app.config["DEFAULT_TRAINING_DOMAIN"],
                approved_sender=app.config["SENDER_EMAIL"],
            )

        if request.method == "POST":
            error = validate_campaign_copy(values["subject"], values["body"])
            if not values["name"] or len(values["name"]) > 120:
                error = "Campaign name is required and must be 120 characters or fewer."
            if len(values["failure_message"]) > 1000:
                error = "Failure-page message must be 1,000 characters or fewer."

            approved_sender = str(app.config["SENDER_EMAIL"]).strip().lower()
            if not EMAIL_RE.fullmatch(values["live_sender_email"]):
                error = "Enter a valid live sender email address."
            elif values["live_sender_email"] != approved_sender:
                error = (
                    "The live sender must match the approved SMTP From address. "
                    "Update SMTP Settings first if the sender account needs to change."
                )
            if not valid_simulation_alias(values["simulation_alias"], app.config["DEFAULT_TRAINING_DOMAIN"]):
                error = "Generate a valid simulation alias using the configured default training domain."

            initial_recipients = parse_manual_recipients(values["recipient_entries"])
            if (
                initial_recipients
                and not app.config["ALLOWED_RECIPIENT_DOMAINS"]
                and not (values["authorize_recipient_domains"] and has_permission("manage_settings"))
            ):
                error = (
                    "Recipients were entered, but no recipient domains are approved. "
                    "Open Recipient domains or confirm authorization below the To field."
                )

            try:
                prepared_media = prepare_media_upload(app, request.files.get("failure_media"))
            except ValueError as exc:
                log_audit_event(
                    action="MEDIA_UPLOAD_REJECTED",
                    outcome="WARNING",
                    metadata={"control": MEDIA_UPLOAD_CONTROL_ID, "reason": str(exc)},
                )
                error = str(exc)
                prepared_media = None

            if error:
                flash(error, "error")
                return (
                    render_template(
                        "campaign_new.html",
                        values=values,
                        scenarios=SAFE_SCENARIOS,
                        allowed_domains=sorted(app.config["ALLOWED_RECIPIENT_DOMAINS"]),
                        training_domain=app.config["DEFAULT_TRAINING_DOMAIN"],
                        approved_sender=app.config["SENDER_EMAIL"],
                    ),
                    400,
                )

            added_domains = authorize_recipient_domains(
                app,
                initial_recipients,
                bool(values["authorize_recipient_domains"]) and has_permission("manage_settings"),
            )
            if added_domains:
                flash(
                    "Approved recipient domain(s) for this local trainer: "
                    + ", ".join(sorted(added_domains)),
                    "success",
                )

            stored_media: tuple[str, str, str] | None = None
            if prepared_media:
                stored_media = store_media(app, prepared_media)

            db = get_db()
            try:
                cursor = db.execute(
                    """
                    INSERT INTO campaigns
                        (name, subject, body, failure_message, media_filename,
                         media_original_name, media_mime, live_sender_email, simulation_alias, created_at, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft')
                    """,
                    (
                        values["name"],
                        values["subject"],
                        values["body"],
                        values["failure_message"],
                        stored_media[0] if stored_media else None,
                        stored_media[1] if stored_media else None,
                        stored_media[2] if stored_media else None,
                        values["live_sender_email"],
                        values["simulation_alias"],
                        utc_now(),
                    ),
                )
                campaign_id = int(cursor.lastrowid)
                db.commit()
                imported = 0
                rejected: list[str] = []

                if initial_recipients:
                    imported, rejected = upsert_recipient_rows(
                        db,
                        campaign_id,
                        initial_recipients,
                        app.config["ALLOWED_RECIPIENT_DOMAINS"],
                    )
                    flash(f"Campaign created with {imported} recipient(s).", "success")
                    if rejected:
                        preview = "; ".join(rejected[:5])
                        more = " …" if len(rejected) > 5 else ""
                        flash(
                            f"Rejected {len(rejected)} recipient entry or entries: {preview}{more}",
                            "error",
                        )
                else:
                    flash("Campaign created. Add recipients before dispatching.", "success")
                log_audit_event(
                    action="CAMPAIGN_CREATED",
                    target={"campaign_id": campaign_id},
                    metadata={
                        "recipient_count": imported,
                        "rejected_recipient_count": len(rejected),
                        "has_training_media": bool(stored_media),
                        "training_media_bytes": prepared_media[3] if prepared_media else 0,
                        "media_validation_control": MEDIA_UPLOAD_CONTROL_ID if prepared_media else "",
                        "scenario": values["scenario"],
                        "difficulty": values["difficulty"],
                        "simulation_alias_domain": values["simulation_alias"].rsplit("@", 1)[-1],
                        "live_sender_domain": values["live_sender_email"].rsplit("@", 1)[-1],
                    },
                )
            except sqlite3.DatabaseError:
                if stored_media:
                    delete_media_file(app, stored_media[0])
                raise
            return redirect(url_for("campaign_detail", campaign_id=campaign_id))

        default_values = {
            "name": "",
            "subject": "",
            "body": "",
            "scenario": "account_notice",
            "difficulty": "basic",
            "recipient_entries": "",
            "authorize_recipient_domains": False,
            "live_sender_email": str(app.config["SENDER_EMAIL"]).strip().lower(),
            "simulation_alias": generate_simulation_alias(app.config["DEFAULT_TRAINING_DOMAIN"], "account_notice"),
            "failure_message": (
                "This was an authorized phishing simulation. Review the warning signs below "
                "before completing the training."
            ),
        }
        return render_template(
            "campaign_new.html",
            values=default_values,
            scenarios=SAFE_SCENARIOS,
            allowed_domains=sorted(app.config["ALLOWED_RECIPIENT_DOMAINS"]),
            training_domain=app.config["DEFAULT_TRAINING_DOMAIN"],
            approved_sender=app.config["SENDER_EMAIL"],
        )

    @app.route("/settings/recipient-domains", methods=["GET", "POST"])
    @permission_required("manage_settings")
    def recipient_domain_settings() -> Any:
        if app.config.get("FORCE_ALLOW_ALL_DOMAINS") and not app.config.get("TESTING"):
            app.config["ALLOWED_RECIPIENT_DOMAINS"] = {"*"}
            if request.method == "POST":
                flash("All-domain mode is locked on in this build. Every valid email domain is accepted.", "success")
                return redirect(url_for("recipient_domain_settings"))
            return render_template(
                "recipient_domains.html",
                domains="*",
                force_all_domains=True,
            )
        if request.method == "POST":
            if active_dispatch_job_count(get_db()):
                flash("Recipient-domain settings are locked while a dispatch job is queued or running.", "error")
                return redirect(url_for("recipient_domain_settings"))
            requested = parse_domains(request.form.get("domains", ""))
            valid, invalid = validate_domains(requested)
            if invalid:
                flash(
                    "These domain values are invalid: " + ", ".join(invalid[:5]),
                    "error",
                )
                return render_template(
                    "recipient_domains.html",
                    domains=request.form.get("domains", ""),
                ), 400
            if not request.form.get("authorization_confirmed"):
                flash(
                    "Confirm that you are authorized to test recipients in these domains.",
                    "error",
                )
                return render_template(
                    "recipient_domains.html",
                    domains=request.form.get("domains", ""),
                ), 400
            save_allowed_domains(app, valid)
            log_audit_event(
                action="RECIPIENT_DOMAIN_ALLOWLIST_UPDATED",
                target={"setting": "recipient_domains"},
                metadata={"domain_count": len(valid), "allow_all": "*" in valid},
            )
            flash(
                "Recipient domain allowlist saved: "
                + (", ".join(sorted(valid)) if valid else "none"),
                "success",
            )
            return redirect(url_for("recipient_domain_settings"))

        return render_template(
            "recipient_domains.html",
            domains="\n".join(sorted(app.config["ALLOWED_RECIPIENT_DOMAINS"])),
            force_all_domains=False,
        )

    @app.route("/settings/smtp", methods=["GET", "POST"])
    @permission_required("manage_settings")
    def smtp_settings() -> Any:
        current = smtp_config_values(app)
        if request.method == "POST":
            if active_dispatch_job_count(get_db(), "smtp"):
                flash("SMTP settings are locked while a live dispatch job is queued or running.", "error")
                return redirect(url_for("smtp_settings"))
            authorize_gmail_recipients = (
                request.form.get("authorize_gmail_recipients") == "yes"
            )
            provider = request.form.get("provider", "custom").strip()
            if provider not in SMTP_PROVIDER_PRESETS:
                provider = "custom"

            preset = SMTP_PROVIDER_PRESETS[provider]
            if provider == "custom":
                host = request.form.get("host", "").strip().lower()
                port = smtp_port(request.form.get("port"), 0)
                encryption = request.form.get("encryption", "starttls").strip()
            else:
                host = preset["host"]
                port = int(preset["port"])
                encryption = preset["encryption"]

            username = request.form.get("username", "").strip()
            submitted_password = request.form.get("password", "")
            if request.form.get("clear_password") == "yes":
                password = ""
            elif submitted_password:
                # Google displays App Passwords in grouped blocks. Normalize only the
                # Gmail preset so pasted spaces/tabs/newlines cannot cause a 535 login
                # failure. Preserve custom-provider credentials exactly as entered.
                password = (
                    "".join(submitted_password.split())
                    if provider == "google_workspace"
                    else submitted_password
                )
            else:
                password = current["password"]

            submitted_training_domain = request.form.get("training_domain")
            training_domain = (
                normalize_training_domain(submitted_training_domain)
                if submitted_training_domain is not None
                else normalize_training_domain(current.get("training_domain", DEFAULT_TRAINING_DOMAIN))
            ) or DEFAULT_TRAINING_DOMAIN

            new_values = {
                "enabled": request.form.get("enabled") == "yes",
                "provider": provider,
                "host": host,
                "port": port,
                "encryption": encryption,
                "username": username,
                "password": password,
                "sender_name": request.form.get("sender_name", "").strip(),
                "sender_email": request.form.get("sender_email", "").strip().lower(),
                "base_url": request.form.get("base_url", "").strip().rstrip("/"),
                "organization_name": request.form.get("organization_name", "").strip(),
                "training_domain": training_domain,
                "verified_at": current["verified_at"],
                "verified_fingerprint": current["verified_fingerprint"],
            }

            errors: list[str] = []
            if not SMTP_HOST_RE.fullmatch(host):
                errors.append("Enter a valid SMTP host name.")
            if not 1 <= port <= 65535:
                errors.append("SMTP port must be between 1 and 65535.")
            if encryption not in SMTP_ENCRYPTION_OPTIONS:
                errors.append("Select a supported SMTP encryption mode.")
            if not new_values["sender_name"] or len(new_values["sender_name"]) > 120:
                errors.append("Sender name is required and must be 120 characters or fewer.")
            if not EMAIL_RE.fullmatch(new_values["sender_email"]):
                errors.append("Enter a valid approved sender email address.")
            if not re.fullmatch(r"https?://[^\s/]+(?::\d{1,5})?(?:/[^\s]*)?", new_values["base_url"]):
                errors.append("Enter a valid HTTP or HTTPS training site base URL.")
            if not new_values["organization_name"] or len(new_values["organization_name"]) > 160:
                errors.append("Organization name is required and must be 160 characters or fewer.")
            if not DOMAIN_RE.fullmatch(new_values["training_domain"]):
                errors.append("Enter a valid default training domain, such as training.example.org.")
            if (
                submitted_training_domain is not None
                and new_values["training_domain"] != DEFAULT_TRAINING_DOMAIN
                and new_values["training_domain"] != current.get("training_domain", DEFAULT_TRAINING_DOMAIN)
                and request.form.get("training_domain_control_confirmed") != "yes"
            ):
                errors.append("Confirm that your organization controls the custom training domain.")
            if username and not password:
                errors.append("Enter the SMTP password or app password for this username.")
            if len(password) > 512:
                errors.append("SMTP password is too long.")
            if request.form.get("authorization_confirmed") != "yes":
                errors.append("Confirm that the sender account is approved for authorized awareness testing.")

            if errors:
                for error in errors:
                    flash(error, "error")
                display_values = dict(new_values)
                display_values["password"] = ""
                return render_template(
                    "smtp_settings.html",
                    smtp=display_values,
                    password_set=bool(password),
                    providers=SMTP_PROVIDER_PRESETS,
                    readiness_issues=smtp_readiness_issues(app),
                    gmail_recipient_authorized=authorize_gmail_recipients,
                ), 400

            if smtp_fingerprint(new_values) != smtp_fingerprint(current):
                new_values["verified_at"] = ""
                new_values["verified_fingerprint"] = ""
            save_smtp_settings(app, new_values)
            gmail_domain_added = False
            if authorize_gmail_recipients and "gmail.com" not in app.config["ALLOWED_RECIPIENT_DOMAINS"]:
                allowed_domains = set(app.config["ALLOWED_RECIPIENT_DOMAINS"])
                allowed_domains.discard("*")
                allowed_domains.add("gmail.com")
                save_allowed_domains(app, allowed_domains)
                gmail_domain_added = True
                log_audit_event(
                    action="RECIPIENT_DOMAIN_ALLOWLIST_UPDATED",
                    target={"setting": "recipient_domains"},
                    metadata={
                        "domain_count": len(allowed_domains),
                        "allow_all": False,
                        "gmail_simulation_enabled": True,
                        "source": "smtp_settings",
                    },
                )
            log_audit_event(
                action="SMTP_SETTINGS_UPDATED",
                target={"setting": "smtp"},
                metadata={
                    "enabled": new_values["enabled"],
                    "provider": provider,
                    "host": host,
                    "port": port,
                    "encryption": encryption,
                    "username_configured": bool(username),
                    "password_configured": bool(password),
                    "sender_domain": new_values["sender_email"].rsplit("@", 1)[-1],
                    "training_domain": new_values["training_domain"],
                    "gmail_recipient_domain_authorized": (
                        "gmail.com" in app.config["ALLOWED_RECIPIENT_DOMAINS"]
                    ),
                },
            )
            if gmail_domain_added:
                flash(
                    "gmail.com was added to the explicit recipient-domain allowlist for authorized simulations.",
                    "success",
                )
            flash("SMTP settings were saved. Test the connection before live dispatch.", "success")
            return redirect(url_for("smtp_settings"))

        display = dict(current)
        display["password"] = ""
        return render_template(
            "smtp_settings.html",
            smtp=display,
            password_set=bool(current["password"]),
            providers=SMTP_PROVIDER_PRESETS,
            readiness_issues=smtp_readiness_issues(app),
            gmail_recipient_authorized=(
                "gmail.com" in app.config["ALLOWED_RECIPIENT_DOMAINS"]
            ),
        )

    @app.post("/settings/smtp/test")
    @permission_required("manage_settings")
    def test_smtp_settings() -> Any:
        if active_dispatch_job_count(get_db(), "smtp"):
            flash("SMTP testing is locked while a live dispatch job is queued or running.", "error")
            return redirect(url_for("smtp_settings"))
        issues = smtp_connection_issues(app)
        if issues:
            for issue in issues:
                flash(issue, "error")
            return redirect(url_for("smtp_settings"))

        test_recipient = request.form.get("test_recipient", "").strip().lower()
        send_test_message = bool(test_recipient)
        allowed_domains = app.config["ALLOWED_RECIPIENT_DOMAINS"]
        if send_test_message:
            if "*" in allowed_domains:
                flash("Set a specific authorized client-domain allowlist before sending a test message.", "error")
                return redirect(url_for("smtp_settings"))
            if not allowed_email(test_recipient, allowed_domains):
                flash("The test recipient must use a specifically authorized client domain.", "error")
                return redirect(url_for("smtp_settings"))

        try:
            smtp = open_smtp_connection(app)
            try:
                if send_test_message:
                    message = EmailMessage()
                    message["Subject"] = "PhishGuard SMTP configuration test"
                    message["From"] = f"{app.config['SENDER_NAME']} <{app.config['SENDER_EMAIL']}>"
                    message["To"] = test_recipient
                    message.set_content(
                        "This is a harmless PhishGuard SMTP configuration test. "
                        "No campaign was launched and no recipient interaction is being tracked."
                    )
                    smtp.send_message(message)
            finally:
                close_smtp_connection(smtp)
        except (OSError, RuntimeError, smtplib.SMTPException) as exc:
            error_type = type(exc).__name__
            smtp_code = getattr(exc, "smtp_code", None)
            smtp_error = getattr(exc, "smtp_error", b"")
            if isinstance(smtp_error, bytes):
                smtp_detail = smtp_error.decode("utf-8", errors="replace")
            else:
                smtp_detail = str(smtp_error or "")
            # SMTP server responses do not contain the submitted password. Limit the
            # displayed text to keep the UI useful without exposing excessive detail.
            smtp_detail = " ".join(smtp_detail.split())[:500]

            log_audit_event(
                action="SMTP_CONNECTION_TEST",
                target={"setting": "smtp"},
                outcome="FAILURE",
                metadata={
                    "error_type": error_type,
                    "smtp_code": smtp_code,
                    "smtp_detail": smtp_detail,
                    "test_message_requested": send_test_message,
                },
            )

            if isinstance(exc, smtplib.SMTPAuthenticationError):
                detail = f" Gmail/SMTP response: {smtp_code} {smtp_detail}" if smtp_code else ""
                flash(
                    "SMTP authentication failed." + detail +
                    " Confirm the full Gmail address is the SMTP username and use a current App Password. "
                    "For the Gmail preset, pasted whitespace in the App Password is removed automatically.",
                    "error",
                )
            else:
                detail = f" SMTP response: {smtp_code} {smtp_detail}" if smtp_code or smtp_detail else ""
                flash(
                    f"SMTP test failed: {error_type}." + detail +
                    " Review the host, port, encryption, and provider settings.",
                    "error",
                )
            return redirect(url_for("smtp_settings"))

        values = smtp_config_values(app)
        values["verified_at"] = utc_now()
        values["verified_fingerprint"] = smtp_fingerprint(values)
        save_smtp_settings(app, values)
        log_audit_event(
            action="SMTP_CONNECTION_TEST",
            target={"setting": "smtp"},
            metadata={
                "provider": values["provider"],
                "host": values["host"],
                "port": values["port"],
                "encryption": values["encryption"],
                "test_message_sent": send_test_message,
                "test_recipient_domain": test_recipient.rsplit("@", 1)[-1] if test_recipient else "",
            },
        )
        if send_test_message:
            flash("SMTP connection verified and the harmless test email was sent.", "success")
        else:
            flash("SMTP connection and authentication were verified. No email was sent.", "success")
        return redirect(url_for("smtp_settings"))

    @app.get("/campaigns/<int:campaign_id>")
    @permission_required("view_results")
    def campaign_detail(campaign_id: int) -> Any:
        db = get_db()
        campaign = db.execute("SELECT * FROM campaigns WHERE id = ?", (campaign_id,)).fetchone()
        if campaign is None:
            abort(404)
        recipients = db.execute(
            """
            SELECT r.*,
                   MAX(CASE WHEN e.event_type = 'delivered' THEN e.occurred_at END) AS delivered_at,
                   MAX(CASE WHEN e.event_type = 'clicked' THEN e.occurred_at END) AS clicked_at,
                   MAX(CASE WHEN e.event_type = 'completed' THEN e.occurred_at END) AS completed_at,
                   (SELECT qa.score_percent FROM quiz_attempts qa
                    WHERE qa.recipient_id = r.id ORDER BY qa.id DESC LIMIT 1) AS quiz_score,
                   (SELECT qa.passed FROM quiz_attempts qa
                    WHERE qa.recipient_id = r.id ORDER BY qa.id DESC LIMIT 1) AS quiz_passed,
                   (SELECT COUNT(*) FROM quiz_attempts qa
                    WHERE qa.recipient_id = r.id) AS quiz_attempts
            FROM recipients r
            LEFT JOIN events e ON e.recipient_id = r.id
            WHERE r.campaign_id = ?
            GROUP BY r.id
            ORDER BY r.email
            """,
            (campaign_id,),
        ).fetchall()
        test_group_count = db.execute(
            "SELECT COUNT(*) AS count FROM users WHERE account_group = 'phishguard_test_users' AND active = 1 AND email <> ''"
        ).fetchone()["count"]
        quiz = db.execute(
            "SELECT id, title, passing_score, original_filename, updated_at FROM quizzes WHERE campaign_id = ?",
            (campaign_id,),
        ).fetchone()
        latest_dispatch_job = db.execute(
            "SELECT * FROM dispatch_jobs WHERE campaign_id = ? ORDER BY id DESC LIMIT 1",
            (campaign_id,),
        ).fetchone()
        return render_template(
            "campaign_detail.html",
            campaign=campaign,
            recipients=recipients,
            allowed_domains=sorted(app.config["ALLOWED_RECIPIENT_DOMAINS"]),
            smtp_enabled=app.config["ENABLE_SMTP"],
            smtp_ready=app.config["ENABLE_SMTP"] and not smtp_readiness_issues(app),
            smtp_issues=smtp_readiness_issues(app) if app.config["ENABLE_SMTP"] else [],
            test_group_count=test_group_count,
            quiz=quiz,
            latest_dispatch_job=latest_dispatch_job,
        )

    @app.get("/campaigns/<int:campaign_id>/status")
    @permission_required("view_results")
    def campaign_status(campaign_id: int) -> Any:
        db = get_db()
        campaign = db.execute(
            "SELECT id, status FROM campaigns WHERE id = ?", (campaign_id,)
        ).fetchone()
        if campaign is None:
            abort(404)
        metrics = db.execute(
            """
            SELECT COUNT(*) AS recipients,
                   SUM(CASE WHEN EXISTS (
                       SELECT 1 FROM events e WHERE e.recipient_id = r.id AND e.event_type = 'delivered'
                   ) THEN 1 ELSE 0 END) AS delivered,
                   SUM(CASE WHEN EXISTS (
                       SELECT 1 FROM events e WHERE e.recipient_id = r.id AND e.event_type = 'clicked'
                   ) THEN 1 ELSE 0 END) AS clicked,
                   SUM(CASE WHEN EXISTS (
                       SELECT 1 FROM events e WHERE e.recipient_id = r.id AND e.event_type = 'completed'
                   ) THEN 1 ELSE 0 END) AS completed,
                   SUM(CASE WHEN EXISTS (
                       SELECT 1 FROM quiz_attempts qa WHERE qa.recipient_id = r.id AND qa.passed = 1
                   ) THEN 1 ELSE 0 END) AS quiz_passed
            FROM recipients r
            WHERE r.campaign_id = ?
            """,
            (campaign_id,),
        ).fetchone()
        job = db.execute(
            """
            SELECT id, mode, status, total_recipients, processed_recipients,
                   sent_recipients, failed_recipients, last_error,
                   created_at, started_at, finished_at
            FROM dispatch_jobs WHERE campaign_id = ? ORDER BY id DESC LIMIT 1
            """,
            (campaign_id,),
        ).fetchone()
        response = jsonify(
            {
                "campaign_id": campaign_id,
                "campaign_status": campaign["status"],
                "metrics": {
                    key: int(metrics[key] or 0)
                    for key in ("recipients", "delivered", "clicked", "completed", "quiz_passed")
                },
                "dispatch_job": dict(job) if job is not None else None,
                "updated_at": utc_now(),
            }
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/campaigns/<int:campaign_id>/recipients/add")
    @permission_required("manage_campaigns")
    def add_recipients(campaign_id: int) -> Any:
        db = get_db()
        campaign = db.execute("SELECT id FROM campaigns WHERE id = ?", (campaign_id,)).fetchone()
        if campaign is None:
            abort(404)
        rows = parse_manual_recipients(request.form.get("recipient_entries", ""))
        if not rows:
            flash("Enter at least one email address.", "error")
            return redirect(url_for("campaign_detail", campaign_id=campaign_id))
        added_domains = authorize_recipient_domains(
            app,
            rows,
            request.form.get("authorize_recipient_domains") == "yes" and has_permission("manage_settings"),
        )
        if added_domains:
            flash(
                "Approved recipient domain(s): " + ", ".join(sorted(added_domains)),
                "success",
            )
        allowed_domains = app.config["ALLOWED_RECIPIENT_DOMAINS"]
        if not allowed_domains:
            flash(
                "No recipient domains are approved. Open Recipient domains or confirm authorization below.",
                "error",
            )
            return redirect(url_for("campaign_detail", campaign_id=campaign_id))
        imported, rejected = upsert_recipient_rows(db, campaign_id, rows, allowed_domains)
        log_audit_event(
            action="CAMPAIGN_RECIPIENTS_UPDATED",
            target={"campaign_id": campaign_id},
            metadata={"source": "manual", "accepted": imported, "rejected": len(rejected)},
        )
        flash(f"Added or updated {imported} recipient(s).", "success")
        if rejected:
            preview = "; ".join(rejected[:5])
            more = " …" if len(rejected) > 5 else ""
            flash(f"Rejected {len(rejected)} entry or entries: {preview}{more}", "error")
        return redirect(url_for("campaign_detail", campaign_id=campaign_id))

    @app.post("/campaigns/<int:campaign_id>/recipients/test-group")
    @permission_required("manage_campaigns")
    def add_test_group_recipients(campaign_id: int) -> Any:
        db = get_db()
        campaign = db.execute("SELECT id FROM campaigns WHERE id = ?", (campaign_id,)).fetchone()
        if campaign is None:
            abort(404)

        test_users = db.execute(
            """
            SELECT email, display_name
            FROM users
            WHERE account_group = 'phishguard_test_users'
              AND active = 1
              AND email <> ''
            ORDER BY username COLLATE NOCASE
            """
        ).fetchall()
        if not test_users:
            flash("No active PhishGuard Test Users with email addresses are available.", "error")
            return redirect(url_for("campaign_detail", campaign_id=campaign_id))

        rows = [(row["email"], row["display_name"]) for row in test_users]
        imported, rejected = upsert_recipient_rows(
            db, campaign_id, rows, app.config["ALLOWED_RECIPIENT_DOMAINS"]
        )
        log_audit_event(
            action="CAMPAIGN_TEST_GROUP_ADDED",
            target={"campaign_id": campaign_id},
            metadata={"accepted": imported, "rejected": len(rejected), "group": "phishguard_test_users"},
        )
        flash(f"Added or updated {imported} recipient(s) from the PhishGuard Test Users group.", "success")
        if rejected:
            preview = "; ".join(rejected[:5])
            more = " …" if len(rejected) > 5 else ""
            flash(f"Rejected {len(rejected)} test participant(s): {preview}{more}", "error")
        return redirect(url_for("campaign_detail", campaign_id=campaign_id))

    @app.post("/campaigns/<int:campaign_id>/import")
    @permission_required("manage_campaigns")
    def import_recipients(campaign_id: int) -> Any:
        db = get_db()
        campaign = db.execute("SELECT id FROM campaigns WHERE id = ?", (campaign_id,)).fetchone()
        if campaign is None:
            abort(404)
        upload = request.files.get("recipients")
        if upload is None or not upload.filename:
            flash("Choose a CSV file.", "error")
            return redirect(url_for("campaign_detail", campaign_id=campaign_id))

        try:
            text = upload.stream.read().decode("utf-8-sig")
            reader = csv.DictReader(io.StringIO(text))
        except UnicodeDecodeError:
            flash("CSV must use UTF-8 encoding.", "error")
            return redirect(url_for("campaign_detail", campaign_id=campaign_id))

        if not reader.fieldnames or "email" not in {
            name.strip().lower() for name in reader.fieldnames
        }:
            flash("CSV must contain an email column. first_name is optional.", "error")
            return redirect(url_for("campaign_detail", campaign_id=campaign_id))

        normalized_headers = {name: name.strip().lower() for name in reader.fieldnames}
        rows: list[tuple[str, str]] = []
        for raw_row in reader:
            row = {
                normalized_headers[k]: (v or "").strip()
                for k, v in raw_row.items()
                if k is not None
            }
            rows.append((row.get("email", "").lower(), row.get("first_name", "")[:80]))

        added_domains = authorize_recipient_domains(
            app,
            rows,
            request.form.get("authorize_recipient_domains") == "yes" and has_permission("manage_settings"),
        )
        if added_domains:
            flash(
                "Approved recipient domain(s): " + ", ".join(sorted(added_domains)),
                "success",
            )
        allowed_domains = app.config["ALLOWED_RECIPIENT_DOMAINS"]
        if not allowed_domains:
            flash(
                "No recipient domains are approved. Open Recipient domains or confirm authorization below.",
                "error",
            )
            return redirect(url_for("campaign_detail", campaign_id=campaign_id))

        imported, rejected = upsert_recipient_rows(db, campaign_id, rows, allowed_domains)
        log_audit_event(
            action="CAMPAIGN_RECIPIENTS_UPDATED",
            target={"campaign_id": campaign_id},
            metadata={"source": "csv", "accepted": imported, "rejected": len(rejected)},
        )
        flash(f"Imported or updated {imported} recipient(s).", "success")
        if rejected:
            preview = "; ".join(rejected[:5])
            more = " …" if len(rejected) > 5 else ""
            flash(f"Rejected {len(rejected)} row(s): {preview}{more}", "error")
        return redirect(url_for("campaign_detail", campaign_id=campaign_id))

    @app.get("/quiz-template")
    @permission_required("manage_campaigns")
    def download_quiz_template() -> Any:
        return send_from_directory(
            Path(__file__).with_name("sample_quizzes"),
            "phishing_awareness_5_question_quiz.json",
            as_attachment=True,
            download_name="phishing_awareness_5_question_quiz.json",
            mimetype="application/json",
            max_age=0,
        )

    @app.post("/campaigns/<int:campaign_id>/quiz")
    @permission_required("manage_campaigns")
    def upload_campaign_quiz(campaign_id: int) -> Any:
        db = get_db()
        campaign = db.execute("SELECT id FROM campaigns WHERE id = ?", (campaign_id,)).fetchone()
        if campaign is None:
            abort(404)
        try:
            document, original_name, upload_size = prepare_quiz_upload(
                request.files.get("quiz_file")
            )
        except ValueError as exc:
            log_audit_event(
                action="QUIZ_UPLOAD_REJECTED",
                outcome="WARNING",
                target={"campaign_id": campaign_id},
                metadata={"reason": str(exc)},
            )
            flash(str(exc), "error")
            return redirect(url_for("campaign_detail", campaign_id=campaign_id))

        existing = db.execute(
            "SELECT id FROM quizzes WHERE campaign_id = ?", (campaign_id,)
        ).fetchone()
        if existing:
            db.execute("DELETE FROM quizzes WHERE id = ?", (existing["id"],))
        timestamp = utc_now()
        db.execute(
            """
            INSERT INTO quizzes
                (campaign_id, title, passing_score, questions_json, original_filename,
                 created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                campaign_id,
                document["title"],
                document["passing_score"],
                json.dumps(document["questions"], separators=(",", ":"), ensure_ascii=False),
                original_name,
                timestamp,
                timestamp,
            ),
        )
        db.commit()
        log_audit_event(
            action="CAMPAIGN_QUIZ_UPLOADED",
            target={"campaign_id": campaign_id},
            metadata={
                "question_count": QUIZ_QUESTION_COUNT,
                "passing_score": document["passing_score"],
                "upload_bytes": upload_size,
                "replaced_existing_quiz": bool(existing),
            },
        )
        flash(
            f"Quiz uploaded with {QUIZ_QUESTION_COUNT} questions and a "
            f"{document['passing_score']}% passing score.",
            "success",
        )
        return redirect(url_for("campaign_detail", campaign_id=campaign_id))

    @app.post("/campaigns/<int:campaign_id>/quiz/delete")
    @permission_required("manage_campaigns")
    def delete_campaign_quiz(campaign_id: int) -> Any:
        db = get_db()
        result = db.execute("DELETE FROM quizzes WHERE campaign_id = ?", (campaign_id,))
        db.commit()
        if result.rowcount:
            log_audit_event(
                action="CAMPAIGN_QUIZ_REMOVED",
                target={"campaign_id": campaign_id},
            )
            flash("The campaign quiz and its attempt records were removed.", "success")
        else:
            flash("This campaign does not have a quiz.", "error")
        return redirect(url_for("campaign_detail", campaign_id=campaign_id))

    @app.post("/campaigns/<int:campaign_id>/media")
    @permission_required("manage_campaigns")
    def update_campaign_media(campaign_id: int) -> Any:
        db = get_db()
        campaign = db.execute("SELECT * FROM campaigns WHERE id = ?", (campaign_id,)).fetchone()
        if campaign is None:
            abort(404)

        failure_message = request.form.get("failure_message", "").strip()
        if len(failure_message) > 1000:
            flash("Failure-page message must be 1,000 characters or fewer.", "error")
            return redirect(url_for("campaign_detail", campaign_id=campaign_id))
        try:
            prepared = prepare_media_upload(app, request.files.get("failure_media"))
        except ValueError as exc:
            log_audit_event(
                action="MEDIA_UPLOAD_REJECTED",
                outcome="WARNING",
                target={"campaign_id": campaign_id},
                metadata={"control": MEDIA_UPLOAD_CONTROL_ID, "reason": str(exc)},
            )
            flash(str(exc), "error")
            return redirect(url_for("campaign_detail", campaign_id=campaign_id))

        new_media: tuple[str, str, str] | None = None
        if prepared:
            new_media = store_media(app, prepared)

        db.execute(
            """
            UPDATE campaigns
            SET failure_message = ?,
                media_filename = COALESCE(?, media_filename),
                media_original_name = COALESCE(?, media_original_name),
                media_mime = COALESCE(?, media_mime)
            WHERE id = ?
            """,
            (
                failure_message,
                new_media[0] if new_media else None,
                new_media[1] if new_media else None,
                new_media[2] if new_media else None,
                campaign_id,
            ),
        )
        db.commit()
        if new_media:
            delete_media_file(app, campaign["media_filename"])
        log_audit_event(
            action="CAMPAIGN_TRAINING_CONTENT_UPDATED",
            target={"campaign_id": campaign_id},
            metadata={
                "new_media_uploaded": bool(new_media),
                "training_media_bytes": prepared[3] if prepared else 0,
                "media_validation_control": MEDIA_UPLOAD_CONTROL_ID if prepared else "",
                "message_updated": True,
            },
        )
        flash("Failure-page content was updated.", "success")
        return redirect(url_for("campaign_detail", campaign_id=campaign_id))

    @app.post("/campaigns/<int:campaign_id>/media/delete")
    @permission_required("manage_campaigns")
    def delete_campaign_media(campaign_id: int) -> Any:
        db = get_db()
        campaign = db.execute("SELECT * FROM campaigns WHERE id = ?", (campaign_id,)).fetchone()
        if campaign is None:
            abort(404)
        delete_media_file(app, campaign["media_filename"])
        db.execute(
            """
            UPDATE campaigns
            SET media_filename = NULL, media_original_name = NULL, media_mime = NULL
            WHERE id = ?
            """,
            (campaign_id,),
        )
        db.commit()
        log_audit_event(
            action="CAMPAIGN_TRAINING_MEDIA_REMOVED",
            target={"campaign_id": campaign_id},
        )
        flash("Failure media was removed.", "success")
        return redirect(url_for("campaign_detail", campaign_id=campaign_id))

    @app.get("/campaigns/<int:campaign_id>/media")
    @permission_required("view_results")
    def admin_campaign_media(campaign_id: int) -> Any:
        campaign = get_db().execute(
            "SELECT media_filename, media_mime FROM campaigns WHERE id = ?", (campaign_id,)
        ).fetchone()
        if campaign is None or not campaign["media_filename"]:
            abort(404)
        return send_from_directory(
            app.config["MEDIA_DIR"],
            campaign["media_filename"],
            mimetype=campaign["media_mime"],
            conditional=True,
            max_age=0,
        )

    @app.post("/campaigns/<int:campaign_id>/dispatch")
    @permission_required("dispatch_campaigns")
    def dispatch_campaign(campaign_id: int) -> Any:
        db = get_db()
        campaign = db.execute("SELECT * FROM campaigns WHERE id = ?", (campaign_id,)).fetchone()
        if campaign is None:
            abort(404)
        if app.config["ENABLE_SMTP"]:
            readiness_issues = smtp_readiness_issues(app)
            if readiness_issues:
                log_audit_event(
                    action="CAMPAIGN_DISPATCH_BLOCKED",
                    target={"campaign_id": campaign_id},
                    outcome="DENIED",
                    metadata={"reason_count": len(readiness_issues), "mode": "SMTP"},
                )
                flash(
                    "Live delivery is not ready: " + " ".join(readiness_issues),
                    "error",
                )
                return redirect(url_for("campaign_detail", campaign_id=campaign_id))
        recipients = db.execute(
            "SELECT * FROM recipients WHERE campaign_id = ? ORDER BY id", (campaign_id,)
        ).fetchall()
        if not recipients:
            flash("Import or enter at least one recipient before dispatching.", "error")
            return redirect(url_for("campaign_detail", campaign_id=campaign_id))

        active_job = db.execute(
            """
            SELECT id FROM dispatch_jobs
            WHERE campaign_id = ? AND status IN ('queued', 'running')
            ORDER BY id DESC LIMIT 1
            """,
            (campaign_id,),
        ).fetchone()
        if active_job is not None:
            flash("This campaign already has a queued or running dispatch job.", "error")
            return redirect(url_for("campaign_detail", campaign_id=campaign_id))

        mode = "smtp" if app.config["ENABLE_SMTP"] else "preview"
        cursor = db.execute(
            """
            INSERT INTO dispatch_jobs
                (campaign_id, requested_by_user_id, mode, status, smtp_fingerprint,
                 total_recipients, created_at)
            VALUES (?, ?, ?, 'queued', ?, ?, ?)
            """,
            (
                campaign_id,
                int(g.current_user["id"]),
                mode,
                smtp_fingerprint(smtp_config_values(app)) if mode == "smtp" else "",
                len(recipients),
                utc_now(),
            ),
        )
        job_id = int(cursor.lastrowid)
        db.executemany(
            """
            INSERT INTO dispatch_job_recipients (job_id, recipient_id, status)
            VALUES (?, ?, 'queued')
            """,
            [(job_id, int(recipient["id"])) for recipient in recipients],
        )
        db.execute("UPDATE campaigns SET status = 'queued' WHERE id = ?", (campaign_id,))
        db.commit()
        log_audit_event(
            action="CAMPAIGN_DISPATCH_QUEUED",
            target={"campaign_id": campaign_id},
            metadata={
                "dispatch_job_id": job_id,
                "recipient_count": len(recipients),
                "mode": mode,
                "rate_per_minute": app.config["DISPATCH_RATE_PER_MINUTE"],
            },
        )

        if app.config.get("SYNCHRONOUS_DISPATCH"):
            process_dispatch_job(app, job_id)
            result = db.execute(
                "SELECT status, sent_recipients, failed_recipients FROM dispatch_jobs WHERE id = ?",
                (job_id,),
            ).fetchone()
            display_mode = "SMTP" if mode == "smtp" else "preview outbox"
            flash(
                f"Processed {result['sent_recipients']} message(s) through {display_mode}; "
                f"{result['failed_recipients']} failed.",
                "success" if result["sent_recipients"] else "error",
            )
        else:
            if app.config.get("BACKGROUND_DISPATCH_ENABLED"):
                start_dispatch_worker(app)
                app.extensions["dispatch_worker"]["wake"].set()
            display_mode = "SMTP" if mode == "smtp" else "preview outbox"
            flash(
                f"Queued {len(recipients)} message(s) for {display_mode}. Progress updates appear below.",
                "success",
            )
        return redirect(url_for("campaign_detail", campaign_id=campaign_id))

    @app.post("/campaigns/<int:campaign_id>/purge")
    @permission_required("delete_campaigns")
    def purge_campaign(campaign_id: int) -> Any:
        db = get_db()
        campaign = db.execute(
            "SELECT name, media_filename FROM campaigns WHERE id = ?", (campaign_id,)
        ).fetchone()
        if campaign:
            delete_media_file(app, campaign["media_filename"])
        result = db.execute("DELETE FROM campaigns WHERE id = ?", (campaign_id,))
        db.commit()
        if result.rowcount:
            log_audit_event(
                action="CAMPAIGN_PURGED",
                target={"campaign_id": campaign_id},
                metadata={"campaign_name": campaign["name"] if campaign else ""},
            )
            flash("Campaign and associated recipient, event, quiz, and attempt data were deleted.", "success")
        return redirect(url_for("dashboard"))

    def recipient_for_token(token: str) -> sqlite3.Row | None:
        if len(token) < 20 or len(token) > 200:
            return None
        return get_db().execute(
            """
            SELECT r.id, r.first_name, c.name AS campaign_name,
                   c.failure_message, c.media_filename, c.media_mime,
                   q.id AS quiz_id, q.title AS quiz_title,
                   q.passing_score AS quiz_passing_score, q.questions_json
            FROM recipients r
            JOIN campaigns c ON c.id = r.campaign_id
            LEFT JOIN quizzes q ON q.campaign_id = c.id
            WHERE r.token_digest = ?
            """,
            (token_digest(token),),
        ).fetchone()

    @app.get("/t/<token>")
    def training(token: str) -> Any:
        """Recipient click destination: reveal the simulation, then launch training."""
        recipient = recipient_for_token(token)
        if recipient is None:
            abort(404)
        record_event(get_db(), recipient["id"], "clicked")
        return render_template(
            "demo_reveal.html",
            token=token,
            first_name=recipient["first_name"],
            organization_name=app.config["ORGANIZATION_NAME"],
            failure_message=recipient["failure_message"],
            training_continue_url=url_for("training_lesson", token=token),
            campaign_mode=True,
        )

    @app.get("/t/<token>/lesson")
    def training_lesson(token: str) -> Any:
        """Existing individualized lesson/quiz reached after the reveal video."""
        recipient = recipient_for_token(token)
        if recipient is None:
            abort(404)
        quiz = None
        if recipient["quiz_id"]:
            quiz = quiz_for_participant(
                {
                    "title": recipient["quiz_title"],
                    "passing_score": recipient["quiz_passing_score"],
                    "questions": json.loads(recipient["questions_json"]),
                }
            )
        return render_template(
            "training.html",
            token=token,
            first_name=recipient["first_name"],
            organization_name=app.config["ORGANIZATION_NAME"],
            failure_message=recipient["failure_message"],
            media_mime=recipient["media_mime"],
            has_media=bool(recipient["media_filename"]),
            quiz=quiz,
            quiz_error=None,
            quiz_feedback=None,
            quiz_score=None,
            selected_answers={},
        )

    @app.get("/t/<token>/media")
    def training_media(token: str) -> Any:
        recipient = recipient_for_token(token)
        if recipient is None or not recipient["media_filename"]:
            abort(404)
        return send_from_directory(
            app.config["MEDIA_DIR"],
            recipient["media_filename"],
            mimetype=recipient["media_mime"],
            conditional=True,
            max_age=0,
        )

    @app.post("/t/<token>/complete")
    def complete_training(token: str) -> Any:
        recipient = recipient_for_token(token)
        if recipient is None:
            abort(404)
        if recipient["quiz_id"]:
            abort(400, description="Complete the required training quiz.")
        if request.form.get("acknowledged") != "yes":
            abort(400, description="Training acknowledgment is required")
        record_event(get_db(), recipient["id"], "completed")
        return render_template(
            "completed.html",
            organization_name=app.config["ORGANIZATION_NAME"],
            quiz_score=None,
        )

    @app.post("/t/<token>/quiz")
    def submit_training_quiz(token: str) -> Any:
        recipient = recipient_for_token(token)
        if recipient is None or not recipient["quiz_id"]:
            abort(404)
        document = {
            "title": recipient["quiz_title"],
            "passing_score": recipient["quiz_passing_score"],
            "questions": json.loads(recipient["questions_json"]),
        }
        public_quiz = quiz_for_participant(document)
        selected_answers = {
            f"question_{index}": request.form.get(f"question_{index}", "")
            for index in range(QUIZ_QUESTION_COUNT)
        }
        try:
            answers, correct_count, feedback = score_quiz_submission(
                document, selected_answers
            )
        except ValueError as exc:
            return (
                render_template(
                    "training.html",
                    token=token,
                    first_name=recipient["first_name"],
                    organization_name=app.config["ORGANIZATION_NAME"],
                    failure_message=recipient["failure_message"],
                    media_mime=recipient["media_mime"],
                    has_media=bool(recipient["media_filename"]),
                    quiz=public_quiz,
                    quiz_error=str(exc),
                    quiz_feedback=None,
                    quiz_score=None,
                    selected_answers=selected_answers,
                ),
                400,
            )

        score_percent = round((correct_count / QUIZ_QUESTION_COUNT) * 100)
        passed = score_percent >= document["passing_score"]
        db = get_db()
        db.execute(
            """
            INSERT INTO quiz_attempts
                (quiz_id, recipient_id, score_percent, correct_answers,
                 total_questions, passed, answers_json, submitted_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                recipient["quiz_id"],
                recipient["id"],
                score_percent,
                correct_count,
                QUIZ_QUESTION_COUNT,
                int(passed),
                json.dumps(answers, separators=(",", ":")),
                utc_now(),
            ),
        )
        db.commit()
        log_audit_event(
            action="TRAINING_QUIZ_SUBMITTED",
            outcome="SUCCESS" if passed else "WARNING",
            target={"recipient_id": recipient["id"], "quiz_id": recipient["quiz_id"]},
            metadata={
                "score_percent": score_percent,
                "correct_answers": correct_count,
                "question_count": QUIZ_QUESTION_COUNT,
                "passed": passed,
            },
        )
        if passed:
            record_event(db, recipient["id"], "completed")
            return render_template(
                "completed.html",
                organization_name=app.config["ORGANIZATION_NAME"],
                quiz_score=score_percent,
            )
        return render_template(
            "training.html",
            token=token,
            first_name=recipient["first_name"],
            organization_name=app.config["ORGANIZATION_NAME"],
            failure_message=recipient["failure_message"],
            media_mime=recipient["media_mime"],
            has_media=bool(recipient["media_filename"]),
            quiz=public_quiz,
            quiz_error=(
                f"Your score was {score_percent}%. Review the explanations and try again. "
                f"A score of {document['passing_score']}% is required."
            ),
            quiz_feedback=feedback,
            quiz_score=score_percent,
            selected_answers=selected_answers,
        )


app = create_app()

if __name__ == "__main__":
    app.run(debug=False)
