"""PhishGuard audit logging and in-memory login lockout support.

Integrated from the user-supplied ``audit_logger (2).py`` on 2026-09-02.
The supplied JSON event schema and three-failure/five-minute lockout behavior
are retained, with application-required startup safety, privacy redaction,
thread safety, request-route context, and audit-viewer helpers layered on top.
"""

import json
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from threading import Lock
from typing import Any

from flask import g, has_app_context, has_request_context, request

AUDIT_LOGGER_INTEGRATION_VERSION = "2026.09.02.2"

# ==========================================
# 1. AUDIT LOGGING CORE
# ==========================================
audit_logger = logging.getLogger("PhishGuardAudit")
audit_logger.setLevel(logging.INFO)
audit_logger.propagate = False

_handler: logging.FileHandler | None = None
_tracker_lock = Lock()

# Never persist these fields even if a caller accidentally supplies them.
SENSITIVE_AUDIT_KEYS = {
    "password",
    "password_hash",
    "smtp_password",
    "secret_key",
    "token",
    "token_digest",
    "raw_ip",
    "ip_address",
    "remote_addr",
    "path",
    "full_path",
    "query_string",
    "url",
}


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if key_text.lower() in SENSITIVE_AUDIT_KEYS:
                clean[key_text] = "[REDACTED]"
            else:
                clean[key_text] = _sanitize(item)
        return clean
    if isinstance(value, (list, tuple, set)):
        return [_sanitize(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def configure_audit_logging(log_file: str | Path) -> Path:
    """Configure the JSON-lines audit file after the Flask instance path exists."""
    global _handler

    log_path = Path(log_file).expanduser().resolve()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    if _handler is not None:
        audit_logger.removeHandler(_handler)
        _handler.close()

    _handler = logging.FileHandler(log_path, encoding="utf-8")
    _handler.setFormatter(logging.Formatter("%(message)s"))
    audit_logger.addHandler(_handler)
    return log_path


def log_audit_event(action, outcome="SUCCESS", target=None, metadata=None):
    """
    Writes structured, JSON-formatted logs for administrative and security events.
    Adheres strictly to PhishGuard privacy boundaries (no raw IP/password capture).
    """
    actor = {
        "user_id": "system/anonymous",
        "role": "unknown",
    }
    if has_app_context():
        actor = {
            "user_id": getattr(g, "user_id", "system/anonymous"),
            "role": getattr(g, "user_role", "unknown"),
        }

    clean_metadata = _sanitize(metadata or {})
    if not isinstance(clean_metadata, dict):
        clean_metadata = {"details": clean_metadata}
    clean_metadata.pop("request", None)

    # Record the matched route pattern rather than request.path. This gives
    # administrators useful context without persisting recipient training
    # tokens, query strings, client addresses, or other request payload data.
    if has_request_context():
        matched_rule = request.url_rule
        route_rule = matched_rule.rule if matched_rule is not None else "unmatched"
        endpoint = matched_rule.endpoint if matched_rule is not None else "unmatched"
        clean_metadata["request"] = {
            "method": request.method,
            "endpoint": endpoint,
            "route": route_rule,
        }

    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor": actor,
        "action": str(action),
        "target": _sanitize(target or {}),
        "outcome": str(outcome),
        "metadata": clean_metadata,
    }
    audit_logger.info(json.dumps(log_entry, sort_keys=True))


# ==========================================
# 2. IN-MEMORY BRUTE-FORCE TRACKER
# ==========================================
# Stores attempt state: {"username": {"count": int, "last_attempt": datetime}}
FAILED_ATTEMPTS = {}
MAX_ALLOWED_FAILURES = 3
LOCKOUT_MINUTES = 5


def _key(username: str) -> str:
    return (username or "").strip().casefold()


def check_account_lockout(username):
    """
    Checks if an account is currently blocked due to excessive failed logins.
    Returns True if allowed, False if locked out.
    """
    now = datetime.now(timezone.utc)
    username_key = _key(username)
    with _tracker_lock:
        record = FAILED_ATTEMPTS.get(username_key)

        if record:
            is_max_reached = record["count"] >= MAX_ALLOWED_FAILURES
            time_elapsed = now - record["last_attempt"]

            if is_max_reached and time_elapsed < timedelta(minutes=LOCKOUT_MINUTES):
                return False  # Locked out

            if time_elapsed >= timedelta(minutes=LOCKOUT_MINUTES):
                # Reset after cooldown period expires
                FAILED_ATTEMPTS.pop(username_key, None)

    return True


def record_login_failure(username):
    """
    Increments failure counts and triggers a security alert log when threshold is breached.
    """
    now = datetime.now(timezone.utc)
    username_key = _key(username)
    with _tracker_lock:
        if username_key not in FAILED_ATTEMPTS:
            FAILED_ATTEMPTS[username_key] = {"count": 1, "last_attempt": now}
        else:
            FAILED_ATTEMPTS[username_key]["count"] += 1
            FAILED_ATTEMPTS[username_key]["last_attempt"] = now
        current_count = FAILED_ATTEMPTS[username_key]["count"]

    # Log standard failure
    log_audit_event(
        action="LOGIN_FAILED",
        outcome="FAILURE",
        target={"username": username},
        metadata={"consecutive_failures": current_count},
    )

    # Trigger brute-force alert log if threshold reached
    if current_count >= MAX_ALLOWED_FAILURES:
        log_audit_event(
            action="SECURITY_ALERT_BRUTE_FORCE_DETECTED",
            outcome="WARNING",
            target={"username": username},
            metadata={
                "consecutive_failures": current_count,
                "lockout_duration_minutes": LOCKOUT_MINUTES,
            },
        )


def record_login_success(username):
    """
    Resets the failed counter upon successful authentication and logs the login.
    """
    with _tracker_lock:
        FAILED_ATTEMPTS.pop(_key(username), None)
    log_audit_event(
        action="LOGIN_SUCCESS",
        outcome="SUCCESS",
        target={"username": username},
    )


def reset_login_failure_tracker() -> None:
    """Clear in-memory attempt state. Used by isolated test application instances."""
    with _tracker_lock:
        FAILED_ATTEMPTS.clear()


def read_recent_audit_events(log_file: str | Path, limit: int = 250) -> list[dict[str, Any]]:
    """Read the newest audit records for the Administrator-only audit viewer."""
    limit = max(1, min(int(limit), 1000))
    path = Path(log_file)
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]
    events: list[dict[str, Any]] = []
    for line in reversed(lines):
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            item = {
                "timestamp": "",
                "actor": {"user_id": "unknown", "role": "unknown"},
                "action": "UNPARSEABLE_LOG_ENTRY",
                "target": {},
                "outcome": "WARNING",
                "metadata": {"message": "A non-JSON audit line was encountered."},
            }
        events.append(item)
    return events
