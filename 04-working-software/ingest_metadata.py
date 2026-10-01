"""
PhishGuard Data Ingestion & PII Redaction Pipeline
----------------------------------------------------
Remediated version — 2026-09-13.

Change from the prior version: DB_PASS and the PII-hashing salt are now
REQUIRED environment variables with no hardcoded fallback value. If either
is missing at process start, the module fails closed (raises immediately)
instead of silently falling back to a shared, hardcoded secret.

This closes the gap between the project's governance record (Week 6 notes,
Sprint 2 Review Packet, Lessons Learned — all of which state the hardcoded-
secrets issue was fixed 8/14/26 and verified 8/18/26) and the pipeline code
actually in use, which still contained a hardcoded DB password fallback and
a hardcoded, non-secret salt as of the 9/13/26 review.
"""

import os
import hashlib
import psycopg2
from datetime import datetime, timezone
from collections import defaultdict


class MissingSecretError(RuntimeError):
    """Raised when a required secret is not present in the environment.

    Fails closed on purpose: this pipeline handles PII-adjacent data, so it
    must never start with a guessable, hardcoded, or shared default in
    place of a real secret.
    """


def _require_env(var_name: str) -> str:
    value = os.getenv(var_name)
    if not value:
        raise MissingSecretError(
            f"Required environment variable '{var_name}' is not set. "
            "Refusing to start with a hardcoded fallback."
        )
    return value


# Container Network Configuration
# Connection host/name/user are non-secret configuration and may keep sane
# defaults for local/dev use. DB_PASS and the PII salt are secrets and are
# required from the environment with no fallback.
DB_HOST = os.getenv("METADATA_DB_HOST", "phishguard-db-container")
DB_NAME = os.getenv("METADATA_DB_NAME", "phish_analytics")
DB_USER = os.getenv("METADATA_DB_USER", "analytics_writer")
DB_PORT = os.getenv("METADATA_DB_PORT", "5432")

DB_PASS = _require_env("METADATA_DB_PASS")
PII_HASH_SALT = _require_env("PHISHGUARD_PII_SALT")


def redact_pii_email(email_str: str) -> str | None:
    """Hashes target email with the project salt to prevent PII storage.

    The salt is now pulled from PHISHGUARD_PII_SALT at process start
    (see PII_HASH_SALT above) rather than hardcoded in source, so it can be
    rotated and kept out of version control like any other secret.
    """
    if not email_str:
        return None
    salted_email = email_str.strip().lower() + PII_HASH_SALT
    return hashlib.sha256(salted_email.encode("utf-8")).hexdigest()[:16]


def sanitize_ip_address(ip_str: str) -> str | None:
    """Masks IPv4 last octet for non-PII network analytics."""
    if not ip_str:
        return None
    if "." in ip_str:
        parts = ip_str.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0"
    return "Anonymized_IP"


def parse_and_filter_event(raw_payload: dict) -> dict:
    """Main Engine: Filters out PII and body content, returning analytics metadata."""
    event_type = raw_payload.get("event_type", "").lower()

    return {
        "campaign_id": raw_payload.get("campaign_id"),
        "target_id_hash": redact_pii_email(raw_payload.get("target_email")),
        "event_type": raw_payload.get("event_type"),
        "masked_source_ip": sanitize_ip_address(raw_payload.get("source_ip")),
        "is_mobile": "Mobile" in raw_payload.get("user_agent", ""),
        "is_failure": any(fail_word in event_type for fail_word in ["click", "submit", "credential"]),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def process_and_analyze_batch(raw_payloads: list):
    """
    Processes a batch of raw payloads: sanitizes them, evaluates repeat offenders,
    computes campaign metrics, and dispatches records to the secure container database.

    Note on "repeat offenders": these counts are keyed to a salted, truncated
    hash of the target email, not the email itself. That makes the value
    pseudonymous and linkable across events for the same person within this
    dataset — useful for identifying who needs follow-up training — but it is
    not anonymous in the strict sense, since a person can still be tracked by
    their consistent hash across the batch. Document it as pseudonymized
    tracking, not anonymous tracking, in any client-facing material.
    """
    if not raw_payloads:
        return {"processed_count": 0, "message": "No payloads provided."}

    conn = psycopg2.connect(
        host=DB_HOST, dbname=DB_NAME, user=DB_USER, password=DB_PASS, port=DB_PORT
    )
    cursor = conn.cursor()

    # In-memory tracking for trend/repeat analysis across the current batch
    user_failure_tracker = defaultdict(int)

    insert_query = """
        INSERT INTO phishing_event_analytics
        (campaign_id, target_hash, event_type, source_ip_masked, is_mobile, timestamp)
        VALUES (%s, %s, %s, %s, %s, %s);
    """

    parsed_events = []
    try:
        for raw in raw_payloads:
            clean_meta = parse_and_filter_event(raw)
            parsed_events.append(clean_meta)

            # Track failures for repeat offender logic
            if clean_meta["is_failure"] and clean_meta["target_id_hash"]:
                user_failure_tracker[clean_meta["target_id_hash"]] += 1

            # Save sanitized event to isolated container database
            cursor.execute(insert_query, (
                clean_meta["campaign_id"],
                clean_meta["target_id_hash"],
                clean_meta["event_type"],
                clean_meta["masked_source_ip"],
                clean_meta["is_mobile"],
                clean_meta["timestamp"],
            ))

        conn.commit()
    finally:
        cursor.close()
        conn.close()

    # Identify repeat offenders (2+ failures) — see docstring note on pseudonymity above
    repeat_offenders = {uhash: count for uhash, count in user_failure_tracker.items() if count > 1}

    # Calculate campaign metrics for the team
    total_processed = len(parsed_events)
    total_failures = sum(1 for e in parsed_events if e["is_failure"])
    total_successes = total_processed - total_failures

    failure_rate = (total_failures / total_processed * 100) if total_processed > 0 else 0
    success_rate = (total_successes / total_processed * 100) if total_processed > 0 else 0

    return {
        "processed_count": total_processed,
        "total_failures": total_failures,
        "total_successes": total_successes,
        "failure_rate_pct": round(failure_rate, 2),
        "success_rate_pct": round(success_rate, 2),
        "repeat_offenders_flagged": len(repeat_offenders),
    }


if __name__ == "__main__":
    # Test stub for pipeline execution
    pass
