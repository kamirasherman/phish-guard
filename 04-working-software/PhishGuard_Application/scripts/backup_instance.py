from __future__ import annotations

import json
import os
import shutil
import sqlite3
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def main() -> int:
    destination = Path(sys.argv[1] if len(sys.argv) > 1 else "/backups").resolve()
    instance = Path(os.getenv("PHISHGUARD_INSTANCE_DIR", "/app/instance")).resolve()
    database = instance / "trainer.sqlite"
    if not database.exists():
        print(f"No database exists at {database}.", file=sys.stderr)
        return 1

    destination.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive = destination / f"phishguard-backup-{stamp}.tar.gz"

    with tempfile.TemporaryDirectory(prefix="phishguard-backup-") as temporary:
        staging = Path(temporary) / "instance"
        staging.mkdir()
        source_db = sqlite3.connect(database)
        backup_db = sqlite3.connect(staging / "trainer.sqlite")
        try:
            source_db.backup(backup_db)
        finally:
            backup_db.close()
            source_db.close()

        for filename in ("smtp_settings.json", "allowed_domains.txt", "audit.log"):
            source = instance / filename
            if source.exists():
                shutil.copy2(source, staging / filename)
        for directory_name in ("campaign_media", "outbox"):
            source = instance / directory_name
            if source.exists():
                shutil.copytree(source, staging / directory_name)
        (staging / "backup_manifest.json").write_text(
            json.dumps(
                {
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "warning": "Archive may contain SMTP credentials and recipient data; encrypt and restrict access.",
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        with tarfile.open(archive, "w:gz") as bundle:
            bundle.add(staging, arcname="instance")

    print(archive)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
