from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

AUDIT_LOG_PATH = os.environ.get("NETWAY_AUDIT_LOG", "/tmp/netway_audit.jsonl")


def log_event(event_type: str, details: dict) -> None:
    """Append an audit event to the audit log."""
    entry = {
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "event_type": event_type,
        **details,
    }
    try:
        with open(AUDIT_LOG_PATH, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except Exception as exc:
        logger.warning("Audit log write failed: %s", exc)
