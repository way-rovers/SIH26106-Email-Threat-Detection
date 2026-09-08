"""
correlation_graph/main.py — Person 3: cross-email campaign correlation.

Public contract:
    correlate(record: dict, db_path: str = "data/campaigns.db") -> dict

Return shape:
{
    "campaign_id":   str | None,   # null if no cluster match found
    "linked_emails": [str],        # other email_ids in the same cluster
    "cluster_size":  int,
    "match_reason":  [str],        # e.g. ["same_origin_ip", "same_impersonated_domain"]
}

*record* is the combined pipeline dict assembled so far (see dashboard/pipeline.py).

Rules:
- Never raise an exception.
- Reads AND writes SQLite at db_path so it has memory across emails.
  "Same infrastructure" = same origin_ip, same /24 IP block, or same
  closest_match brand from the typosquat result.
- schema.sql defines the tables; use it when initialising a fresh DB.
"""

import sqlite3
from pathlib import Path
from typing import Optional


_SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def open_connection(db_path: str) -> Optional[sqlite3.Connection]:
    """Open *db_path* and initialise the correlation tables if necessary.

    Returns ``None`` if SQLite or filesystem setup fails, letting callers
    preserve the module's never-raise public contract.  Callers that receive
    a connection own it and must close it when finished.
    """
    connection = None
    try:
        database_path = Path(db_path)
        if database_path.parent != Path("."):
            database_path.parent.mkdir(parents=True, exist_ok=True)

        connection = sqlite3.connect(str(database_path))
        with _SCHEMA_PATH.open(encoding="utf-8") as schema_file:
            connection.executescript(schema_file.read())
        return connection
    except (OSError, sqlite3.Error, TypeError, ValueError):
        if connection is not None:
            connection.close()
        return None


def correlate(record: dict, db_path: str = "data/campaigns.db") -> dict:
    """Correlate *record* against previously-seen emails in *db_path*.

    STUB — currently returns hardcoded example data. Replace with real
    SQLite read/write + graph clustering logic in Phase 1.

    Args:
        record:  The combined pipeline record assembled by dashboard/pipeline.py.
        db_path: Path to the SQLite database file.

    Returns:
        A dict with keys: campaign_id, linked_emails, cluster_size, match_reason.
    """
    # HARDCODED STUB — replace with real DB read/write + union-find in Phase 1.
    return {
        "campaign_id": "CAMP-001",
        "linked_emails": ["phish-002@micros0ft-support.com"],
        "cluster_size": 2,
        "match_reason": ["same_origin_ip", "same_impersonated_domain"],
    }
