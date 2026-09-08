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

import json
import ipaddress
import sqlite3
from pathlib import Path
from typing import Optional


_SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def _unclustered_result() -> dict:
    """Return a fresh safe result before clustering is available."""
    return {
        "campaign_id": None,
        "linked_emails": [],
        "cluster_size": 1,
        "match_reason": [],
    }


def _ipv4_block(ip_address: object) -> Optional[str]:
    """Return the /24 prefix for a valid IPv4 address, else ``None``."""
    try:
        parsed_address = ipaddress.ip_address(ip_address)
        if not isinstance(parsed_address, ipaddress.IPv4Address):
            return None
        return ".".join(str(parsed_address).split(".")[:3])
    except (ValueError, TypeError):
        return None


def _insert_edges(
    connection: sqlite3.Connection,
    email_id: str,
    matched_email_ids: list[str],
    reason: str,
) -> None:
    """Persist one reason-specific directed edge for every matching email."""
    connection.executemany(
        "INSERT INTO edges (email_id_a, email_id_b, reason) VALUES (?, ?, ?)",
        [(email_id, matched_email_id, reason) for matched_email_id in matched_email_ids],
    )


def _write_matching_edges(
    connection: sqlite3.Connection,
    email_id: str,
    origin_ip: object,
    impersonated_domain: object,
) -> None:
    """Apply the three persistence-backed correlation rules for one email."""
    if origin_ip is not None:
        same_origin_ip = connection.execute(
            "SELECT email_id FROM emails WHERE origin_ip = ? AND email_id != ?",
            (origin_ip, email_id),
        ).fetchall()
        _insert_edges(
            connection,
            email_id,
            [matched_email_id for (matched_email_id,) in same_origin_ip],
            "same_origin_ip",
        )

    current_ip_block = _ipv4_block(origin_ip)
    if current_ip_block is not None:
        possible_ip_block_matches = connection.execute(
            "SELECT email_id, origin_ip FROM emails "
            "WHERE email_id != ? AND origin_ip IS NOT NULL",
            (email_id,),
        ).fetchall()
        _insert_edges(
            connection,
            email_id,
            [
                matched_email_id
                for matched_email_id, matched_origin_ip in possible_ip_block_matches
                if _ipv4_block(matched_origin_ip) == current_ip_block
            ],
            "same_ip_block",
        )

    if impersonated_domain is not None:
        same_impersonated_domain = connection.execute(
            """
            SELECT email_id FROM emails
            WHERE impersonated_domain = ?
              AND impersonated_domain IS NOT NULL
              AND email_id != ?
            """,
            (impersonated_domain, email_id),
        ).fetchall()
        _insert_edges(
            connection,
            email_id,
            [matched_email_id for (matched_email_id,) in same_impersonated_domain],
            "same_impersonated_domain",
        )


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

    Args:
        record:  The combined pipeline record assembled by dashboard/pipeline.py.
        db_path: Path to the SQLite database file.

    Returns:
        A dict with keys: campaign_id, linked_emails, cluster_size, match_reason.
    """
    connection = None
    try:
        if not isinstance(record, dict) or not record.get("email_id"):
            return _unclustered_result()

        parsed = record.get("parsed")
        typosquat = record.get("typosquat")
        parsed = parsed if isinstance(parsed, dict) else {}
        typosquat = typosquat if isinstance(typosquat, dict) else {}

        connection = open_connection(db_path)
        if connection is None:
            return _unclustered_result()

        connection.execute(
            """
            INSERT OR REPLACE INTO emails
                (email_id, sender_domain, origin_ip, impersonated_domain, raw_record)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                record["email_id"],
                parsed.get("sender_domain"),
                parsed.get("origin_ip"),
                typosquat.get("closest_match"),
                json.dumps(record, default=str),
            ),
        )
        _write_matching_edges(
            connection,
            record["email_id"],
            parsed.get("origin_ip"),
            typosquat.get("closest_match"),
        )
        connection.commit()
    except Exception:
        return _unclustered_result()
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass

    return _unclustered_result()
