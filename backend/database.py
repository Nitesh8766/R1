"""
database.py
------------
Lightweight SQLite storage for analysis history. Stores a summary row per
analysis plus the full structured result as JSON, so a history entry can
be reopened later without re-analyzing the file.
"""

import sqlite3
import json
import os
import time

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "history.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            sha256 TEXT,
            timestamp TEXT NOT NULL,
            raw_score INTEGER,
            normalized_score INTEGER,
            verdict TEXT,
            finding_count INTEGER,
            result_json TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def save_analysis(result: dict) -> int:
    """Stores a completed analysis result dict and returns its history id.
    Skips storage silently if the analysis didn't produce a real verdict
    (e.g. missing/empty/unreadable file) -- nothing meaningful to record."""
    if result.get("error") or result["risk"].get("verdict") is None:
        return None

    conn = get_connection()
    cur = conn.execute(
        """INSERT INTO analyses
           (filename, sha256, timestamp, raw_score, normalized_score, verdict, finding_count, result_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            result["file"]["name"],
            result["file"]["sha256"],
            time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            result["risk"]["raw_score"],
            result["risk"]["normalized_score"],
            result["risk"]["verdict"],
            len(result["findings"]),
            json.dumps(result),
        ),
    )
    conn.commit()
    new_id = cur.lastrowid
    conn.close()
    return new_id


def get_recent(limit=20):
    conn = get_connection()
    rows = conn.execute(
        """SELECT id, filename, sha256, timestamp, raw_score, normalized_score,
                  verdict, finding_count
           FROM analyses ORDER BY id DESC LIMIT ?""",
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_by_id(analysis_id: int):
    conn = get_connection()
    row = conn.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
    conn.close()
    if row is None:
        return None
    record = dict(row)
    record["result"] = json.loads(record.pop("result_json"))
    return record
