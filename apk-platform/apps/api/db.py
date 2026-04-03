import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[2] / "metadata" / "metadata.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    return conn


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS samples (
            sample_id TEXT PRIMARY KEY,
            sha256 TEXT NOT NULL,
            filename TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            storage_path TEXT NOT NULL,
            status TEXT NOT NULL
        )
        """
    )

    conn.commit()
    conn.close()


def insert_sample(
    sample_id: str,
    sha256: str,
    filename: str,
    uploaded_at: str,
    storage_path: str,
    status: str,
):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO samples (
            sample_id,
            sha256,
            filename,
            uploaded_at,
            storage_path,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (sample_id, sha256, filename, uploaded_at, storage_path, status),
    )

    conn.commit()
    conn.close()


def get_sample_by_id(sample_id: str):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT sample_id, sha256, filename, uploaded_at, storage_path, status
        FROM samples
        WHERE sample_id = ?
        """,
        (sample_id,),
    )

    row = cur.fetchone()
    conn.close()
    return row


def update_sample_status(sample_id: str, status: str) -> int:
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        UPDATE samples
        SET status = ?
        WHERE sample_id = ?
        """,
        (status, sample_id),
    )

    updated = cur.rowcount
    conn.commit()
    conn.close()
    return updated


def list_samples(limit: int = 20):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT sample_id, sha256, filename, uploaded_at, storage_path, status
        FROM samples
        ORDER BY uploaded_at DESC
        LIMIT ?
        """,
        (limit,),
    )

    rows = cur.fetchall()
    conn.close()
    return rows


def count_samples(query: str | None = None) -> int:
    conn = get_connection()
    cur = conn.cursor()

    if query and query.strip():
        keyword = f"%{query.strip()}%"
        cur.execute(
            """
            SELECT COUNT(*)
            FROM samples
            WHERE filename LIKE ?
            """,
            (keyword,),
        )
    else:
        cur.execute(
            """
            SELECT COUNT(*)
            FROM samples
            """
        )

    total = cur.fetchone()[0]
    conn.close()
    return total


def list_samples_paginated(limit: int, offset: int, query: str | None = None):
    conn = get_connection()
    cur = conn.cursor()

    if query and query.strip():
        keyword = f"%{query.strip()}%"
        cur.execute(
            """
            SELECT sample_id, sha256, filename, uploaded_at, storage_path, status
            FROM samples
            WHERE filename LIKE ?
            ORDER BY uploaded_at DESC
            LIMIT ? OFFSET ?
            """,
            (keyword, limit, offset),
        )
    else:
        cur.execute(
            """
            SELECT sample_id, sha256, filename, uploaded_at, storage_path, status
            FROM samples
            ORDER BY uploaded_at DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        )

    rows = cur.fetchall()
    conn.close()
    return rows