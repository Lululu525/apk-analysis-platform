import sqlite3
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parents[2]
DB_PATH = APP_ROOT / "metadata" / "metadata.db"

def get_conn():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(DB_PATH)

def init_db():
    with get_conn() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS samples (
          sample_id TEXT PRIMARY KEY,
          sha256 TEXT NOT NULL,
          filename TEXT NOT NULL,
          uploaded_at TEXT NOT NULL,
          storage_path TEXT NOT NULL,
          status TEXT NOT NULL
        );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_samples_sha256 ON samples(sha256);")
        conn.commit()

def insert_sample(sample_id: str, sha256: str, filename: str, uploaded_at: str, storage_path: str, status: str):
    with get_conn() as conn:
        conn.execute("""
        INSERT INTO samples(sample_id, sha256, filename, uploaded_at, storage_path, status)
        VALUES (?, ?, ?, ?, ?, ?);
        """, (sample_id, sha256, filename, uploaded_at, storage_path, status))
        conn.commit()

def get_sample_by_id(sample_id: str):
    with get_conn() as conn:
        cursor = conn.execute("""
        SELECT sample_id, sha256, filename, uploaded_at, storage_path, status
        FROM samples
        WHERE sample_id = ?
        """, (sample_id,))
        row = cursor.fetchone()
        return row

def list_samples(limit: int = 20):
    with get_conn() as conn:
        cursor = conn.execute("""
        SELECT sample_id, sha256, filename, uploaded_at, storage_path, status
        FROM samples
        ORDER BY uploaded_at DESC
        LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        return rows

def update_sample_status(sample_id: str, status: str):
    with get_conn() as conn:
        cur = conn.execute("""
        UPDATE samples
        SET status = ?
        WHERE sample_id = ?
        """, (status, sample_id))
        conn.commit()
        return cur.rowcount