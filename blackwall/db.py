"""SQLite depolama katmanı.

Hem mitmproxy addon'u (yazıcı) hem de FastAPI uygulaması (okuyucu/yazıcı) aynı
dosyayı açar. Süreçler arası eşzamanlı erişim için WAL modu kullanılır.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional

# DB yolu ortam değişkeni ile override edilebilir (addon ve web aynı değeri kullanmalı).
DB_PATH = Path(os.environ.get("BLACKWALL_DB", Path(__file__).resolve().parent.parent / "blackwall.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    REAL NOT NULL,          -- unix epoch (saniye)
    source        TEXT NOT NULL DEFAULT 'proxy',  -- 'proxy' | 'repeater'
    method        TEXT NOT NULL,
    scheme        TEXT NOT NULL,
    host          TEXT NOT NULL,
    port          INTEGER NOT NULL,
    path          TEXT NOT NULL,          -- query dahil
    url           TEXT NOT NULL,
    http_version  TEXT,
    req_headers   TEXT NOT NULL,          -- JSON: [[isim, değer], ...]
    req_body      BLOB,
    status_code   INTEGER,
    reason        TEXT,
    resp_headers  TEXT,                   -- JSON: [[isim, değer], ...]
    resp_body     BLOB,
    duration_ms   REAL,                   -- istek-yanıt süresi
    error         TEXT
);
CREATE INDEX IF NOT EXISTS idx_flows_created_at ON flows (created_at);
CREATE INDEX IF NOT EXISTS idx_flows_host ON flows (host);
"""


def connect() -> sqlite3.Connection:
    """WAL modunda bir bağlantı açar. Her çağıran kendi bağlantısını yönetmeli."""
    conn = sqlite3.connect(str(DB_PATH), timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=15000;")
    return conn


def init_db() -> None:
    conn = connect()
    try:
        conn.executescript(SCHEMA)
    finally:
        conn.close()


def _dumps(headers: Any) -> str:
    return json.dumps(headers, ensure_ascii=False)


def insert_flow(
    conn: sqlite3.Connection,
    *,
    source: str,
    method: str,
    scheme: str,
    host: str,
    port: int,
    path: str,
    url: str,
    http_version: Optional[str],
    req_headers: list[tuple[str, str]],
    req_body: Optional[bytes],
    status_code: Optional[int] = None,
    reason: Optional[str] = None,
    resp_headers: Optional[list[tuple[str, str]]] = None,
    resp_body: Optional[bytes] = None,
    duration_ms: Optional[float] = None,
    error: Optional[str] = None,
    created_at: Optional[float] = None,
) -> int:
    cur = conn.execute(
        """
        INSERT INTO flows (
            created_at, source, method, scheme, host, port, path, url, http_version,
            req_headers, req_body, status_code, reason, resp_headers, resp_body,
            duration_ms, error
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            created_at if created_at is not None else time.time(),
            source,
            method,
            scheme,
            host,
            port,
            path,
            url,
            http_version,
            _dumps(req_headers),
            req_body,
            status_code,
            reason,
            _dumps(resp_headers) if resp_headers is not None else None,
            resp_body,
            duration_ms,
            error,
        ),
    )
    return int(cur.lastrowid)


def list_flows(
    conn: sqlite3.Connection,
    *,
    limit: int = 200,
    offset: int = 0,
    q: Optional[str] = None,
) -> list[dict]:
    """History tablosu için özet satırlar (gövdeler hariç)."""
    sql = [
        "SELECT id, created_at, source, method, scheme, host, port, path, url,",
        "       status_code, reason, duration_ms, error,",
        "       LENGTH(resp_body) AS resp_size",
        "FROM flows",
    ]
    args: list[Any] = []
    if q:
        sql.append("WHERE url LIKE ? OR host LIKE ? OR method LIKE ?")
        like = f"%{q}%"
        args += [like, like, like]
    sql.append("ORDER BY id DESC LIMIT ? OFFSET ?")
    args += [limit, offset]
    rows = conn.execute("\n".join(sql), args).fetchall()
    return [dict(r) for r in rows]


def _row_to_detail(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["req_headers"] = json.loads(d["req_headers"]) if d.get("req_headers") else []
    d["resp_headers"] = json.loads(d["resp_headers"]) if d.get("resp_headers") else []
    d["req_body"] = _decode_body(d.get("req_body"))
    d["resp_body"] = _decode_body(d.get("resp_body"))
    return d


def _decode_body(body: Optional[bytes]) -> dict:
    """Gövdeyi UI için güvenli şekilde döndürür: metin ise text, değilse base64."""
    import base64

    if body is None:
        return {"text": None, "base64": None, "size": 0, "truncated": False}
    size = len(body)
    try:
        text = body.decode("utf-8")
        return {"text": text, "base64": None, "size": size, "truncated": False}
    except UnicodeDecodeError:
        return {
            "text": None,
            "base64": base64.b64encode(body).decode("ascii"),
            "size": size,
            "truncated": False,
        }


def get_flow(conn: sqlite3.Connection, flow_id: int) -> Optional[dict]:
    row = conn.execute("SELECT * FROM flows WHERE id = ?", (flow_id,)).fetchone()
    if row is None:
        return None
    return _row_to_detail(row)


def get_flow_raw(conn: sqlite3.Connection, flow_id: int) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM flows WHERE id = ?", (flow_id,)).fetchone()


def clear_flows(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM flows")
