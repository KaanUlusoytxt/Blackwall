"""SQLite storage layer.

Both the mitmproxy addon (writer) and the FastAPI app (reader/writer) open the
same file. WAL mode is used for concurrent cross-process access.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional

# The DB path can be overridden via an env var (addon and web must use the same value).
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
    req_headers   TEXT NOT NULL,          -- JSON: [[name, value], ...]
    req_body      BLOB,
    status_code   INTEGER,
    reason        TEXT,
    resp_headers  TEXT,                   -- JSON: [[name, value], ...]
    resp_body     BLOB,
    duration_ms   REAL,                   -- request-response time
    error         TEXT
);
CREATE INDEX IF NOT EXISTS idx_flows_created_at ON flows (created_at);
CREATE INDEX IF NOT EXISTS idx_flows_host ON flows (host);

-- WebSocket connections (one row per upgraded HTTP flow)
CREATE TABLE IF NOT EXISTS ws_flows (
    flow_id      TEXT PRIMARY KEY,
    created_at   REAL NOT NULL,
    host         TEXT,
    port         INTEGER,
    path         TEXT,
    url          TEXT,
    state        TEXT NOT NULL DEFAULT 'open',  -- open | closed | error
    closed_at    REAL,
    close_code   INTEGER,
    close_reason TEXT
);

-- WebSocket messages
CREATE TABLE IF NOT EXISTS ws_messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id    TEXT NOT NULL,
    created_at REAL NOT NULL,
    direction  TEXT NOT NULL,   -- c2s (client→server) | s2c (server→client)
    type       TEXT NOT NULL,   -- text | binary
    content    BLOB,
    injected   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_ws_messages_flow ON ws_messages (flow_id, id);

-- Injection queue: the web process writes, the addon (mitmproxy process) consumes
CREATE TABLE IF NOT EXISTS ws_inject (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id      TEXT NOT NULL,
    direction    TEXT NOT NULL,  -- c2s | s2c
    type         TEXT NOT NULL,  -- text | binary
    content      BLOB,
    created_at   REAL NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',  -- pending | done | gone | error
    error        TEXT,
    processed_at REAL
);
CREATE INDEX IF NOT EXISTS idx_ws_inject_status ON ws_inject (status, id);
"""


def connect() -> sqlite3.Connection:
    """Open a connection in WAL mode. Each caller manages its own connection."""
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
    """Summary rows for the History table (bodies excluded)."""
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
    """Return the body safely for the UI: text if decodable, otherwise base64."""
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


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------
def ws_flow_start(
    conn: sqlite3.Connection,
    *,
    flow_id: str,
    created_at: float,
    host: str,
    port: int,
    path: str,
    url: str,
) -> None:
    conn.execute(
        """
        INSERT INTO ws_flows (flow_id, created_at, host, port, path, url, state)
        VALUES (?,?,?,?,?,?, 'open')
        ON CONFLICT(flow_id) DO UPDATE SET state='open'
        """,
        (flow_id, created_at, host, port, path, url),
    )


def ws_flow_end(
    conn: sqlite3.Connection,
    *,
    flow_id: str,
    closed_at: float,
    state: str = "closed",
    close_code: Optional[int] = None,
    close_reason: Optional[str] = None,
) -> None:
    conn.execute(
        """
        UPDATE ws_flows
        SET state=?, closed_at=?, close_code=?, close_reason=?
        WHERE flow_id=?
        """,
        (state, closed_at, close_code, close_reason, flow_id),
    )


def ws_insert_message(
    conn: sqlite3.Connection,
    *,
    flow_id: str,
    created_at: float,
    direction: str,
    type: str,
    content: Optional[bytes],
    injected: bool = False,
) -> int:
    cur = conn.execute(
        """
        INSERT INTO ws_messages (flow_id, created_at, direction, type, content, injected)
        VALUES (?,?,?,?,?,?)
        """,
        (flow_id, created_at, direction, type, content, 1 if injected else 0),
    )
    return int(cur.lastrowid)


def ws_list_flows(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        """
        SELECT f.*,
               (SELECT COUNT(*) FROM ws_messages m WHERE m.flow_id=f.flow_id) AS msg_count,
               (SELECT MAX(created_at) FROM ws_messages m WHERE m.flow_id=f.flow_id) AS last_msg_at
        FROM ws_flows f
        ORDER BY f.created_at DESC
        """
    ).fetchall()
    return [dict(r) for r in rows]


def ws_list_messages(conn: sqlite3.Connection, flow_id: str, after_id: int = 0) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM ws_messages WHERE flow_id=? AND id>? ORDER BY id ASC",
        (flow_id, after_id),
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["content"] = _decode_body(d.get("content"))
        d["injected"] = bool(d["injected"])
        out.append(d)
    return out


# -- Injection queue --------------------------------------------------------
def ws_enqueue_inject(
    conn: sqlite3.Connection,
    *,
    flow_id: str,
    direction: str,
    type: str,
    content: Optional[bytes],
    created_at: float,
) -> int:
    cur = conn.execute(
        """
        INSERT INTO ws_inject (flow_id, direction, type, content, created_at, status)
        VALUES (?,?,?,?,?, 'pending')
        """,
        (flow_id, direction, type, content, created_at),
    )
    return int(cur.lastrowid)


def ws_pending_injects(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM ws_inject WHERE status='pending' ORDER BY id ASC"
    ).fetchall()
    return [dict(r) for r in rows]


def ws_mark_inject(
    conn: sqlite3.Connection,
    inject_id: int,
    status: str,
    *,
    processed_at: float,
    error: Optional[str] = None,
) -> None:
    conn.execute(
        "UPDATE ws_inject SET status=?, error=?, processed_at=? WHERE id=?",
        (status, error, processed_at, inject_id),
    )


def ws_get_inject(conn: sqlite3.Connection, inject_id: int) -> Optional[dict]:
    row = conn.execute("SELECT id, flow_id, direction, type, status, error FROM ws_inject WHERE id=?", (inject_id,)).fetchone()
    return dict(row) if row else None
