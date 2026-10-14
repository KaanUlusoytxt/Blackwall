"""mitmproxy addon'u: HTTP(S) akışlarını ve WebSocket mesajlarını SQLite'a yazar.

Kullanım:
    mitmdump -s blackwall/addon.py

- HTTP istek/yanıtları `flows` tablosuna (response/error hook'ları).
- WebSocket bağlantıları `ws_flows`, mesajları `ws_messages` tablosuna.
- `ws_inject` kuyruğu: web süreci enjeksiyon isteği yazar; bu addon canlı
  bağlantıya `inject.websocket` komutuyla mesajı gerçekten gönderir.

HTTP/2 Faz 1 kapsamı dışında.
"""
from __future__ import annotations

import asyncio
import sqlite3
import time

from mitmproxy import ctx, http

from blackwall import db


class BlackwallAddon:
    def __init__(self) -> None:
        db.init_db()
        # Addon tek thread'de (mitmproxy event loop'u) çalışır; tek bağlantı yeterli.
        self.conn: sqlite3.Connection = db.connect()
        # Canlı WebSocket akışları: flow.id -> flow (enjeksiyon için gerekli)
        self.live_ws: dict[str, http.HTTPFlow] = {}
        self._running = False
        self._task: asyncio.Task | None = None

    # -- HTTP ---------------------------------------------------------------
    def response(self, flow: http.HTTPFlow) -> None:
        self._store(flow)

    def error(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            self._store(flow)

    def _store(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        resp = flow.response
        duration_ms = None
        if resp is not None and req.timestamp_start and resp.timestamp_end:
            duration_ms = (resp.timestamp_end - req.timestamp_start) * 1000.0
        try:
            db.insert_flow(
                self.conn,
                source="proxy",
                method=req.method,
                scheme=req.scheme,
                host=req.host,
                port=req.port,
                path=req.path,
                url=req.pretty_url,
                http_version=req.http_version,
                req_headers=list(req.headers.items(multi=True)),
                req_body=req.raw_content,
                status_code=resp.status_code if resp else None,
                reason=resp.reason if resp else None,
                resp_headers=list(resp.headers.items(multi=True)) if resp else None,
                resp_body=resp.raw_content if resp else None,
                duration_ms=duration_ms,
                error=str(flow.error) if flow.error else None,
                created_at=req.timestamp_start,
            )
        except Exception as exc:
            ctx.log.warn(f"Blackwall: HTTP akışı kaydedilemedi: {exc}")

    # -- WebSocket ----------------------------------------------------------
    def websocket_start(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        try:
            db.ws_flow_start(
                self.conn,
                flow_id=flow.id,
                created_at=time.time(),
                host=req.host,
                port=req.port,
                path=req.path,
                url=req.pretty_url,
            )
            self.live_ws[flow.id] = flow
        except Exception as exc:
            ctx.log.warn(f"Blackwall: ws_start kaydedilemedi: {exc}")

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        if flow.websocket is None or not flow.websocket.messages:
            return
        msg = flow.websocket.messages[-1]
        try:
            db.ws_insert_message(
                self.conn,
                flow_id=flow.id,
                created_at=msg.timestamp or time.time(),
                direction="c2s" if msg.from_client else "s2c",
                type="text" if msg.is_text else "binary",
                content=bytes(msg.content),
                injected=bool(msg.injected),
            )
        except Exception as exc:
            ctx.log.warn(f"Blackwall: ws mesajı kaydedilemedi: {exc}")

    def websocket_end(self, flow: http.HTTPFlow) -> None:
        ws = flow.websocket
        try:
            db.ws_flow_end(
                self.conn,
                flow_id=flow.id,
                closed_at=time.time(),
                state="closed",
                close_code=ws.close_code if ws else None,
                close_reason=ws.close_reason if ws else None,
            )
        except Exception as exc:
            ctx.log.warn(f"Blackwall: ws_end kaydedilemedi: {exc}")
        finally:
            self.live_ws.pop(flow.id, None)

    # -- Enjeksiyon kuyruğu -------------------------------------------------
    def running(self) -> None:
        if self._task is None:
            self._running = True
            self._task = asyncio.ensure_future(self._inject_loop())

    async def _inject_loop(self) -> None:
        while self._running:
            try:
                self._process_injects()
            except Exception as exc:
                ctx.log.warn(f"Blackwall: enjeksiyon döngüsü hatası: {exc}")
            await asyncio.sleep(0.4)

    def _process_injects(self) -> None:
        pending = db.ws_pending_injects(self.conn)
        for row in pending:
            now = time.time()
            flow = self.live_ws.get(row["flow_id"])
            if flow is None:
                db.ws_mark_inject(
                    self.conn, row["id"], "gone",
                    processed_at=now, error="bağlantı açık değil",
                )
                continue
            try:
                to_client = row["direction"] == "s2c"
                is_text = row["type"] == "text"
                content = row["content"] or b""
                ctx.master.commands.call(
                    "inject.websocket", flow, to_client, content, is_text
                )
                db.ws_mark_inject(self.conn, row["id"], "done", processed_at=now)
            except Exception as exc:
                db.ws_mark_inject(
                    self.conn, row["id"], "error", processed_at=now, error=str(exc)
                )

    def done(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
        try:
            self.conn.close()
        except Exception:
            pass


addons = [BlackwallAddon()]
