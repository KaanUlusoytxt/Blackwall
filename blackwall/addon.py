"""mitmproxy addon'u: tüm HTTP(S) akışlarını yakalar ve SQLite'a yazar.

Kullanım:
    mitmdump -s blackwall/addon.py

HTTP/2 ve WebSocket Faz 1 kapsamı dışında; sadece normal HTTP istek/yanıtları
kaydedilir.
"""
from __future__ import annotations

import sqlite3

from mitmproxy import http

from blackwall import db


class BlackwallAddon:
    def __init__(self) -> None:
        db.init_db()
        # Addon tek thread'de çalışır; tek, uzun ömürlü bağlantı yeterli.
        self.conn: sqlite3.Connection = db.connect()

    def response(self, flow: http.HTTPFlow) -> None:
        """İstek-yanıt tamamlandığında kaydet."""
        self._store(flow)

    def error(self, flow: http.HTTPFlow) -> None:
        """Yanıt alınamadan hata olduysa yine de isteği kaydet."""
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
        except Exception as exc:  # addon'un çökmemesi için yut
            from mitmproxy import ctx

            ctx.log.warn(f"Blackwall: akış kaydedilemedi: {exc}")

    def done(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass


addons = [BlackwallAddon()]
