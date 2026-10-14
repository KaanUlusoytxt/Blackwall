"""Repeater ve Intruder için TEK ortak istek gönderim yolu.

Her iki araç da aynı (method, url, headers, body) girdisinden aynı httpx isteğini
kurar; böylece gönderilen byte'lar birebir aynıdır. Intruder yalnızca payload'ı
yerleştirip ham isteği parse eder, sonra bu modülü çağırır.

Kurallar (her iki araçta da aynı):
  * Content-Length, payload yerleştikten sonra GÖVDENİN GERÇEK uzunluğuna göre
    yeniden hesaplanır (gelen bayat Content-Length atılır).
  * Diğer header'lar ve sırası korunur; Host httpx tarafından (yoksa) eklenir.
"""
from __future__ import annotations

from typing import Optional, Union

import httpx


def recompute_headers(
    headers: list[tuple[str, str]], body: Optional[bytes]
) -> list[tuple[str, str]]:
    """Bayat Content-Length'i atar, gövde doluysa gerçek uzunluğu ekler."""
    out = [(k, v) for k, v in headers if k.lower() != "content-length"]
    if body:
        out.append(("Content-Length", str(len(body))))
    return out


def render_sent(req: httpx.Request) -> str:
    """httpx'in göndereceği isteği ham metin olarak üretir (hata ayıklama/görüntü)."""
    target = req.url.raw_path.decode("ascii", "replace")
    lines = [f"{req.method} {target} HTTP/1.1"]
    for k, v in req.headers.raw:
        lines.append(f"{k.decode('latin-1')}: {v.decode('latin-1')}")
    head = "\r\n".join(lines) + "\r\n\r\n"
    body = req.content or b""
    try:
        body_text = body.decode("utf-8")
    except UnicodeDecodeError:
        body_text = body.decode("latin-1")
    return head + body_text


def build_request(
    client: Union[httpx.Client, httpx.AsyncClient],
    *,
    method: str,
    url: str,
    headers: list[tuple[str, str]],
    body: Optional[bytes],
) -> tuple[httpx.Request, str]:
    """Ortak kurulum: CL yeniden hesapla, httpx Request kur, gönderilecek ham metni üret.

    (request, sent_raw) döndürür. Gönderme (sync/async) çağırana aittir ama
    hazırlanan Request her iki araçta da birebir aynıdır.
    """
    final_headers = recompute_headers(headers, body)
    req = client.build_request(
        method.upper(),
        url,
        headers=final_headers,
        content=(body if body else None),
    )
    return req, render_sent(req)
