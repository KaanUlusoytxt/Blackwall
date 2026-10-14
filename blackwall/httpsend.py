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


def request_wire_bytes(req: httpx.Request) -> bytes:
    """httpx isteğini TAM tel (wire) byte dizisi olarak üretir.

    httpcore'un HTTP/1.1 üzerinde gerçekte gönderdiği biçim: request line,
    `req.headers.raw` sırasıyla başlıklar, boş satır, gövde. Böylece Race ham
    sokete bu byte'ları yazdığında Repeater'ın (httpx) gönderdiğiyle birebir aynı olur.
    """
    target = req.url.raw_path  # bytes: path?query (origin-form)
    out = bytearray()
    out += req.method.encode("ascii") + b" " + target + b" HTTP/1.1\r\n"
    # httpcore tel üzerinde Host başlığını en başa alır; aynı sırayı üret.
    raw_headers = list(req.headers.raw)
    host = [(k, v) for k, v in raw_headers if k.lower() == b"host"]
    rest = [(k, v) for k, v in raw_headers if k.lower() != b"host"]
    for k, v in host + rest:
        out += k + b": " + v + b"\r\n"
    out += b"\r\n"
    out += req.content or b""
    return bytes(out)


def render_sent(req: httpx.Request) -> str:
    """httpx'in göndereceği isteği ham metin olarak üretir (hata ayıklama/görüntü)."""
    wire = request_wire_bytes(req)
    try:
        return wire.decode("utf-8")
    except UnicodeDecodeError:
        return wire.decode("latin-1")


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
