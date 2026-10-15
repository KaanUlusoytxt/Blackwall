"""The SINGLE shared request-send path for Repeater and Intruder.

Both tools build the same httpx request from the same (method, url, headers, body)
input, so the bytes sent are identical. Intruder only substitutes the payload and
parses the raw request, then calls this module.

Rules (identical for both tools):
  * Content-Length is recomputed from the REAL body length after the payload is
    substituted (any stale incoming Content-Length is dropped).
  * Other headers and their order are preserved; Host is added by httpx if missing.
"""
from __future__ import annotations

from typing import Optional, Union

import httpx


def recompute_headers(
    headers: list[tuple[str, str]], body: Optional[bytes]
) -> list[tuple[str, str]]:
    """Drop stale Content-Length; add the real length when the body is non-empty."""
    out = [(k, v) for k, v in headers if k.lower() != "content-length"]
    if body:
        out.append(("Content-Length", str(len(body))))
    return out


def request_wire_bytes(req: httpx.Request) -> bytes:
    """Produce the FULL wire byte sequence for an httpx request.

    The exact form httpcore sends over HTTP/1.1: request line, headers in
    `req.headers.raw` order, blank line, body. So when Race writes these bytes to
    a raw socket they are byte-identical to what Repeater (httpx) sends.
    """
    target = req.url.raw_path  # bytes: path?query (origin-form)
    out = bytearray()
    out += req.method.encode("ascii") + b" " + target + b" HTTP/1.1\r\n"
    # httpcore puts the Host header first on the wire; reproduce the same order.
    raw_headers = list(req.headers.raw)
    host = [(k, v) for k, v in raw_headers if k.lower() == b"host"]
    rest = [(k, v) for k, v in raw_headers if k.lower() != b"host"]
    for k, v in host + rest:
        out += k + b": " + v + b"\r\n"
    out += b"\r\n"
    out += req.content or b""
    return bytes(out)


def render_sent(req: httpx.Request) -> str:
    """Render the request httpx will send as raw text (for debugging/display)."""
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
    """Shared setup: recompute CL, build the httpx Request, render the raw text to send.

    Returns (request, sent_raw). Sending (sync/async) is up to the caller, but the
    prepared Request is byte-identical for both tools.
    """
    final_headers = recompute_headers(headers, body)
    req = client.build_request(
        method.upper(),
        url,
        headers=final_headers,
        content=(body if body else None),
    )
    return req, render_sent(req)
