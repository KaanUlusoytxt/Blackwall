"""Offline encode/decode/hash and JWT helpers (Decoder & JWT tabs).

Connects to no external service; everything is computed locally.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import html
import itertools
import json
import re
import urllib.parse
from typing import Any

# ---------------------------------------------------------------------------
# Decoder — each op takes text and returns text, so layers can be chained.
# ---------------------------------------------------------------------------

def _b64_pad(s: str) -> bytes:
    s2 = s.strip().encode("ascii", "ignore")
    pad = (-len(s2)) % 4
    return s2 + b"=" * pad


DECODER_OPS = {
    "base64-encode",
    "base64-decode",
    "base64url-encode",
    "base64url-decode",
    "url-encode",
    "url-decode",
    "html-encode",
    "html-decode",
    "hex-encode",
    "hex-decode",
    "ascii-encode",
    "ascii-decode",
    "md5",
    "sha1",
    "sha256",
}


def apply_op(op: str, text: str) -> str:
    if op == "base64-encode":
        return base64.b64encode(text.encode("utf-8")).decode("ascii")
    if op == "base64-decode":
        return base64.b64decode(_b64_pad(text)).decode("utf-8", "replace")
    if op == "base64url-encode":
        return base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii").rstrip("=")
    if op == "base64url-decode":
        return base64.urlsafe_b64decode(_b64_pad(text)).decode("utf-8", "replace")
    if op == "url-encode":
        return urllib.parse.quote(text, safe="")
    if op == "url-decode":
        return urllib.parse.unquote(text)
    if op == "html-encode":
        return html.escape(text)
    if op == "html-decode":
        return html.unescape(text)
    if op == "hex-encode":
        return text.encode("utf-8").hex()
    if op == "hex-decode":
        cleaned = "".join(text.split()).replace("0x", "")
        return bytes.fromhex(cleaned).decode("utf-8", "replace")
    if op == "ascii-encode":
        return " ".join(str(ord(c)) for c in text)
    if op == "ascii-decode":
        return "".join(chr(int(tok)) for tok in text.split())
    if op in ("md5", "sha1", "sha256"):
        return hashlib.new(op, text.encode("utf-8")).hexdigest()
    raise ValueError(f"unknown op: {op}")


def run_pipeline(text: str, ops: list[str]) -> list[dict]:
    """Return each step's output: [{op, output, error}]."""
    steps: list[dict] = []
    cur = text
    for op in ops:
        if op not in DECODER_OPS:
            steps.append({"op": op, "output": None, "error": "unknown op"})
            break
        try:
            cur = apply_op(op, cur)
            steps.append({"op": op, "output": cur, "error": None})
        except (binascii.Error, ValueError, UnicodeError) as exc:
            steps.append({"op": op, "output": None, "error": f"{type(exc).__name__}: {exc}"})
            break
    return steps


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------

def _b64url_decode(seg: str) -> bytes:
    return base64.urlsafe_b64decode(_b64_pad(seg))


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def jwt_decode(token: str) -> dict:
    """Decode a JWT without verification (header/payload/signature)."""
    token = token.strip()
    parts = token.split(".")
    if len(parts) not in (2, 3):
        raise ValueError("Invalid JWT: expected 2-3 dot-separated segments")

    def _parse(seg: str) -> Any:
        raw = _b64url_decode(seg).decode("utf-8", "replace")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw  # show as raw text

    header = _parse(parts[0])
    payload = _parse(parts[1])
    signature_b64 = parts[2] if len(parts) == 3 else ""
    alg = header.get("alg") if isinstance(header, dict) else None
    return {
        "header": header,
        "payload": payload,
        "signature": signature_b64,
        "alg": alg,
        "parts": len(parts),
    }


def _signing_input(header: dict, payload: Any) -> str:
    h = _b64url_encode(json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    p = _b64url_encode(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    return f"{h}.{p}"


def jwt_sign(payload: Any, *, alg: str, secret: str = "", extra_header: dict | None = None) -> dict:
    """Produce a new token with alg:none or HS256."""
    alg = alg.upper()
    # Base it on the user-supplied header (and field order); otherwise a sane default.
    header: dict = dict(extra_header) if extra_header else {"alg": alg, "typ": "JWT"}
    header["alg"] = "none" if alg == "NONE" else alg  # always set alg per the choice
    header.setdefault("typ", "JWT")

    if alg == "NONE":
        signing_input = _signing_input(header, payload)
        # alg:none tokens have an empty signature segment but keep the trailing dot.
        return {"token": f"{signing_input}.", "header": header}

    if alg == "HS256":
        signing_input = _signing_input(header, payload)
        sig = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
        return {"token": f"{signing_input}.{_b64url_encode(sig)}", "header": header}

    raise ValueError(f"unsupported alg: {alg} (none or HS256)")


# ---------------------------------------------------------------------------
# Intruder — substitute payloads into §...§ marked positions
# ---------------------------------------------------------------------------

_MARKER_RE = re.compile(r"§([^§]*)§")


def parse_positions(text: str) -> tuple[list[str], list[str]]:
    """Split the raw request at §...§ markers.

    Returns:
      segments: n+1 plain-text pieces
      defaults: n values, the default inside each marker
    Reassembled with build_request(segments, values).
    """
    segments: list[str] = []
    defaults: list[str] = []
    last = 0
    for m in _MARKER_RE.finditer(text):
        segments.append(text[last : m.start()])
        defaults.append(m.group(1))
        last = m.end()
    segments.append(text[last:])
    return segments, defaults


def build_request(segments: list[str], values: list[str]) -> str:
    """Join segments (n+1) and values (n) into a concrete request."""
    out = [segments[0]]
    for i, val in enumerate(values):
        out.append(val)
        out.append(segments[i + 1])
    return "".join(out)


def build_cases(
    attack: str, defaults: list[str], payload_sets: list[list[str]]
) -> list[list[str]]:
    """Produce the per-request position values (length = position count) per attack type."""
    n = len(defaults)
    if n == 0:
        raise ValueError("No §...§ marked position in the request")

    if attack == "sniper":
        if not payload_sets or not payload_sets[0]:
            raise ValueError("sniper requires one payload list")
        lst = payload_sets[0]
        cases: list[list[str]] = []
        for pos in range(n):
            for p in lst:
                values = list(defaults)
                values[pos] = p
                cases.append(values)
        return cases

    if attack == "pitchfork":
        if len(payload_sets) < n:
            raise ValueError(f"pitchfork requires {n} lists (one per position)")
        k = min(len(payload_sets[i]) for i in range(n))
        return [[payload_sets[i][j] for i in range(n)] for j in range(k)]

    if attack == "cluster":
        if len(payload_sets) < n:
            raise ValueError(f"cluster bomb requires {n} lists (one per position)")
        lists = [payload_sets[i] for i in range(n)]
        if any(len(x) == 0 for x in lists):
            raise ValueError("cluster bomb requires each list to have at least one payload")
        return [list(combo) for combo in itertools.product(*lists)]

    raise ValueError(f"unknown attack type: {attack}")


def parse_http(text: str, scheme: str) -> tuple[str, str, list[tuple[str, str]], bytes]:
    """Split a concrete raw HTTP request into method, url, headers, body."""
    text = text.replace("\r\n", "\n")
    head, sep, body = text.partition("\n\n")
    lines = head.split("\n")
    if not lines or not lines[0].strip():
        raise ValueError("empty request line")
    parts = lines[0].split(" ")
    method = parts[0].strip()
    target = parts[1].strip() if len(parts) > 1 else "/"

    headers: list[tuple[str, str]] = []
    host = None
    for ln in lines[1:]:
        if not ln.strip() or ":" not in ln:
            continue
        k, v = ln.split(":", 1)
        k, v = k.strip(), v.strip()
        headers.append((k, v))
        if k.lower() == "host":
            host = v

    if target.startswith(("http://", "https://")):
        url = target
    else:
        if not host:
            raise ValueError("No Host header and the target is not an absolute URL")
        url = f"{scheme}://{host}{target}"

    return method, url, headers, body.encode("utf-8")


def host_header(headers: list[tuple[str, str]]) -> str:
    for k, v in headers:
        if k.lower() == "host":
            return v
    return ""


def parse_request(text: str) -> tuple[str, str, list[tuple[str, str]], bytes]:
    """Split a raw request into method, path (request-line target), headers, body.

    Does NOT resolve the URL — the connection target (scheme/host/port) is supplied
    separately, so it does not depend on the Host: line (same target logic as Repeater).
    """
    text = text.replace("\r\n", "\n")
    # Strip leading blank lines (paste artifact) — the first real line is the request line.
    text = text.lstrip("\n")
    head, _, body = text.partition("\n\n")
    lines = head.split("\n")
    if not lines or not lines[0].strip():
        raise ValueError("empty request line")
    # The request line must contain AT LEAST method + path (METHOD /path [HTTP/x]).
    # A single-token line (e.g. a body line "search=x") is NOT a request line → do not
    # write the body into method; raise a clear error.
    parts = lines[0].split()
    if len(parts) < 2:
        raise ValueError(
            f"invalid request line: expected 'METHOD /path [HTTP/x]', "
            f"got: {lines[0]!r} (the first line must be the request line)"
        )
    method = parts[0]
    path = parts[1]

    headers: list[tuple[str, str]] = []
    for ln in lines[1:]:
        if not ln.strip() or ":" not in ln:
            continue
        k, v = ln.split(":", 1)
        headers.append((k.strip(), v.strip()))
    return method, path, headers, body.encode("utf-8")


def build_http11_request(
    method: str, path: str, headers: list[tuple[str, str]], body: Optional[bytes]
) -> bytes:
    """Produce canonical HTTP/1.1 raw request bytes.

    * Request line is always HTTP/1.1.
    * ALL headers (including cookies) are written verbatim, order preserved.
    * Content-Length is computed from the REAL body byte length (updated in place if
      present, appended if missing; dropped when the body is empty).
    * The body (including csrf) is appended as-is.
    """
    body = body or b""
    out: list[tuple[str, str]] = []
    cl_set = False
    for k, v in headers:
        if k.lower() == "content-length":
            if body:
                out.append((k, str(len(body))))   # fix in place
                cl_set = True
            # drop Content-Length entirely when there is no body
        else:
            out.append((k, v))
    if body and not cl_set:
        out.append(("Content-Length", str(len(body))))

    lines = [f"{method} {path} HTTP/1.1"]
    lines += [f"{k}: {v}" for k, v in out]
    head_str = "\r\n".join(lines) + "\r\n\r\n"
    try:
        head = head_str.encode("latin-1")
    except UnicodeEncodeError:
        head = head_str.encode("utf-8")
    return head + body


def clean_host(host: str, port: Optional[int] = None) -> tuple[str, Optional[int]]:
    """Strip scheme/path/whitespace/embedded port from host → (host, port)."""
    host = (host or "").strip()
    if "://" in host:                      # drop the scheme prefix
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0].strip()   # drop path and whitespace
    host = host.split("?", 1)[0].strip()
    # embedded port (except IPv6)
    if not host.startswith("[") and host.count(":") == 1:
        h, _, p = host.partition(":")
        host = h.strip()
        if not port:
            try:
                port = int(p)
            except ValueError:
                pass
    return host, port


def resolve_url(scheme: str, host: str, port: Optional[int], path: str) -> str:
    """Safely build the connection target from scheme+host+port+path.

    Strips any accidental scheme/path/whitespace/port inside host.
    """
    scheme = (scheme or "").strip().lower()
    if scheme not in ("http", "https"):
        scheme = "http"

    host, port = clean_host(host, port)

    if not host:
        raise ValueError("could not resolve target host")
    if not port:
        port = 443 if scheme == "https" else 80

    # if the request-line is an absolute URL, use it as-is
    if path.startswith(("http://", "https://")):
        return path
    if not path.startswith("/"):
        path = "/" + path

    default_port = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    netloc = host if default_port else f"{host}:{port}"
    return f"{scheme}://{netloc}{path}"
