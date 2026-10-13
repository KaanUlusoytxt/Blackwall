"""Offline encode/decode/hash ve JWT yardımcıları (Decoder & JWT sekmeleri).

Hiçbir dış servise bağlanmaz; her şey yerel olarak hesaplanır.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import html
import json
import urllib.parse
from typing import Any

# ---------------------------------------------------------------------------
# Decoder — her işlem metin alır, metin döndürür. Böylece katmanlar zincirlenebilir.
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
    raise ValueError(f"bilinmeyen işlem: {op}")


def run_pipeline(text: str, ops: list[str]) -> list[dict]:
    """Her adımın çıktısını döndürür: [{op, output, error}]."""
    steps: list[dict] = []
    cur = text
    for op in ops:
        if op not in DECODER_OPS:
            steps.append({"op": op, "output": None, "error": "bilinmeyen işlem"})
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
    """Bir JWT'yi doğrulamadan çözer (header/payload/signature)."""
    token = token.strip()
    parts = token.split(".")
    if len(parts) not in (2, 3):
        raise ValueError("Geçersiz JWT: nokta ile ayrılmış 2-3 bölüm bekleniyor")

    def _parse(seg: str) -> Any:
        raw = _b64url_decode(seg).decode("utf-8", "replace")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw  # ham metin olarak göster

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
    """alg:none ya da HS256 ile yeni token üretir."""
    alg = alg.upper()
    # Kullanıcının verdiği header'ı (ve alan sırasını) temel al; yoksa makul varsayılan.
    header: dict = dict(extra_header) if extra_header else {"alg": alg, "typ": "JWT"}
    header["alg"] = "none" if alg == "NONE" else alg  # alg'i her zaman seçime göre ayarla
    header.setdefault("typ", "JWT")

    if alg == "NONE":
        signing_input = _signing_input(header, payload)
        # alg:none tokenlarında imza bölümü boştur ama ayırıcı nokta korunur.
        return {"token": f"{signing_input}.", "header": header}

    if alg == "HS256":
        signing_input = _signing_input(header, payload)
        sig = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
        return {"token": f"{signing_input}.{_b64url_encode(sig)}", "header": header}

    raise ValueError(f"desteklenmeyen alg: {alg} (none veya HS256)")
