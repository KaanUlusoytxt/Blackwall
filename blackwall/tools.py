"""Offline encode/decode/hash ve JWT yardımcıları (Decoder & JWT sekmeleri).

Hiçbir dış servise bağlanmaz; her şey yerel olarak hesaplanır.
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


# ---------------------------------------------------------------------------
# Intruder — §...§ işaretli konumlara payload yerleştirme
# ---------------------------------------------------------------------------

_MARKER_RE = re.compile(r"§([^§]*)§")


def parse_positions(text: str) -> tuple[list[str], list[str]]:
    """Ham isteği §...§ işaretlerinden ayırır.

    Döndürür:
      segments: n+1 adet düz metin parçası
      defaults: n adet, her işaretin içindeki varsayılan değer
    build_request(segments, values) ile yeniden birleştirilir.
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
    """segments (n+1) ve values (n) birleştirip somut isteği üretir."""
    out = [segments[0]]
    for i, val in enumerate(values):
        out.append(val)
        out.append(segments[i + 1])
    return "".join(out)


def build_cases(
    attack: str, defaults: list[str], payload_sets: list[list[str]]
) -> list[list[str]]:
    """Saldırı tipine göre her isteğin konum değerlerini (uzunluk = konum sayısı) üretir."""
    n = len(defaults)
    if n == 0:
        raise ValueError("İstekte §...§ ile işaretlenmiş konum yok")

    if attack == "sniper":
        if not payload_sets or not payload_sets[0]:
            raise ValueError("sniper için bir payload listesi gerekli")
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
            raise ValueError(f"pitchfork için {n} liste gerekli (konum başına bir)")
        k = min(len(payload_sets[i]) for i in range(n))
        return [[payload_sets[i][j] for i in range(n)] for j in range(k)]

    if attack == "cluster":
        if len(payload_sets) < n:
            raise ValueError(f"cluster bomb için {n} liste gerekli (konum başına bir)")
        lists = [payload_sets[i] for i in range(n)]
        if any(len(x) == 0 for x in lists):
            raise ValueError("cluster bomb için her liste en az bir payload içermeli")
        return [list(combo) for combo in itertools.product(*lists)]

    raise ValueError(f"bilinmeyen saldırı tipi: {attack}")


def parse_http(text: str, scheme: str) -> tuple[str, str, list[tuple[str, str]], bytes]:
    """Somut ham HTTP isteğini method, url, headers, body'ye ayırır."""
    text = text.replace("\r\n", "\n")
    head, sep, body = text.partition("\n\n")
    lines = head.split("\n")
    if not lines or not lines[0].strip():
        raise ValueError("boş istek satırı")
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
            raise ValueError("Host başlığı yok ve hedef mutlak URL değil")
        url = f"{scheme}://{host}{target}"

    return method, url, headers, body.encode("utf-8")


def host_header(headers: list[tuple[str, str]]) -> str:
    for k, v in headers:
        if k.lower() == "host":
            return v
    return ""


def parse_request(text: str) -> tuple[str, str, list[tuple[str, str]], bytes]:
    """Ham isteği method, path (request-line hedefi), headers, body'ye ayırır.

    URL ÇÖZÜMÜ YAPMAZ — bağlantı hedefi (şema/host/port) ayrıca verilir; böylece
    Host: satırına bağımlı kalınmaz (Repeater ile aynı hedef mantığı).
    """
    text = text.replace("\r\n", "\n")
    head, _, body = text.partition("\n\n")
    lines = head.split("\n")
    if not lines or not lines[0].strip():
        raise ValueError("boş istek satırı")
    parts = lines[0].split(" ")
    method = parts[0].strip()
    path = parts[1].strip() if len(parts) > 1 else "/"

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
    """Canonical HTTP/1.1 ham istek byte'ları üretir.

    * Request line her zaman HTTP/1.1.
    * TÜM header'lar (cookie dahil) sırası korunarak birebir yazılır.
    * Content-Length GÖVDENİN gerçek byte uzunluğundan hesaplanır (varsa yerinde
      güncellenir, yoksa eklenir; gövde boşsa atılır).
    * Gövde (csrf dahil) olduğu gibi eklenir.
    """
    body = body or b""
    out: list[tuple[str, str]] = []
    cl_set = False
    for k, v in headers:
        if k.lower() == "content-length":
            if body:
                out.append((k, str(len(body))))   # aynı konumda düzelt
                cl_set = True
            # gövde yoksa Content-Length'i tamamen at
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
    """host içindeki şema/path/boşluk/gömülü port'u ayıklar → (host, port)."""
    host = (host or "").strip()
    if "://" in host:                      # şema önekini at
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0].strip()   # path ve boşluk at
    host = host.split("?", 1)[0].strip()
    # gömülü port (IPv6 dışında)
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
    """Bağlantı hedefini şema+host+port+path'ten güvenli biçimde kurar.

    host içinde yanlışlıkla şema/path/boşluk/port olsa bile ayıklar.
    """
    scheme = (scheme or "").strip().lower()
    if scheme not in ("http", "https"):
        scheme = "http"

    host, port = clean_host(host, port)

    if not host:
        raise ValueError("hedef host çözülemedi")
    if not port:
        port = 443 if scheme == "https" else 80

    # request-line mutlak URL ise olduğu gibi kullan
    if path.startswith(("http://", "https://")):
        return path
    if not path.startswith("/"):
        path = "/" + path

    default_port = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    netloc = host if default_port else f"{host}:{port}"
    return f"{scheme}://{netloc}{path}"
