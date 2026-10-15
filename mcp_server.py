#!/usr/bin/env python3
"""Blackwall MCP sunucusu.

Claude Desktop gibi MCP istemcilerinin Blackwall'ın araçlarını tool-call olarak
kullanmasını sağlar. Bu sunucu ÇALIŞAN bir Blackwall örneğinin HTTP API'sine
(varsayılan http://127.0.0.1:8000) istek atarak çalışır; Blackwall'ın kendi
kodunu değiştirmez.

Çalıştırma (genelde MCP istemcisi başlatır):
    .venv/bin/python mcp_server.py

Ortam değişkenleri:
    BLACKWALL_URL            Blackwall HTTP API kökü (varsayılan http://127.0.0.1:8000)
    BLACKWALL_ALLOWED_HOSTS  send_request/run_intruder için izinli hedef host'lar
                             (virgül/boşlukla ayrılmış). Boşsa her ikisi de reddedilir.
                             "*.example.com" gibi joker desteklenir.
"""
from __future__ import annotations

import os
from typing import Any, Optional
from urllib.parse import urlsplit

import httpx
from mcp.server.mcpserver import MCPServer

BASE_URL = os.environ.get("BLACKWALL_URL", "http://127.0.0.1:8000").rstrip("/")
HTTP_TIMEOUT = float(os.environ.get("BLACKWALL_MCP_TIMEOUT", "120"))

mcp = MCPServer("blackwall")


# ---------------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------------
def _allowed_hosts() -> list[str]:
    raw = os.environ.get("BLACKWALL_ALLOWED_HOSTS", "")
    return [h.strip().lower() for h in raw.replace(",", " ").split() if h.strip()]


def _host_allowed(host: str) -> bool:
    host = (host or "").lower()
    if not host:
        return False
    for entry in _allowed_hosts():
        if entry == host:
            return True
        if entry.startswith("*.") and host.endswith(entry[1:]):
            return True
    return False


def _require_allowed(host: str) -> None:
    """İzin listesi boşsa ya da host listede değilse hata yükseltir."""
    allowed = _allowed_hosts()
    if not allowed:
        raise ValueError(
            "BLACKWALL_ALLOWED_HOSTS tanımlı değil — güvenlik için hiçbir hedefe "
            "istek atılmıyor. İzinli host tanımla (ör. "
            "BLACKWALL_ALLOWED_HOSTS=\"0a12.web-security-academy.net\"). "
            "/ No allowed hosts configured; set BLACKWALL_ALLOWED_HOSTS first."
        )
    if not _host_allowed(host):
        raise ValueError(
            f"'{host}' izinli host listesinde değil. İzinliler: {', '.join(allowed)}. "
            f"Kaza saldırısını önlemek için hedefi BLACKWALL_ALLOWED_HOSTS'a ekleyin. "
            f"/ Host not in the allow-list."
        )


def _parse_target(target: str) -> tuple[str, str, int]:
    """'https://host:port' ya da 'host:port' → (scheme, host, port)."""
    t = (target or "").strip()
    if "://" not in t:
        t = "http://" + t
    u = urlsplit(t)
    scheme = u.scheme or "http"
    host = u.hostname or ""
    port = u.port or (443 if scheme == "https" else 80)
    return scheme, host, port


def _host_from_request_text(request_text: str) -> str:
    for line in request_text.replace("\r\n", "\n").split("\n"):
        if ":" in line and line.split(":", 1)[0].strip().lower() == "host":
            return line.split(":", 1)[1].strip().split(":")[0]
    return ""


def _client() -> httpx.Client:
    # lang=en cookie → Blackwall'ın hata mesajları İngilizce döner (MCP istemcisi için).
    return httpx.Client(base_url=BASE_URL, timeout=HTTP_TIMEOUT, cookies={"lang": "en"})


def _raise_for(resp: httpx.Response) -> None:
    if resp.is_success:
        return
    detail = resp.text
    try:
        detail = resp.json().get("detail", detail)
    except Exception:
        pass
    raise RuntimeError(f"Blackwall API {resp.status_code}: {detail}")


def _check_blackwall_running() -> None:
    try:
        with _client() as c:
            c.get("/api/flows", params={"limit": 1})
    except httpx.ConnectError:
        raise RuntimeError(
            f"Blackwall API'ye ({BASE_URL}) ulaşılamıyor. Önce Blackwall'ı başlatın "
            f"(python app.py ya da ./run.sh). / Blackwall is not running."
        )


# ---------------------------------------------------------------------------
# Tool'lar
# ---------------------------------------------------------------------------
@mcp.tool()
def get_history(q: Optional[str] = None, limit: int = 50) -> list[dict]:
    """Blackwall proxy geçmişindeki (History) yakalanmış HTTP isteklerini listeler.

    Hedefin hangi istekleri yaptığını, hangi endpoint'lerin/parametrelerin var
    olduğunu keşfetmek için kullan. Sadece özet döner (gövde yok); tam istek/yanıt
    için dönen bir id ile get_flow çağır.

    Args:
        q: url / host / method içinde arama metni (opsiyonel).
        limit: en fazla kaç satır (varsayılan 50).
    """
    _check_blackwall_running()
    with _client() as c:
        r = c.get("/api/flows", params={"limit": max(1, min(limit, 1000)), **({"q": q} if q else {})})
    _raise_for(r)
    flows = r.json().get("flows", [])
    return [
        {
            "id": f["id"], "method": f["method"], "status": f.get("status_code"),
            "host": f["host"], "path": f["path"], "url": f["url"],
            "source": f["source"], "size": f.get("resp_size"),
            "duration_ms": round(f["duration_ms"]) if f.get("duration_ms") is not None else None,
            "error": f.get("error"),
        }
        for f in flows
    ]


@mcp.tool()
def get_flow(flow_id: int) -> dict:
    """Bir History kaydının (id ile) TAM istek ve yanıtını döndürür.

    İstek satırı + başlıklar + gövde ve yanıt satırı + başlıklar + gövde metin
    olarak verilir. get_history ile bulduğun bir id'yi incelemek için kullan.

    Args:
        flow_id: get_history'den gelen akış id'si.
    """
    _check_blackwall_running()
    with _client() as c:
        r = c.get(f"/api/flows/{flow_id}")
    _raise_for(r)
    f = r.json()

    def _body(b: dict) -> str:
        if not b or b.get("size", 0) == 0:
            return ""
        if b.get("text") is not None:
            return b["text"]
        return f"[binary {b.get('size')} bytes, base64]\n{b.get('base64') or ''}"

    req_hdr = "\n".join(f"{k}: {v}" for k, v in f.get("req_headers", []))
    req = f"{f['method']} {f['path']} {f.get('http_version') or 'HTTP/1.1'}\n{req_hdr}\n\n{_body(f.get('req_body'))}"
    if f.get("error"):
        resp = f"ERROR: {f['error']}"
    else:
        resp_hdr = "\n".join(f"{k}: {v}" for k, v in f.get("resp_headers", []))
        resp = (f"{f.get('http_version') or 'HTTP/1.1'} {f.get('status_code') or ''} "
                f"{f.get('reason') or ''}\n{resp_hdr}\n\n{_body(f.get('resp_body'))}")
    return {
        "id": f["id"], "url": f["url"], "status": f.get("status_code"),
        "request": req, "response": resp,
    }


@mcp.tool()
def send_request(
    url: str,
    method: str = "GET",
    headers: Optional[dict] = None,
    body: Optional[str] = None,
    verify_tls: bool = False,
    follow_redirects: bool = False,
) -> dict:
    """Tek bir HTTP isteği gönderir (Blackwall Repeater) ve yanıtı döndürür.

    Bir isteği elle değiştirip tekrar yollamak, bir hipotezi test etmek için kullan.
    GÜVENLİK: Yalnızca BLACKWALL_ALLOWED_HOSTS içindeki host'lara gider; liste boşsa
    reddedilir.

    Args:
        url: tam hedef URL (https://host/path).
        method: HTTP metodu (GET/POST/...).
        headers: {"İsim": "değer", ...} başlık sözlüğü (opsiyonel).
        body: istek gövdesi metni (opsiyonel).
        verify_tls: TLS sertifikası doğrulansın mı (varsayılan False).
        follow_redirects: yönlendirmeler izlensin mi (varsayılan False).
    """
    _check_blackwall_running()
    host = urlsplit(url).hostname or ""
    _require_allowed(host)
    payload: dict[str, Any] = {
        "method": method,
        "url": url,
        "headers": [[k, v] for k, v in (headers or {}).items()],
        "body_text": body,
        "verify_tls": verify_tls,
        "follow_redirects": follow_redirects,
    }
    with _client() as c:
        r = c.post("/api/repeater/send", json=payload)
    _raise_for(r)
    f = r.json()
    body_obj = f.get("resp_body") or {}
    return {
        "flow_id": f.get("id"),
        "status": f.get("status_code"),
        "reason": f.get("reason"),
        "error": f.get("error"),
        "headers": f.get("resp_headers", []),
        "body": body_obj.get("text") if body_obj.get("text") is not None
                else (f"[binary {body_obj.get('size', 0)} bytes]" if body_obj.get("size") else ""),
    }


@mcp.tool()
def run_intruder(
    request_text: str,
    payload_sets: list[list[str]],
    attack: str = "sniper",
    target: Optional[str] = None,
    grep: Optional[list[str]] = None,
    concurrency: int = 10,
    timeout: float = 15.0,
    verify_tls: bool = False,
    follow_redirects: bool = False,
    max_wait: float = 60.0,
) -> dict:
    """Bir ham isteği payload'larla çoğaltıp gönderir (Blackwall Intruder) ve sonuç tablosunu döndürür.

    Payload konumlarını ham istekte §...§ ile işaretle (ör. "user=§admin§").
    Fuzzing, kimlik/parola denemeleri, numaralandırma için kullan. İş tamamlanana
    (ya da max_wait'e) kadar bekler.

    Args:
        request_text: §...§ ile işaretli konumlar içeren ham HTTP isteği.
        payload_sets: her konum için payload listesi; sniper'da tek liste yeter.
        attack: "sniper" | "pitchfork" | "cluster".
        target: hedef "https://host:port" (verilmezse istekteki Host başlığından, şema https).
        grep: yanıt gövdesinde aranacak metinler; her biri sonuçta var/yok olarak işaretlenir.
        concurrency: eşzamanlı istek sayısı (varsayılan 10).
        timeout: istek başına timeout (s).
        verify_tls: TLS doğrulaması.
        follow_redirects: yönlendirme izleme.
        max_wait: sonuçlar için en fazla bekleme (s).
    """
    import time as _time

    _check_blackwall_running()
    if target:
        scheme, host, port = _parse_target(target)
    else:
        host = _host_from_request_text(request_text)
        scheme, port = "https", 0
    _require_allowed(host)

    payload = {
        "request_text": request_text,
        "scheme": scheme,
        "host": host,
        "port": port,
        "attack": attack,
        "payload_sets": payload_sets,
        "concurrency": concurrency,
        "timeout": timeout,
        "verify_tls": verify_tls,
        "follow_redirects": follow_redirects,
        "grep": grep or [],
    }
    with _client() as c:
        r = c.post("/api/intruder/start", json=payload)
        _raise_for(r)
        start = r.json()
        job_id = start["job_id"]

        deadline = _time.time() + max_wait
        state, data = "running", {}
        while _time.time() < deadline:
            sr = c.get(f"/api/intruder/status/{job_id}")
            _raise_for(sr)
            data = sr.json()
            state = data["state"]
            if state != "running":
                break
            _time.sleep(0.5)

    grep_terms = data.get("grep_terms", [])
    results = []
    for row in sorted(data.get("results", []), key=lambda x: x["index"]):
        item = {
            "index": row["index"],
            "payloads": row.get("payloads"),
            "status": row.get("status"),
            "length": row.get("length"),
            "duration_ms": round(row["duration_ms"]) if row.get("duration_ms") is not None else None,
            "error": row.get("error"),
        }
        if grep_terms:
            item["grep"] = {term: bool(hit) for term, hit in zip(grep_terms, row.get("grep", []))}
        results.append(item)

    return {
        "job_id": job_id,
        "state": state,
        "total": data.get("total"),
        "done": data.get("done"),
        "grep_terms": grep_terms,
        "note": None if state == "done" else f"state={state} (max_wait {max_wait}s dolmuş olabilir)",
        "results": results,
    }


@mcp.tool()
def decode(input: str, ops: list[str]) -> dict:
    """Bir metni çok katmanlı encode/decode/hash işleminden geçirir (Blackwall Decoder).

    ops sırayla uygulanır. Geçerli işlemler: base64-encode, base64-decode,
    base64url-encode, base64url-decode, url-encode, url-decode, html-encode,
    html-decode, hex-encode, hex-decode, ascii-encode, ascii-decode, md5, sha1, sha256.

    Args:
        input: girdi metni.
        ops: uygulanacak işlemler listesi (sırayla).
    """
    _check_blackwall_running()
    with _client() as c:
        r = c.post("/api/decoder/run", json={"input": input, "ops": ops})
    _raise_for(r)
    d = r.json()
    return {"result": d.get("result"), "steps": d.get("steps")}


@mcp.tool()
def jwt_decode(token: str) -> dict:
    """Bir JWT'yi imza doğrulamadan çözer: header + payload + alg + imza bilgisi.

    Args:
        token: xxxxx.yyyyy.zzzzz biçiminde JWT.
    """
    _check_blackwall_running()
    with _client() as c:
        r = c.post("/api/jwt/decode", json={"token": token})
    _raise_for(r)
    return r.json()


@mcp.tool()
def jwt_sign(
    payload: dict,
    alg: str = "HS256",
    secret: str = "",
    header: Optional[dict] = None,
) -> dict:
    """Bir JWT üretir/imzalar (Blackwall JWT). alg="none" ile imzasız, alg="HS256" ile secret ile imzalı.

    alg:none zafiyeti testleri ve bilinen secret ile token sahteleme için kullan.

    Args:
        payload: JWT payload sözlüğü.
        alg: "none" | "HS256".
        secret: HS256 için gizli anahtar.
        header: eklenecek/üzerine yazılacak header alanları (opsiyonel).
    """
    _check_blackwall_running()
    with _client() as c:
        r = c.post("/api/jwt/sign", json={"payload": payload, "alg": alg, "secret": secret, "header": header})
    _raise_for(r)
    return r.json()


@mcp.tool()
def check_oast() -> dict:
    """Çalışan OAST (interactsh) oturumunun durumunu ve yakalanan out-of-band etkileşimleri döndürür.

    SSRF / blind enjeksiyon / DNS exfil testlerinden sonra hedefin Blackwall'ın OAST
    subdomain'ine DNS/HTTP isteği yapıp yapmadığını kontrol etmek için kullan.
    (OAST oturumunu Blackwall arayüzünden başlatmış olman gerekir.)
    """
    _check_blackwall_running()
    with _client() as c:
        r = c.get("/api/oast/status")
    _raise_for(r)
    s = r.json()
    return {
        "active": s.get("active"),
        "polling": s.get("polling"),
        "server": s.get("server"),
        "subdomains": s.get("urls", []),
        "interaction_count": s.get("count", 0),
        "interactions": s.get("interactions", []),
        "error": s.get("error"),
        "hint": None if s.get("active") else "OAST oturumu aktif değil; Blackwall OAST sekmesinden 'Başlat' deyin.",
    }


if __name__ == "__main__":
    mcp.run(transport="stdio")
