"""FastAPI uygulaması: history API'si, akış detayı ve Repeater.

Çalıştırma:
    uvicorn blackwall.web.app:app --reload
"""
from __future__ import annotations

import asyncio
import base64
import time
import uuid
from pathlib import Path
from typing import Any, Optional

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from blackwall import db, httpsend, oast, raw, tools

# Intruder sınırları
MAX_REQUESTS = 10_000      # bir saldırıda üretilecek toplam istek üst sınırı
MAX_CONCURRENCY = 100
MAX_STORED_BODY = 200_000  # saklanan yanıt gövdesi (karakter)
MAX_JOBS = 20              # bellekte tutulan iş sayısı

STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(title="Blackwall", version="0.1.0")


@app.on_event("startup")
def _startup() -> None:
    db.init_db()


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------
@app.get("/api/flows")
def api_flows(
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    q: Optional[str] = None,
):
    conn = db.connect()
    try:
        return {"flows": db.list_flows(conn, limit=limit, offset=offset, q=q)}
    finally:
        conn.close()


@app.get("/api/flows/{flow_id}")
def api_flow(flow_id: int):
    conn = db.connect()
    try:
        flow = db.get_flow(conn, flow_id)
    finally:
        conn.close()
    if flow is None:
        raise HTTPException(404, "Akış bulunamadı")
    return flow


@app.delete("/api/flows")
def api_clear():
    conn = db.connect()
    try:
        db.clear_flows(conn)
    finally:
        conn.close()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Repeater
# ---------------------------------------------------------------------------
class RepeaterRequest(BaseModel):
    method: str = "GET"
    url: str
    # Başlıklar [[isim, değer], ...] biçiminde; aynı başlık birden çok kez olabilir.
    headers: list[tuple[str, str]] = Field(default_factory=list)
    body_text: Optional[str] = None
    body_base64: Optional[str] = None
    # Sunucu sertifika doğrulaması (pentest hedeflerinde genelde kapalı istenir).
    verify_tls: bool = False
    follow_redirects: bool = False
    timeout: float = 30.0


@app.post("/api/repeater/send")
def api_repeater_send(reqdata: RepeaterRequest):
    if reqdata.body_base64 is not None:
        body: Optional[bytes] = base64.b64decode(reqdata.body_base64)
    elif reqdata.body_text is not None:
        body = reqdata.body_text.encode("utf-8")
    else:
        body = None

    headers = list(reqdata.headers)
    parsed = httpx.URL(reqdata.url)

    started = time.time()
    error: Optional[str] = None
    resp: Optional[httpx.Response] = None
    sent_raw: Optional[str] = None
    try:
        with httpx.Client(
            verify=reqdata.verify_tls,
            follow_redirects=reqdata.follow_redirects,
            timeout=reqdata.timeout,
        ) as client:
            # Intruder ile BİREBİR aynı gönderim yolu (CL gövdeye göre yeniden hesaplanır).
            req, sent_raw = httpsend.build_request(
                client,
                method=reqdata.method,
                url=reqdata.url,
                headers=headers,
                body=body,
            )
            resp = client.send(req, follow_redirects=reqdata.follow_redirects)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
    duration_ms = (time.time() - started) * 1000.0

    conn = db.connect()
    try:
        flow_id = db.insert_flow(
            conn,
            source="repeater",
            method=reqdata.method.upper(),
            scheme=parsed.scheme or "http",
            host=parsed.host or "",
            port=parsed.port or (443 if parsed.scheme == "https" else 80),
            path=parsed.raw_path.decode("ascii", "replace") if parsed.raw_path else "/",
            url=reqdata.url,
            http_version=resp.http_version if resp is not None else None,
            req_headers=headers,
            req_body=body,
            status_code=resp.status_code if resp is not None else None,
            reason=resp.reason_phrase if resp is not None else None,
            resp_headers=list(resp.headers.items()) if resp is not None else None,
            resp_body=resp.content if resp is not None else None,
            duration_ms=duration_ms,
            error=error,
        )
        detail = db.get_flow(conn, flow_id)
    finally:
        conn.close()
    return detail


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------
class DecoderRequest(BaseModel):
    input: str = ""
    ops: list[str] = Field(default_factory=list)


@app.get("/api/decoder/ops")
def api_decoder_ops():
    return {"ops": sorted(tools.DECODER_OPS)}


@app.post("/api/decoder/run")
def api_decoder_run(reqdata: DecoderRequest):
    steps = tools.run_pipeline(reqdata.input, reqdata.ops)
    result = steps[-1]["output"] if steps and steps[-1]["error"] is None else None
    return {"steps": steps, "result": result}


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------
class JwtDecodeRequest(BaseModel):
    token: str


class JwtSignRequest(BaseModel):
    payload: object
    alg: str = "HS256"           # "none" | "HS256"
    secret: str = ""
    header: Optional[dict] = None  # opsiyonel ek header alanları


@app.post("/api/jwt/decode")
def api_jwt_decode(reqdata: JwtDecodeRequest):
    try:
        return tools.jwt_decode(reqdata.token)
    except Exception as exc:
        raise HTTPException(400, f"JWT çözülemedi: {exc}")


@app.post("/api/jwt/sign")
def api_jwt_sign(reqdata: JwtSignRequest):
    try:
        return tools.jwt_sign(
            reqdata.payload,
            alg=reqdata.alg,
            secret=reqdata.secret,
            extra_header=reqdata.header,
        )
    except Exception as exc:
        raise HTTPException(400, f"İmzalama başarısız: {exc}")


# ---------------------------------------------------------------------------
# Intruder
# ---------------------------------------------------------------------------
# İş durumları bellekte tutulur (kalıcılık gerekmez; Faz 1 kapsamı).
INTRUDER_JOBS: dict[str, dict] = {}


class IntruderStart(BaseModel):
    request_text: str
    scheme: str = "https"
    host: str = ""                        # bağlantı hedefi (kaynak flow'dan); boşsa Host başlığından
    port: int = 0                         # 0 → şemaya göre varsayılan
    attack: str = "sniper"               # sniper | pitchfork | cluster
    payload_sets: list[list[str]] = Field(default_factory=list)
    concurrency: int = 10
    timeout: float = 15.0
    verify_tls: bool = False
    follow_redirects: bool = False
    grep: list[str] = Field(default_factory=list)   # yanıt gövdesinde aranacak metinler


def _prune_jobs() -> None:
    if len(INTRUDER_JOBS) <= MAX_JOBS:
        return
    oldest = sorted(INTRUDER_JOBS.items(), key=lambda kv: kv[1]["created"])
    for jid, _ in oldest[: len(INTRUDER_JOBS) - MAX_JOBS]:
        INTRUDER_JOBS.pop(jid, None)


async def _run_intruder(job_id: str) -> None:
    job = INTRUDER_JOBS[job_id]
    sem = asyncio.Semaphore(job["concurrency"])
    segments = job["segments"]
    cases: list[list[str]] = job["cases"]

    async with httpx.AsyncClient(
        verify=job["verify_tls"],
        follow_redirects=job["follow_redirects"],
        timeout=job["timeout"],
    ) as client:

        async def one(index: int, values: list[str]) -> None:
            async with sem:
                if job["state"] == "cancelled":
                    return
                concrete = tools.build_request(segments, values)
                grep_terms = job["grep_terms"]
                result: dict[str, Any] = {
                    "index": index,
                    "payloads": values,
                    "status": None,
                    "length": None,
                    "duration_ms": None,
                    "error": None,
                    "grep": [False] * len(grep_terms),
                }
                started = time.perf_counter()
                sent_raw = concrete  # parse başarısız olursa en azından ham metni sakla
                try:
                    # Hedef Host: satırından DEĞİL, kaynak flow'dan (şema+host+port) çözülür;
                    # path request satırından gelir. Sonra Repeater ile aynı gönderim yolu.
                    method, path, headers, body = tools.parse_request(concrete)
                    url = tools.resolve_url(
                        job["scheme"],
                        job["host"] or tools.host_header(headers),
                        job["port"],
                        path,
                    )
                    req, sent_raw = httpsend.build_request(
                        client, method=method, url=url, headers=headers, body=body
                    )
                    resp = await client.send(req, follow_redirects=job["follow_redirects"])
                    dur = (time.perf_counter() - started) * 1000.0
                    text = resp.text
                    # grep-match: yanıt GÖVDESİNDE (kısaltmadan önce) her metni ara
                    if grep_terms:
                        result["grep"] = [(t in text) for t in grep_terms]
                    truncated = len(text) > MAX_STORED_BODY
                    if truncated:
                        text = text[:MAX_STORED_BODY]
                    result.update(
                        status=resp.status_code,
                        length=len(resp.content),
                        duration_ms=dur,
                    )
                    status_line = (
                        f"{resp.http_version} {resp.status_code} {resp.reason_phrase}"
                    )
                    hdrs = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
                    job["responses"][index] = (
                        status_line + "\n" + hdrs + "\n\n" + text
                        + ("\n\n[... kısaltıldı ...]" if truncated else "")
                    )
                    job["requests"][index] = sent_raw
                except Exception as exc:
                    result["error"] = f"{type(exc).__name__}: {exc}"
                    result["duration_ms"] = (time.perf_counter() - started) * 1000.0
                    job["responses"][index] = f"HATA: {result['error']}"
                    job["requests"][index] = sent_raw
                finally:
                    job["results"].append(result)
                    job["done"] += 1

        await asyncio.gather(*(one(i, v) for i, v in enumerate(cases)))

    if job["state"] != "cancelled":
        job["state"] = "done"


@app.post("/api/intruder/start")
async def api_intruder_start(cfg: IntruderStart):
    segments, defaults = tools.parse_positions(cfg.request_text)
    try:
        cases = tools.build_cases(cfg.attack, defaults, cfg.payload_sets)
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    if not cases:
        raise HTTPException(400, "Üretilecek istek yok (payload listeleri boş olabilir)")
    if len(cases) > MAX_REQUESTS:
        raise HTTPException(
            400,
            f"Toplam istek sayısı {len(cases)}, üst sınır {MAX_REQUESTS}. "
            "Payload listelerini küçültün.",
        )

    concurrency = max(1, min(cfg.concurrency, MAX_CONCURRENCY))
    job_id = uuid.uuid4().hex[:12]
    INTRUDER_JOBS[job_id] = {
        "created": time.time(),
        "state": "running",
        "attack": cfg.attack,
        "scheme": cfg.scheme,
        "host": cfg.host.strip(),
        "port": cfg.port,
        "grep_terms": [t for t in (s.strip() for s in cfg.grep) if t],
        "segments": segments,
        "cases": cases,
        "concurrency": concurrency,
        "timeout": cfg.timeout,
        "verify_tls": cfg.verify_tls,
        "follow_redirects": cfg.follow_redirects,
        "total": len(cases),
        "done": 0,
        "results": [],
        "responses": {},
        "requests": {},
    }
    _prune_jobs()
    asyncio.create_task(_run_intruder(job_id))
    return {"job_id": job_id, "total": len(cases), "concurrency": concurrency}


@app.get("/api/intruder/status/{job_id}")
def api_intruder_status(job_id: str):
    job = INTRUDER_JOBS.get(job_id)
    if job is None:
        raise HTTPException(404, "İş bulunamadı")
    return {
        "state": job["state"],
        "total": job["total"],
        "done": job["done"],
        "attack": job["attack"],
        "grep_terms": job["grep_terms"],
        "results": job["results"],
    }


@app.post("/api/intruder/cancel/{job_id}")
def api_intruder_cancel(job_id: str):
    job = INTRUDER_JOBS.get(job_id)
    if job is None:
        raise HTTPException(404, "İş bulunamadı")
    if job["state"] == "running":
        job["state"] = "cancelled"
    return {"ok": True, "state": job["state"]}


@app.get("/api/intruder/result/{job_id}/{index}")
def api_intruder_result(job_id: str, index: int):
    job = INTRUDER_JOBS.get(job_id)
    if job is None:
        raise HTTPException(404, "İş bulunamadı")
    return {
        "request": job["requests"].get(index, ""),
        "response": job["responses"].get(index, "(yanıt yok)"),
    }


# ---------------------------------------------------------------------------
# OAST (interactsh)
# ---------------------------------------------------------------------------
# Tek, aktif OAST oturumu bellekte tutulur.
OAST_STATE: dict[str, Any] = {
    "client": None,
    "task": None,
    "polling": False,
    "server": None,
    "interval": 6.0,
    "interactions": [],
    "urls": [],
    "error": None,
    "started_at": None,
}


class OastStart(BaseModel):
    server: str = "oast.pro"
    token: str = ""
    interval: float = 6.0


async def _oast_loop() -> None:
    client: oast.InteractshClient = OAST_STATE["client"]
    while OAST_STATE["polling"]:
        try:
            raws = await asyncio.to_thread(client.poll)
            for raw in raws:
                n = oast.normalize_interaction(raw)
                n["index"] = len(OAST_STATE["interactions"])
                n["received_at"] = time.time()
                OAST_STATE["interactions"].append(n)
            OAST_STATE["error"] = None
        except oast.InteractshError as exc:
            OAST_STATE["error"] = str(exc)
        except Exception as exc:  # döngü çökmesin
            OAST_STATE["error"] = f"{type(exc).__name__}: {exc}"
        await asyncio.sleep(OAST_STATE["interval"])


async def _oast_stop_current() -> None:
    OAST_STATE["polling"] = False
    task = OAST_STATE["task"]
    if task:
        task.cancel()
    client = OAST_STATE["client"]
    if client:
        await asyncio.to_thread(client.deregister)
    OAST_STATE["task"] = None


def _oast_status() -> dict:
    client = OAST_STATE["client"]
    summary = [
        {
            "index": i["index"],
            "protocol": i["protocol"],
            "q_type": i["q_type"],
            "remote_address": i["remote_address"],
            "timestamp": i["timestamp"],
            "full_id": i["full_id"],
            "received_at": i["received_at"],
        }
        for i in OAST_STATE["interactions"]
    ]
    return {
        "active": client is not None,
        "polling": OAST_STATE["polling"],
        "server": OAST_STATE["server"],
        "correlation_id": client.correlation_id if client else None,
        "urls": OAST_STATE["urls"],
        "interactions": summary,
        "count": len(summary),
        "error": OAST_STATE["error"],
    }


@app.post("/api/oast/start")
async def api_oast_start(cfg: OastStart):
    await _oast_stop_current()
    OAST_STATE.update(
        client=None, interactions=[], urls=[], error=None,
        server=cfg.server, interval=max(2.0, cfg.interval),
    )
    client = oast.InteractshClient(server=cfg.server, token=cfg.token)
    try:
        await asyncio.to_thread(client.register)
    except oast.InteractshError as exc:
        raise HTTPException(400, str(exc))
    OAST_STATE["client"] = client
    OAST_STATE["started_at"] = time.time()
    first_url = client.new_url()
    OAST_STATE["urls"].append(first_url)
    OAST_STATE["polling"] = True
    OAST_STATE["task"] = asyncio.create_task(_oast_loop())
    return _oast_status()


@app.post("/api/oast/generate")
def api_oast_generate():
    client = OAST_STATE["client"]
    if client is None:
        raise HTTPException(400, "Aktif OAST oturumu yok")
    url = client.new_url()
    OAST_STATE["urls"].append(url)
    return {"url": url}


@app.post("/api/oast/pause")
def api_oast_pause():
    if OAST_STATE["client"] is None:
        raise HTTPException(400, "Aktif OAST oturumu yok")
    OAST_STATE["polling"] = False
    return _oast_status()


@app.post("/api/oast/resume")
async def api_oast_resume():
    if OAST_STATE["client"] is None:
        raise HTTPException(400, "Aktif OAST oturumu yok")
    if not OAST_STATE["polling"]:
        OAST_STATE["polling"] = True
        OAST_STATE["task"] = asyncio.create_task(_oast_loop())
    return _oast_status()


@app.post("/api/oast/stop")
async def api_oast_stop():
    await _oast_stop_current()
    OAST_STATE.update(client=None, server=None, started_at=None)
    return {"ok": True}


@app.get("/api/oast/status")
def api_oast_status():
    return _oast_status()


@app.get("/api/oast/interaction/{index}")
def api_oast_interaction(index: int):
    items = OAST_STATE["interactions"]
    if index < 0 or index >= len(items):
        raise HTTPException(404, "Etkileşim bulunamadı")
    return items[index]


# ---------------------------------------------------------------------------
# WebSocket (yakalama görüntüleme + enjeksiyon kuyruğu)
# ---------------------------------------------------------------------------
class WsInjectRequest(BaseModel):
    flow_id: str
    direction: str = "c2s"       # c2s | s2c
    type: str = "text"           # text | binary
    content_text: Optional[str] = None
    content_base64: Optional[str] = None


@app.get("/api/ws/flows")
def api_ws_flows():
    conn = db.connect()
    try:
        return {"flows": db.ws_list_flows(conn)}
    finally:
        conn.close()


@app.get("/api/ws/flows/{flow_id}/messages")
def api_ws_messages(flow_id: str, after_id: int = 0):
    conn = db.connect()
    try:
        return {"messages": db.ws_list_messages(conn, flow_id, after_id=after_id)}
    finally:
        conn.close()


@app.post("/api/ws/inject")
def api_ws_inject(reqdata: WsInjectRequest):
    if reqdata.direction not in ("c2s", "s2c"):
        raise HTTPException(400, "direction c2s veya s2c olmalı")
    if reqdata.content_base64 is not None:
        content = base64.b64decode(reqdata.content_base64)
    elif reqdata.content_text is not None:
        content = reqdata.content_text.encode("utf-8")
    else:
        content = b""

    conn = db.connect()
    try:
        flow = conn.execute(
            "SELECT state FROM ws_flows WHERE flow_id=?", (reqdata.flow_id,)
        ).fetchone()
        if flow is None:
            raise HTTPException(404, "WebSocket akışı bulunamadı")
        if flow["state"] != "open":
            raise HTTPException(409, "Bağlantı artık açık değil; mesaj gönderilemez")
        inject_id = db.ws_enqueue_inject(
            conn,
            flow_id=reqdata.flow_id,
            direction=reqdata.direction,
            type=reqdata.type,
            content=content,
            created_at=time.time(),
        )
    finally:
        conn.close()
    # addon kuyruğu ~0.4s içinde işler; durum ayrı endpoint'ten yoklanır.
    return {"inject_id": inject_id, "status": "pending"}


@app.get("/api/ws/inject/{inject_id}")
def api_ws_inject_status(inject_id: int):
    conn = db.connect()
    try:
        row = db.ws_get_inject(conn, inject_id)
    finally:
        conn.close()
    if row is None:
        raise HTTPException(404, "Enjeksiyon kaydı bulunamadı")
    return row


# ---------------------------------------------------------------------------
# Raw — ham TCP/TLS istek göndericisi (smuggling)
# ---------------------------------------------------------------------------
class RawSendRequest(BaseModel):
    host: str
    port: int = 80
    tls: bool = False
    http_version: str = "1.1"        # 1.1 (ham socket) | 2 (h2)
    mode: str = "crlf"               # crlf | lf | escape (yalnızca 1.1)
    request1: str = ""
    request2: Optional[str] = None   # aynı socket/bağlantıda ikinci istek
    timeout: float = 10.0
    read_idle: float = 1.0
    delay_ms: int = 0
    sni: Optional[str] = None


@app.post("/api/raw/send")
async def api_raw_send(reqdata: RawSendRequest):
    host = reqdata.host.strip()
    if not host:
        raise HTTPException(400, "host gerekli")
    if not (1 <= reqdata.port <= 65535):
        raise HTTPException(400, "port 1-65535 arası olmalı")
    sni = reqdata.sni.strip() if reqdata.sni else None

    if reqdata.http_version == "2":
        # HTTP/2: ham istek metni parse edilip geçerli h2 isteğine çevrilir.
        req_texts = [reqdata.request1]
        if reqdata.request2 and reqdata.request2.strip():
            req_texts.append(reqdata.request2)
        requests = []
        for text in req_texts:
            try:
                method, path, headers, body = tools.parse_request(text)
            except ValueError as exc:
                raise HTTPException(400, str(exc))
            authority = tools.host_header(headers) or (
                host if reqdata.port == 443 else f"{host}:{reqdata.port}"
            )
            requests.append({"method": method, "path": path, "headers": headers,
                             "body": body, "authority": authority})
        result = await asyncio.to_thread(
            raw.h2_send, host=host, port=reqdata.port, requests=requests,
            timeout=reqdata.timeout, read_idle=reqdata.read_idle, sni=sni,
        )
        return result

    # HTTP/1.1 ham socket (mevcut davranış + iki-istek pipeline).
    if reqdata.mode not in ("crlf", "lf", "escape"):
        raise HTTPException(400, "mode crlf | lf | escape olmalı")
    try:
        payloads = [raw.encode_payload(reqdata.request1, reqdata.mode)]
        if reqdata.request2 and reqdata.request2.strip():
            payloads.append(raw.encode_payload(reqdata.request2, reqdata.mode))
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    result = await asyncio.to_thread(
        raw.send_raw,
        host=host,
        port=reqdata.port,
        use_tls=reqdata.tls,
        payloads=payloads,
        timeout=reqdata.timeout,
        read_idle=reqdata.read_idle,
        delay_ms=reqdata.delay_ms,
        sni=sni,
    )
    return result


# ---------------------------------------------------------------------------
# Race — last-byte synchronization ile race condition saldırısı
# ---------------------------------------------------------------------------
class RaceRequest(BaseModel):
    host: str
    port: int = 80
    tls: bool = False
    sync_mode: str = "last-byte"     # last-byte (HTTP/1.1) | single-packet (HTTP/2)
    request: str = ""
    count: int = 20
    timeout: float = 10.0
    read_idle: float = 1.0
    prefix_delay_ms: int = 100
    sni: Optional[str] = None


@app.post("/api/race/run")
async def api_race_run(reqdata: RaceRequest):
    host, port = tools.clean_host(reqdata.host, reqdata.port)
    if not host:
        raise HTTPException(400, "host gerekli")
    if not port:
        port = 443 if reqdata.tls else 80
    if not (1 <= port <= 65535):
        raise HTTPException(400, "port 1-65535 arası olmalı")

    try:
        method, path, headers, body = tools.parse_request(reqdata.request)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    sni = reqdata.sni.strip() if reqdata.sni else None

    if reqdata.sync_mode == "single-packet":
        # HTTP/2 single-packet attack (ALPN h2 → TLS zorunlu).
        authority = tools.host_header(headers) or (host if port == 443 else f"{host}:{port}")
        result = await asyncio.to_thread(
            raw.race_single_packet,
            host=host, port=port, method=method, path=path,
            headers=headers, body=body, count=reqdata.count,
            timeout=reqdata.timeout, read_idle=reqdata.read_idle,
            prefix_delay_ms=reqdata.prefix_delay_ms, sni=sni, authority=authority,
        )
        sent = _render_h2_request(method, path, authority, headers, body)
        result["sent_request"] = sent
        result["sent_request_hex"] = raw.hexdump(sent.encode("latin-1", "replace"))
        return result

    # last-byte (HTTP/1.1): payload Repeater ile BİREBİR aynı httpx tel byte'ları.
    scheme = "https" if reqdata.tls else "http"
    url = tools.resolve_url(scheme, host, port, path)
    with httpx.Client() as client:
        req, _ = httpsend.build_request(
            client, method=method, url=url, headers=headers, body=body
        )
    payload = httpsend.request_wire_bytes(req)
    if not payload:
        raise HTTPException(400, "boş istek gönderilemez")

    result = await asyncio.to_thread(
        raw.race_last_byte,
        host=host, port=port, use_tls=reqdata.tls, payload=payload,
        count=reqdata.count, timeout=reqdata.timeout, read_idle=reqdata.read_idle,
        prefix_delay_ms=reqdata.prefix_delay_ms, sni=sni,
    )
    result["sent_request"] = payload.decode("latin-1")
    result["sent_request_hex"] = raw.hexdump(payload)
    return result


def _render_h2_request(method, path, authority, headers, body: Optional[bytes]) -> str:
    """HTTP/2 isteğini görüntü için okunur metne çevirir (pseudo-header'lar dahil)."""
    forbidden = {"host", "connection", "keep-alive", "proxy-connection",
                 "transfer-encoding", "upgrade", "content-length"}
    lines = [f":method: {method}", f":path: {path}", ":scheme: https",
             f":authority: {authority}"]
    lines += [f"{k.lower()}: {v}" for k, v in headers if k.lower() not in forbidden]
    text = "\r\n".join(lines) + "\r\n\r\n"
    if body:
        try:
            text += body.decode("utf-8")
        except UnicodeDecodeError:
            text += body.decode("latin-1")
    return text


# ---------------------------------------------------------------------------
# Statik UI
# ---------------------------------------------------------------------------
@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
