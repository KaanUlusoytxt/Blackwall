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

from blackwall import db, tools

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

    # httpx'in kendi Host/Content-Length başlıklarını ezmesine izin ver; ama
    # kullanıcının verdiği başlıkları olduğu gibi gönder.
    headers = list(reqdata.headers)

    parsed = httpx.URL(reqdata.url)

    started = time.time()
    error: Optional[str] = None
    resp: Optional[httpx.Response] = None
    try:
        with httpx.Client(
            verify=reqdata.verify_tls,
            follow_redirects=reqdata.follow_redirects,
            timeout=reqdata.timeout,
        ) as client:
            resp = client.request(
                reqdata.method.upper(),
                reqdata.url,
                headers=headers,
                content=body,
            )
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
    attack: str = "sniper"               # sniper | pitchfork | cluster
    payload_sets: list[list[str]] = Field(default_factory=list)
    concurrency: int = 10
    timeout: float = 15.0
    verify_tls: bool = False
    follow_redirects: bool = False


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
                result: dict[str, Any] = {
                    "index": index,
                    "payloads": values,
                    "status": None,
                    "length": None,
                    "duration_ms": None,
                    "error": None,
                }
                started = time.perf_counter()
                try:
                    method, url, headers, body = tools.parse_http(concrete, job["scheme"])
                    # Host ve Content-Length httpx tarafından yeniden hesaplanır.
                    send_headers = [
                        (k, v) for k, v in headers
                        if k.lower() not in ("host", "content-length")
                    ]
                    resp = await client.request(
                        method, url, headers=send_headers,
                        content=body if body else None,
                    )
                    dur = (time.perf_counter() - started) * 1000.0
                    text = resp.text
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
                    job["requests"][index] = concrete
                except Exception as exc:
                    result["error"] = f"{type(exc).__name__}: {exc}"
                    result["duration_ms"] = (time.perf_counter() - started) * 1000.0
                    job["responses"][index] = f"HATA: {result['error']}"
                    job["requests"][index] = concrete
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
# Statik UI
# ---------------------------------------------------------------------------
@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
