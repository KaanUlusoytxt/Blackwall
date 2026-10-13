"""FastAPI uygulaması: history API'si, akış detayı ve Repeater.

Çalıştırma:
    uvicorn blackwall.web.app:app --reload
"""
from __future__ import annotations

import base64
import time
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from blackwall import db, tools

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
# Statik UI
# ---------------------------------------------------------------------------
@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
