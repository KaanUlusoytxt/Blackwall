#!/usr/bin/env python3
"""Blackwall MCP server.

Lets MCP clients such as Claude Code / Claude Desktop use Blackwall's tools as
tool calls. This server works by making requests to a RUNNING Blackwall instance's
HTTP API (default http://127.0.0.1:8000); it does not modify Blackwall's own code.

Run (usually started by the MCP client):
    .venv/bin/python mcp_server.py

Environment variables:
    BLACKWALL_URL            Blackwall HTTP API root (default http://127.0.0.1:8000)
    BLACKWALL_ALLOWED_HOSTS  allowed target hosts for send_request/run_intruder
                             (comma/space separated). If empty, both are refused.
                             Wildcards like "*.example.com" are supported.
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
# Helpers
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
    """Raise if the allow-list is empty or the host is not in it."""
    allowed = _allowed_hosts()
    if not allowed:
        raise ValueError(
            "BLACKWALL_ALLOWED_HOSTS is not set — for safety no target is "
            "contacted. Set an allowed host first, e.g. "
            "BLACKWALL_ALLOWED_HOSTS=\"0a12.web-security-academy.net\"."
        )
    if not _host_allowed(host):
        raise ValueError(
            f"'{host}' is not in the allow-list. Allowed: {', '.join(allowed)}. "
            f"Add the target to BLACKWALL_ALLOWED_HOSTS to prevent accidental attacks."
        )


def _parse_target(target: str) -> tuple[str, str, int]:
    """'https://host:port' or 'host:port' -> (scheme, host, port)."""
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
    # lang=en cookie -> Blackwall returns English error messages (for the MCP client).
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
            f"Cannot reach the Blackwall API at {BASE_URL}. Start Blackwall first "
            f"(python app.py or ./run.sh)."
        )


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
@mcp.tool()
def get_history(q: Optional[str] = None, limit: int = 50) -> list[dict]:
    """List captured HTTP requests from the Blackwall proxy history (History).

    Use it to discover what requests the target made and which endpoints/parameters
    exist. Returns summaries only (no body); call get_flow with a returned id for the
    full request/response.

    Args:
        q: search text within url / host / method (optional).
        limit: maximum number of rows (default 50).
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
    """Return the FULL request and response of a history entry (by id).

    Provided as text: request line + headers + body, and response line + headers +
    body. Use it to inspect an id you found with get_history.

    Args:
        flow_id: the flow id from get_history.
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
    """Send a single HTTP request (Blackwall Repeater) and return the response.

    Use it to tamper with and resend a request, or to test a hypothesis.
    SECURITY: only goes to hosts in BLACKWALL_ALLOWED_HOSTS; refused if the list is empty.

    Args:
        url: full target URL (https://host/path).
        method: HTTP method (GET/POST/...).
        headers: {"Name": "value", ...} header dict (optional).
        body: request body text (optional).
        verify_tls: whether to verify the TLS certificate (default False).
        follow_redirects: whether to follow redirects (default False).
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
    """Replay a raw request with payloads (Blackwall Intruder) and return the result table.

    Mark payload positions in the raw request with §...§ (e.g. "user=§admin§").
    Use it for fuzzing, credential/password attempts, and enumeration. Waits until the
    job finishes (or max_wait).

    Args:
        request_text: raw HTTP request containing §...§ marked positions.
        payload_sets: payload list per position; for sniper a single list is enough.
        attack: "sniper" | "pitchfork" | "cluster".
        target: target "https://host:port" (if omitted, taken from the Host header, scheme https).
        grep: strings to search in the response body; each is flagged present/absent per result.
        concurrency: number of concurrent requests (default 10).
        timeout: per-request timeout (s).
        verify_tls: TLS verification.
        follow_redirects: whether to follow redirects.
        max_wait: maximum wait for results (s).
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
        "note": None if state == "done" else f"state={state} (max_wait {max_wait}s may have elapsed)",
        "results": results,
    }


@mcp.tool()
def decode(input: str, ops: list[str]) -> dict:
    """Run a text through a multi-layer encode/decode/hash pipeline (Blackwall Decoder).

    ops are applied in order. Valid ops: base64-encode, base64-decode,
    base64url-encode, base64url-decode, url-encode, url-decode, html-encode,
    html-decode, hex-encode, hex-decode, ascii-encode, ascii-decode, md5, sha1, sha256.

    Args:
        input: input text.
        ops: list of ops to apply (in order).
    """
    _check_blackwall_running()
    with _client() as c:
        r = c.post("/api/decoder/run", json={"input": input, "ops": ops})
    _raise_for(r)
    d = r.json()
    return {"result": d.get("result"), "steps": d.get("steps")}


@mcp.tool()
def jwt_decode(token: str) -> dict:
    """Decode a JWT without verifying the signature: header + payload + alg + signature info.

    Args:
        token: JWT in xxxxx.yyyyy.zzzzz form.
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
    """Create/sign a JWT (Blackwall JWT). alg="none" for unsigned, alg="HS256" to sign with a secret.

    Use it for alg:none vulnerability tests and forging tokens with a known secret.

    Args:
        payload: JWT payload dict.
        alg: "none" | "HS256".
        secret: secret key for HS256.
        header: header fields to add/override (optional).
    """
    _check_blackwall_running()
    with _client() as c:
        r = c.post("/api/jwt/sign", json={"payload": payload, "alg": alg, "secret": secret, "header": header})
    _raise_for(r)
    return r.json()


@mcp.tool()
def check_oast() -> dict:
    """Return the status of the running OAST (interactsh) session and captured out-of-band interactions.

    Use it after SSRF / blind injection / DNS exfil tests to check whether the target
    made a DNS/HTTP request to Blackwall's OAST subdomain.
    (You must have started the OAST session from the Blackwall UI.)
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
        "hint": None if s.get("active") else "No active OAST session; start one from the Blackwall OAST tab.",
    }


def _parse_args(argv: list[str]) -> dict:
    """Resolve the transport selection from arguments + environment variables.

    Precedence: command-line argument > environment variable > default.
      transport: stdio (default) | http | streamable-http | sse
      --host / BLACKWALL_MCP_HOST  (default 127.0.0.1)
      --port / BLACKWALL_MCP_PORT  (default 9000)
      --path / BLACKWALL_MCP_PATH  (default /mcp)
    Shortcut: `mcp_server.py http` or `mcp_server.py sse`.
    """
    import argparse

    p = argparse.ArgumentParser(description="Blackwall MCP server")
    p.add_argument(
        "transport", nargs="?",
        default=os.environ.get("BLACKWALL_MCP_TRANSPORT", "stdio"),
        help="stdio | http | streamable-http | sse (default: stdio)",
    )
    p.add_argument("--transport", dest="transport_opt", default=None)
    p.add_argument("--host", default=os.environ.get("BLACKWALL_MCP_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.environ.get("BLACKWALL_MCP_PORT", "9000")))
    p.add_argument("--path", default=os.environ.get("BLACKWALL_MCP_PATH", "/mcp"))
    ns = p.parse_args(argv)
    transport = (ns.transport_opt or ns.transport or "stdio").lower()
    if transport == "http":           # convenience: http -> streamable-http
        transport = "streamable-http"
    return {"transport": transport, "host": ns.host, "port": ns.port, "path": ns.path}


def main(argv: Optional[list[str]] = None) -> None:
    import sys

    cfg = _parse_args(sys.argv[1:] if argv is None else argv)
    transport = cfg["transport"]

    if transport == "stdio":
        # Classic mode started by command (MCP Inspector and Claude Desktop).
        mcp.run(transport="stdio")
    elif transport == "streamable-http":
        # For the Claude Desktop "custom connector":
        #   http://<host>:<port><path>  (default http://127.0.0.1:9000/mcp)
        print(
            f"Blackwall MCP (streamable-http) → http://{cfg['host']}:{cfg['port']}{cfg['path']}",
            file=sys.stderr, flush=True,
        )
        mcp.run(transport="streamable-http", host=cfg["host"], port=cfg["port"],
                streamable_http_path=cfg["path"])
    elif transport == "sse":
        print(
            f"Blackwall MCP (sse) → http://{cfg['host']}:{cfg['port']}{cfg['path']}",
            file=sys.stderr, flush=True,
        )
        mcp.run(transport="sse", host=cfg["host"], port=cfg["port"], sse_path=cfg["path"])
    else:
        raise SystemExit(f"Unknown transport: {transport} (stdio | http | streamable-http | sse)")


if __name__ == "__main__":
    main()
