"""Raw TCP/TLS request sender — for request smuggling / desync research.

Design principles:
  * ONLY stdlib socket + ssl. NO httpx/requests.
  * The user's bytes are untouched: Content-Length / Transfer-Encoding are not
    auto-computed or fixed, header order is preserved, and a chunked body is sent
    as-is.
  * Multiple requests can be sent back-to-back on a single connection (one socket) —
    required for desync tests like CL.TE / TE.CL.

Line-ending modes (since a literal CR cannot be typed in a textarea):
  * crlf   — real line endings are converted to CRLF (for normal requests).
  * lf     — real line endings stay LF (UTF-8).
  * escape — real line endings are ignored; only \\r \\n \\t \\0 \\xHH \\\\
             escapes produce bytes; other characters are UTF-8. Full byte control.
"""
from __future__ import annotations

import base64
import socket
import ssl
import threading
import time
from collections import Counter
from typing import Optional

MAX_RACE = 255          # max number of concurrent connections
RACE_BODY_CAP = 65536   # max stored response body (bytes)


def _decode_escapes(text: str) -> bytes:
    out = bytearray()
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in ("\r", "\n"):
            # in escape mode real line endings are purely visual and ignored
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            nxt = text[i + 1]
            simple = {"r": 0x0D, "n": 0x0A, "t": 0x09, "0": 0x00, "\\": 0x5C}
            if nxt in simple:
                out.append(simple[nxt])
                i += 2
                continue
            if nxt == "x" and i + 3 < n + 1:
                try:
                    out.append(int(text[i + 2 : i + 4], 16))
                    i += 4
                    continue
                except ValueError:
                    pass
            # unknown escape: keep the backslash as-is
            out.append(0x5C)
            i += 1
            continue
        out.extend(c.encode("utf-8"))
        i += 1
    return bytes(out)


def encode_payload(text: str, mode: str) -> bytes:
    """Convert text to raw bytes per the line-ending mode (no other changes)."""
    if mode == "lf":
        return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
    if mode == "crlf":
        normalized = text.replace("\r\n", "\n").replace("\r", "\n")
        return normalized.replace("\n", "\r\n").encode("utf-8")
    if mode == "escape":
        return _decode_escapes(text)
    raise ValueError(f"unknown mode: {mode}")


def open_connection(
    host: str, port: int, use_tls: bool, timeout: float, sni: Optional[str] = None
) -> tuple[socket.socket, Optional[str]]:
    """Open a raw TCP (optionally TLS) connection. Errors raise as OSError/SSLError."""
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    tls_version: Optional[str] = None
    if use_tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Same TLS as Repeater (httpx): ALPN is http/1.1 only (do not negotiate h2).
        try:
            ctx.set_alpn_protocols(["http/1.1"])
        except NotImplementedError:
            pass
        # SNI is sent (server_hostname); it may not be sent for an IP.
        server_hostname = sni if sni else host
        try:
            sock = ctx.wrap_socket(sock, server_hostname=server_hostname)
        except (ValueError, ssl.SSLError):
            sock = ctx.wrap_socket(sock, server_hostname=None)
        tls_version = sock.version()
    return sock, tls_version


def hexdump(data: bytes) -> str:
    """Return a classic hex dump of the byte sequence (debug)."""
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hexpart:<47}  {asc}")
    return "\n".join(lines)


def _recv_response(sock: socket.socket, total_timeout: float, read_idle: float) -> bytes:
    """Read until the connection closes, goes idle (read_idle), or total_timeout elapses."""
    chunks: list[bytes] = []
    deadline = time.time() + total_timeout
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        sock.settimeout(min(read_idle, remaining))
        try:
            data = sock.recv(65536)
        except (socket.timeout, TimeoutError):
            break  # no data for a while -> response (for now) complete
        except ssl.SSLWantReadError:
            continue
        if not data:
            break  # the peer closed
        chunks.append(data)
    return b"".join(chunks)


def _header_dict(block: bytes) -> dict[str, str]:
    """Convert the response header block (excluding the status line) to a lowercased dict."""
    out: dict[str, str] = {}
    for line in block.split(b"\r\n")[1:]:
        if b":" not in line:
            continue
        k, _, v = line.partition(b":")
        out[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1")
    return out


def _chunked_end(data: bytes, start: int) -> Optional[int]:
    """Return the index where the chunked body ends (after the final 0-chunk + terminator)."""
    i, n = start, len(data)
    while i < n:
        le = data.find(b"\r\n", i)
        if le == -1:
            return None
        size_field = data[i:le].split(b";", 1)[0].strip()
        try:
            size = int(size_field, 16)
        except ValueError:
            return None
        i = le + 2
        if size == 0:
            # if trailers exist, consume up to the blank line
            while i < n:
                le2 = data.find(b"\r\n", i)
                if le2 == -1:
                    return None
                if le2 == i:          # blank line -> end of chunked
                    return i + 2
                i = le2 + 2
            return None
        i += size + 2                 # chunk data + the following \r\n
    return None


def split_http_responses(data: bytes) -> list[bytes]:
    """Split concatenated HTTP/1.1 responses from a single socket into separate ones.

    Body length is taken from Transfer-Encoding: chunked, else Content-Length, else
    up to EOF (only for the last response).
    """
    responses: list[bytes] = []
    i, n = 0, len(data)
    while i < n:
        hdr_end = data.find(b"\r\n\r\n", i)
        if hdr_end == -1:
            responses.append(data[i:])        # incomplete/raw remainder
            break
        headers = _header_dict(data[i:hdr_end])
        body_start = hdr_end + 4
        te = headers.get("transfer-encoding", "").lower()
        cl = headers.get("content-length")
        if "chunked" in te:
            end = _chunked_end(data, body_start)
            if end is None:
                responses.append(data[i:]); break
            responses.append(data[i:end]); i = end
        elif cl is not None:
            try:
                length = int(cl)
            except ValueError:
                length = 0
            end = body_start + length
            if end > n:
                responses.append(data[i:]); break   # incomplete body
            responses.append(data[i:end]); i = end
        else:
            responses.append(data[i:]); break        # no CL/chunked -> up to EOF
    return responses


def send_raw(
    *,
    host: str,
    port: int,
    use_tls: bool,
    payloads: list[bytes],
    timeout: float = 10.0,
    read_idle: float = 1.0,
    delay_ms: int = 0,
    sni: Optional[str] = None,
) -> dict:
    """Open one socket and send the payloads.

    * Single request: send -> read the response (existing behavior).
    * Two+ requests (smuggling): all requests are written to the same socket
      back-to-back without waiting for the first response (pipeline), then ALL
      incoming data is read and split into responses. This way the second response
      (e.g. 404) is captured even with `Connection: close`.
    """
    result: dict = {"requests": [], "error": None, "tls": use_tls}
    sock: Optional[socket.socket] = None
    try:
        sock, tls_version = open_connection(host, port, use_tls, timeout, sni)
        if tls_version:
            result["tls_version"] = tls_version
    except OSError as exc:
        result["error"] = f"Connection error: {type(exc).__name__}: {exc}"
        if sock:
            try:
                sock.close()
            except Exception:
                pass
        return result

    try:
        if len(payloads) >= 2:
            _send_pipeline(sock, payloads, result, timeout, read_idle, delay_ms)
        else:
            _send_sequential(sock, payloads, result, timeout, read_idle, delay_ms)
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return result


def _send_sequential(sock, payloads, result, timeout, read_idle, delay_ms) -> None:
    """Single-request (and generally sequential) behavior: send -> read the response."""
    for i, payload in enumerate(payloads):
        if i > 0 and delay_ms > 0:
            time.sleep(delay_ms / 1000.0)
        entry: dict = {
            "index": i,
            "sent_size": len(payload),
            "sent_base64": base64.b64encode(payload).decode("ascii"),
            "send_error": None,
            "recv_error": None,
            "response_base64": "",
            "response_size": 0,
            "duration_ms": 0.0,
        }
        started = time.time()
        try:
            sock.settimeout(timeout)
            sock.sendall(payload)
        except OSError as exc:
            entry["send_error"] = f"{type(exc).__name__}: {exc}"
            entry["duration_ms"] = (time.time() - started) * 1000.0
            result["requests"].append(entry)
            break
        try:
            resp = _recv_response(sock, timeout, read_idle)
            entry["response_base64"] = base64.b64encode(resp).decode("ascii")
            entry["response_size"] = len(resp)
        except OSError as exc:
            entry["recv_error"] = f"{type(exc).__name__}: {exc}"
        entry["duration_ms"] = (time.time() - started) * 1000.0
        result["requests"].append(entry)


def _send_pipeline(sock, payloads, result, timeout, read_idle, delay_ms) -> None:
    """Pipeline: write all requests back-to-back, then read all data and split into responses."""
    entries: list[dict] = []
    for i, payload in enumerate(payloads):
        entries.append({
            "index": i,
            "sent_size": len(payload),
            "sent_base64": base64.b64encode(payload).decode("ascii"),
            "send_error": None,
            "recv_error": None,
            "response_base64": "",
            "response_size": 0,
            "duration_ms": 0.0,
        })

    started = time.time()
    # Write all payloads back-to-back without waiting for the first response.
    for i, payload in enumerate(payloads):
        if i > 0 and delay_ms > 0:
            time.sleep(delay_ms / 1000.0)
        try:
            sock.settimeout(timeout)
            sock.sendall(payload)
        except OSError as exc:
            entries[i]["send_error"] = f"{type(exc).__name__}: {exc}"
            break

    # Read ALL incoming data (EOF if Connection: close, otherwise stop on read_idle).
    recv_error = None
    raw = b""
    try:
        raw = _recv_response(sock, timeout, read_idle)
    except OSError as exc:
        recv_error = f"{type(exc).__name__}: {exc}"

    elapsed = (time.time() - started) * 1000.0
    responses = split_http_responses(raw) if raw else []

    for i, entry in enumerate(entries):
        entry["duration_ms"] = elapsed
        if i < len(responses):
            entry["response_base64"] = base64.b64encode(responses[i]).decode("ascii")
            entry["response_size"] = len(responses[i])
        elif recv_error:
            entry["recv_error"] = recv_error
        result["requests"].append(entry)

    # If more responses arrived than requests (rare), append to the last request.
    if len(responses) > len(entries) and entries:
        extra = b"".join(responses[len(entries):])
        last = result["requests"][-1]
        merged = base64.b64decode(last["response_base64"]) + extra
        last["response_base64"] = base64.b64encode(merged).decode("ascii")
        last["response_size"] = len(merged)


def _parse_status(resp: bytes) -> Optional[int]:
    if not resp:
        return None
    try:
        line = resp.split(b"\r\n", 1)[0]
        parts = line.split(b" ")
        if len(parts) >= 2 and parts[0].upper().startswith(b"HTTP"):
            return int(parts[1])
    except (ValueError, IndexError):
        pass
    return None


def race_last_byte(
    *,
    host: str,
    port: int,
    use_tls: bool,
    payload: bytes,
    count: int,
    timeout: float = 10.0,
    read_idle: float = 1.0,
    prefix_delay_ms: int = 100,
    sni: Optional[str] = None,
) -> dict:
    """Race-condition attack via last-byte synchronization.

    Each connection sends all but the LAST byte of the request, waits a short while
    (so the server buffers the prefix), then meets at a barrier and flushes the last
    byte together -> requests arrive at the server ~simultaneously (HTTP/1.1).
    """
    if len(payload) < 1:
        return {"error": "cannot send an empty request", "results": [], "count": 0}
    count = max(1, min(count, MAX_RACE))   # N=1 -> single request
    prefix, last = payload[:-1], payload[-1:]
    results: list[Optional[dict]] = [None] * count
    barrier = threading.Barrier(count)
    t0 = time.perf_counter()

    def worker(idx: int) -> None:
        entry: dict = {
            "index": idx, "status": None, "response_size": 0,
            "sent_offset_ms": None, "arrival_ms": None, "error": None,
            "response_base64": "", "tls_version": None,
        }
        sock: Optional[socket.socket] = None
        try:
            sock, entry["tls_version"] = open_connection(host, port, use_tls, timeout, sni)
            sock.sendall(prefix)
            time.sleep(prefix_delay_ms / 1000.0)
        except Exception as exc:
            entry["error"] = f"{type(exc).__name__}: {exc}"
            results[idx] = entry
            try:
                barrier.abort()  # release the other waiting threads
            except Exception:
                pass
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
            return

        # Sync point: all connections ready -> flush the last bytes together
        try:
            barrier.wait(timeout=max(5.0, timeout))
        except threading.BrokenBarrierError:
            pass  # a connection dropped; send the last byte anyway

        entry["sent_offset_ms"] = (time.perf_counter() - t0) * 1000.0
        try:
            sock.sendall(last)
            resp = _recv_response(sock, timeout, read_idle)
            entry["arrival_ms"] = (time.perf_counter() - t0) * 1000.0
            entry["response_size"] = len(resp)
            entry["status"] = _parse_status(resp)
            entry["response_base64"] = base64.b64encode(resp[:RACE_BODY_CAP]).decode("ascii")
        except OSError as exc:
            entry["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            try:
                sock.close()
            except Exception:
                pass
        results[idx] = entry

    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    final = [r for r in results if r is not None]
    return _finalize_race(final)


def _finalize_race(results: list[dict], error: Optional[str] = None) -> dict:
    """Shared result packaging: signature, race-winner (distinct), and sync spread."""
    # Race winner: the most common (status, length) signature is "normal"; others are distinct.
    sigs = Counter((r["status"], r["response_size"]) for r in results if r["error"] is None)
    majority = sigs.most_common(1)[0][0] if sigs else None
    for r in results:
        r["signature"] = f"{r['status']}·{r['response_size']}B"
        r["distinct"] = (
            r["error"] is None and majority is not None
            and (r["status"], r["response_size"]) != majority
        )
    offsets = [r["sent_offset_ms"] for r in results if r["sent_offset_ms"] is not None]
    spread = (max(offsets) - min(offsets)) if len(offsets) >= 2 else 0.0
    return {
        "error": error,
        "results": results,
        "count": len(results),
        "majority": (f"{majority[0]}·{majority[1]}B" if majority else None),
        "sync_spread_ms": spread,
    }


def race_single_packet(
    *,
    host: str,
    port: int,
    method: str,
    path: str,
    headers: list[tuple[str, str]],
    body: Optional[bytes],
    count: int,
    timeout: float = 15.0,
    read_idle: float = 2.0,
    prefix_delay_ms: int = 100,
    sni: Optional[str] = None,
    authority: Optional[str] = None,
) -> dict:
    """HTTP/2 single-packet attack.

    Opens one TLS connection (ALPN h2); prepares N requests as separate streams
    (HEADERS + body if any, NO END_STREAM). Once all are ready, it sends every
    stream's END_STREAM frame in a SINGLE write() -> the requests arrive at the
    server in one TCP packet, simultaneously.
    """
    import h2.config
    import h2.connection
    import h2.events

    count = max(1, min(count, MAX_RACE))
    body = body or b""

    # Connection (ALPN h2 required)
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"])
        server_hostname = sni if sni else host
        try:
            tsock = ctx.wrap_socket(sock, server_hostname=server_hostname)
        except (ValueError, ssl.SSLError):
            tsock = ctx.wrap_socket(sock, server_hostname=None)
    except OSError as exc:
        return _finalize_race([], error=f"Connection error: {type(exc).__name__}: {exc}")

    if tsock.selected_alpn_protocol() != "h2":
        try:
            tsock.close()
        except Exception:
            pass
        return _finalize_race([], error="Server does not support HTTP/2 (ALPN h2)")

    try:
        conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=True)
        )
        conn.initiate_connection()
        tsock.sendall(conn.data_to_send())

        # h2 headers: pseudo-headers first; drop connection-specific + Host/CL.
        if not authority:
            authority = tools_host_header(headers) or host
        forbidden = {
            "host", "connection", "keep-alive", "proxy-connection",
            "transfer-encoding", "upgrade", "content-length",
        }
        h2_headers = [
            (":method", method),
            (":path", path),
            (":scheme", "https"),
            (":authority", authority),
        ] + [(k.lower(), v) for k, v in headers if k.lower() not in forbidden]

        # Prime: HEADERS (NO END_STREAM) + body if any (NO END_STREAM).
        # So even body-less requests get END_STREAM in the salvo -> single-packet.
        stream_ids: list[int] = []
        for _ in range(count):
            sid = conn.get_next_available_stream_id()
            stream_ids.append(sid)
            conn.send_headers(sid, h2_headers, end_stream=False)
            if body:
                conn.send_data(sid, body, end_stream=False)
        prime = conn.data_to_send()
        if prime:
            tsock.sendall(prime)

        # Short wait so the server buffers the prime.
        time.sleep(max(0, prefix_delay_ms) / 1000.0)

        # Salvo: every stream's END_STREAM frame in a SINGLE write().
        for sid in stream_ids:
            conn.end_stream(sid)
        salvo = conn.data_to_send()

        t0 = time.perf_counter()
        if salvo:
            tsock.sendall(salvo)   # SINGLE PACKET: all END_STREAM frames

        # Read the responses
        idx_of = {sid: i for i, sid in enumerate(stream_ids)}
        acc: dict[int, dict] = {
            sid: {"status": None, "headers": [], "body": b"", "arrival": None}
            for sid in stream_ids
        }
        ended: set[int] = set()
        deadline = time.time() + timeout
        while len(ended) < count:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            tsock.settimeout(min(read_idle, remaining))
            try:
                data = tsock.recv(65536)
            except (socket.timeout, TimeoutError):
                continue   # idle gap; wait until all streams end / the deadline
            if not data:
                break      # connection closed
            for ev in conn.receive_data(data):
                if isinstance(ev, h2.events.ResponseReceived):
                    acc[ev.stream_id]["headers"] = ev.headers
                    for k, v in ev.headers:
                        kk = k.decode("latin-1") if isinstance(k, bytes) else k
                        if kk == ":status":
                            vv = v.decode("latin-1") if isinstance(v, bytes) else v
                            try:
                                acc[ev.stream_id]["status"] = int(vv)
                            except ValueError:
                                pass
                elif isinstance(ev, h2.events.DataReceived):
                    acc[ev.stream_id]["body"] += ev.data
                    conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                elif isinstance(ev, h2.events.StreamEnded):
                    ended.add(ev.stream_id)
                    acc[ev.stream_id]["arrival"] = (time.perf_counter() - t0) * 1000.0
            out = conn.data_to_send()
            if out:
                tsock.sendall(out)

        # Result rows (stream order = index)
        results: list[dict] = []
        for sid in stream_ids:
            a = acc[sid]
            full = _reconstruct_h2_response(a["status"], a["headers"], a["body"])
            results.append({
                "index": idx_of[sid],
                "status": a["status"],
                "response_size": len(full),
                "sent_offset_ms": 0.0,                  # single packet -> all at once
                "arrival_ms": a["arrival"],
                "error": None if a["status"] is not None else "no response received",
                "response_base64": base64.b64encode(full[:RACE_BODY_CAP]).decode("ascii"),
            })
        return _finalize_race(results)
    except Exception as exc:
        return _finalize_race([], error=f"{type(exc).__name__}: {exc}")
    finally:
        try:
            tsock.close()
        except Exception:
            pass


def _reconstruct_h2_response(status, headers, body: bytes) -> bytes:
    """Approximate the h2 response as HTTP/2 text for display."""
    lines = [f"HTTP/2 {status if status is not None else '?'}"]
    for k, v in headers:
        kk = k.decode("latin-1") if isinstance(k, bytes) else k
        vv = v.decode("latin-1") if isinstance(v, bytes) else v
        if kk == ":status":
            continue
        lines.append(f"{kk}: {vv}")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "replace")
    return head + body


def tools_host_header(headers: list[tuple[str, str]]) -> str:
    for k, v in headers:
        if k.lower() == "host":
            return v
    return ""


_H2_FORBIDDEN = {
    "host", "connection", "keep-alive", "proxy-connection",
    "transfer-encoding", "upgrade", "content-length",
}


def _as_bytes(x) -> bytes:
    return x if isinstance(x, (bytes, bytearray)) else str(x).encode("latin-1", "replace")


def _h2_headers(method, path, authority, headers, malformed):
    """Build the h2 pseudo + regular header list.

    malformed=False: connection-specific headers are dropped, names lowercased.
    malformed=True: untouched except Host->:authority; \\r \\n \\t \\0 \\xHH
      \\\\ escapes INSIDE VALUES are turned into real bytes (CRLF injection).
    """
    pseudo = [(":method", method), (":path", path),
              (":scheme", "https"), (":authority", authority)]
    if malformed:
        reg = [(k, _decode_escapes(v)) for k, v in headers if k.lower() != "host"]
    else:
        reg = [(k.lower(), v) for k, v in headers if k.lower() not in _H2_FORBIDDEN]
    return pseudo, reg


def _render_h2_from_parts(pseudo: list, reg: list, body: bytes) -> bytes:
    """Render the pseudo + regular headers and body that enter the frame as raw bytes.

    reg values may be bytes (raw CRLF etc. from escape decoding in malformed mode);
    these bytes are written inline as-is so they appear in the hex dump.
    """
    out = bytearray()
    for k, v in pseudo:
        out += _as_bytes(k) + b": " + _as_bytes(v) + b"\r\n"
    for k, v in reg:
        out += _as_bytes(k) + b": " + _as_bytes(v) + b"\r\n"
    out += b"\r\n"
    out += body or b""
    return bytes(out)


def h2_send(
    *,
    host: str,
    port: int,
    requests: list[dict],
    timeout: float = 15.0,
    read_idle: float = 3.0,
    sni: Optional[str] = None,
    malformed: bool = False,
) -> dict:
    """Send HTTP/2 request(s) over a single TLS connection (ALPN h2).

    requests: [{method, path, headers, body, authority}] — each a separate stream.
    Responses are collected and converted to the same result shape as send_raw
    (a requests list).

    malformed=False (Layer 1): valid request — connection-specific headers (host,
      content-length, transfer-encoding, connection, ...) are dropped, names
      lowercased, h2 outbound validation on.
    malformed=True (h2 smuggling): h2 outbound validation/normalization OFF;
      normally-forbidden headers (content-length, transfer-encoding, ...) go into the
      frame exactly as written in the raw request. Only Host -> :authority is mapped;
      other headers (name/value) are untouched.
    """
    import h2.config
    import h2.connection
    import h2.events

    result: dict = {"requests": [], "error": None, "tls": True, "malformed": malformed}
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"])
        server_hostname = sni if sni else host
        try:
            tsock = ctx.wrap_socket(sock, server_hostname=server_hostname)
        except (ValueError, ssl.SSLError):
            tsock = ctx.wrap_socket(sock, server_hostname=None)
        result["tls_version"] = tsock.version()
    except OSError as exc:
        result["error"] = f"Connection error: {type(exc).__name__}: {exc}"
        return result

    if tsock.selected_alpn_protocol() != "h2":
        try:
            tsock.close()
        except Exception:
            pass
        result["error"] = "Server does not support HTTP/2 (ALPN h2)"
        return result

    try:
        if malformed:
            cfg = h2.config.H2Configuration(
                client_side=True,
                validate_outbound_headers=False,
                normalize_outbound_headers=False,
                split_outbound_cookies=False,
            )
        else:
            cfg = h2.config.H2Configuration(client_side=True)
        conn = h2.connection.H2Connection(config=cfg)
        conn.initiate_connection()
        tsock.sendall(conn.data_to_send())

        started = time.time()
        meta: list[dict] = []   # {sid, index, sent}
        for i, rq in enumerate(requests):
            body = rq["body"] or b""
            pseudo, reg = _h2_headers(
                rq["method"], rq["path"], rq.get("authority") or host,
                rq["headers"], malformed,
            )
            sid = conn.get_next_available_stream_id()
            conn.send_headers(sid, pseudo + reg, end_stream=(not body))
            if body:
                # Flow control is simple: typical request bodies fit the window.
                conn.send_data(sid, body, end_stream=True)
            meta.append({
                "sid": sid, "index": i,
                "sent": _render_h2_from_parts(pseudo, reg, body),
            })
        tsock.sendall(conn.data_to_send())

        acc = {m["sid"]: {"status": None, "headers": [], "body": b""} for m in meta}
        ended: set[int] = set()
        deadline = time.time() + timeout
        while len(ended) < len(meta):
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            tsock.settimeout(min(read_idle, remaining))
            try:
                data = tsock.recv(65536)
            except (socket.timeout, TimeoutError):
                continue
            if not data:
                break
            for ev in conn.receive_data(data):
                if isinstance(ev, h2.events.ResponseReceived):
                    acc[ev.stream_id]["headers"] = ev.headers
                    for k, v in ev.headers:
                        kk = k.decode("latin-1") if isinstance(k, bytes) else k
                        if kk == ":status":
                            vv = v.decode("latin-1") if isinstance(v, bytes) else v
                            try:
                                acc[ev.stream_id]["status"] = int(vv)
                            except ValueError:
                                pass
                elif isinstance(ev, h2.events.DataReceived):
                    acc[ev.stream_id]["body"] += ev.data
                    conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                elif isinstance(ev, h2.events.StreamEnded):
                    ended.add(ev.stream_id)
            out = conn.data_to_send()
            if out:
                tsock.sendall(out)

        elapsed = (time.time() - started) * 1000.0
        for m in meta:
            a = acc[m["sid"]]
            full = _reconstruct_h2_response(a["status"], a["headers"], a["body"])
            result["requests"].append({
                "index": m["index"],
                "sent_size": len(m["sent"]),
                "sent_base64": base64.b64encode(m["sent"]).decode("ascii"),
                "response_base64": base64.b64encode(full[:RACE_BODY_CAP]).decode("ascii"),
                "response_size": len(full),
                "duration_ms": elapsed,
                "send_error": None,
                "recv_error": None if a["status"] is not None else "no response received",
            })
        return result
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result
    finally:
        try:
            tsock.close()
        except Exception:
            pass


def _h2_smuggle_round(host, port, smuggle, followup, delay, timeout, read_idle, sni) -> dict:
    """One h2 connection: the smuggle stream first, then the follow-up stream.

    Because it is the same connection, the smuggled prefix left on the back-end can
    stick in front of the follow-up request. The follow-up stream's response is
    collected and returned.
    """
    import h2.config
    import h2.connection
    import h2.events

    out: dict = {"conn_error": None, "tls_version": None, "followup": None}
    tsock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"])
        try:
            tsock = ctx.wrap_socket(sock, server_hostname=(sni if sni else host))
        except (ValueError, ssl.SSLError):
            tsock = ctx.wrap_socket(sock, server_hostname=None)
        out["tls_version"] = tsock.version()
    except OSError as exc:
        out["conn_error"] = f"Connection error: {type(exc).__name__}: {exc}"
        return out

    if tsock.selected_alpn_protocol() != "h2":
        try:
            tsock.close()
        except Exception:
            pass
        out["conn_error"] = "Server does not support HTTP/2 (ALPN h2)"
        return out

    try:
        # Validation/normalization OFF: let the malformed smuggle through (follow-up is valid).
        conn = h2.connection.H2Connection(config=h2.config.H2Configuration(
            client_side=True, validate_outbound_headers=False,
            normalize_outbound_headers=False, split_outbound_cookies=False))
        conn.initiate_connection()
        tsock.sendall(conn.data_to_send())

        # 1) Smuggle stream (malformed) — the first stream on the same connection.
        sbody = smuggle["body"] or b""
        ps, rs = _h2_headers(smuggle["method"], smuggle["path"],
                             smuggle.get("authority") or host, smuggle["headers"], True)
        s_sid = conn.get_next_available_stream_id()
        conn.send_headers(s_sid, ps + rs, end_stream=(not sbody))
        if sbody:
            conn.send_data(s_sid, sbody, end_stream=True)
        tsock.sendall(conn.data_to_send())

        if delay:
            time.sleep(delay)

        # 2) Follow-up stream (valid) — right after, on the SAME connection.
        fbody = followup["body"] or b""
        pf, rf = _h2_headers(followup["method"], followup["path"],
                             followup.get("authority") or host, followup["headers"], False)
        f_sid = conn.get_next_available_stream_id()
        conn.send_headers(f_sid, pf + rf, end_stream=(not fbody))
        if fbody:
            conn.send_data(f_sid, fbody, end_stream=True)
        tsock.sendall(conn.data_to_send())
        f_sent = _render_h2_from_parts(pf, rf, fbody)

        # Read the follow-up stream's response (the smuggle stream may RST/GOAWAY, ignore it).
        acc = {"status": None, "headers": [], "body": b""}
        started = time.time()
        deadline = started + timeout
        done = False
        while not done:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            tsock.settimeout(min(read_idle, remaining))
            try:
                data = tsock.recv(65536)
            except (socket.timeout, TimeoutError):
                continue
            if not data:
                break
            try:
                events = conn.receive_data(data)
            except Exception:
                break
            for ev in events:
                sidv = getattr(ev, "stream_id", None)
                if isinstance(ev, h2.events.ResponseReceived) and sidv == f_sid:
                    acc["headers"] = ev.headers
                    for k, v in ev.headers:
                        kk = k.decode("latin-1") if isinstance(k, bytes) else k
                        if kk == ":status":
                            vv = v.decode("latin-1") if isinstance(v, bytes) else v
                            try:
                                acc["status"] = int(vv)
                            except ValueError:
                                pass
                elif isinstance(ev, h2.events.DataReceived) and sidv == f_sid:
                    acc["body"] += ev.data
                    conn.acknowledge_received_data(ev.flow_controlled_length, sidv)
                elif isinstance(ev, h2.events.StreamEnded) and sidv == f_sid:
                    done = True
                elif isinstance(ev, h2.events.ConnectionTerminated):
                    done = True
            outb = conn.data_to_send()
            if outb:
                tsock.sendall(outb)

        full = _reconstruct_h2_response(acc["status"], acc["headers"], acc["body"])
        out["followup"] = {
            "sent_size": len(f_sent),
            "sent_base64": base64.b64encode(f_sent).decode("ascii"),
            "response_base64": base64.b64encode(full[:RACE_BODY_CAP]).decode("ascii"),
            "response_size": len(full),
            "duration_ms": (time.time() - started) * 1000.0,
            "send_error": None,
            "recv_error": None if acc["status"] is not None else "no follow-up response received",
        }
        return out
    except Exception as exc:
        out["conn_error"] = f"{type(exc).__name__}: {exc}"
        return out
    finally:
        try:
            tsock.close()
        except Exception:
            pass


def h2_smuggle_followup(
    *,
    host: str,
    port: int,
    smuggle: dict,
    followup: dict,
    rounds: int = 1,
    delay_ms: int = 0,
    timeout: float = 10.0,
    read_idle: float = 3.0,
    sni: Optional[str] = None,
) -> dict:
    """h2 smuggle + follow-up request — consecutive streams on the SAME connection.

    Each round opens a NEW h2 connection (so the prefix does not accumulate): the
    smuggle stream first (malformed; leaves a smuggled prefix on the back-end via
    TE/CRLF), then the follow-up stream on the same connection. The follow-up
    response is shown — the smuggled prefix is reflected here.
    """
    result: dict = {"requests": [], "error": None, "tls": True, "smuggle": True}
    rounds = max(1, min(int(rounds), 100))
    delay = max(0, min(int(delay_ms), 500)) / 1000.0

    # Sent view of the smuggle request (same every round; show it once).
    ps, rs = _h2_headers(smuggle["method"], smuggle["path"],
                         smuggle.get("authority") or host, smuggle["headers"], True)
    smuggle_sent = _render_h2_from_parts(ps, rs, smuggle["body"] or b"")
    result["requests"].append({
        "index": 0,
        "label": "smuggle (h2 malformed — first stream on the SAME connection as the follow-up each round)",
        "sent_size": len(smuggle_sent),
        "sent_base64": base64.b64encode(smuggle_sent).decode("ascii"),
        "response_base64": "",
        "response_size": 0,
        "duration_ms": 0.0,
        "send_error": None,
        "recv_error": None,
    })

    idx = 1
    for rnd in range(rounds):
        rr = _h2_smuggle_round(host, port, smuggle, followup, delay, timeout, read_idle, sni)
        if rr.get("tls_version") and not result.get("tls_version"):
            result["tls_version"] = rr["tls_version"]
        if rr.get("conn_error"):
            result["requests"].append({
                "index": idx, "label": f"follow-up #{rnd + 1}",
                "sent_size": 0, "sent_base64": "", "response_base64": "",
                "response_size": 0, "duration_ms": 0.0,
                "send_error": None, "recv_error": rr["conn_error"],
            })
        else:
            e = dict(rr["followup"])
            e["index"] = idx
            e["label"] = f"follow-up #{rnd + 1}"
            result["requests"].append(e)
        idx += 1

    return result
