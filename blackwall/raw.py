"""Ham TCP/TLS istek göndericisi — request smuggling / desync araştırması için.

Tasarım ilkeleri:
  * SADECE stdlib socket + ssl. httpx/requests YOK.
  * Kullanıcının byte'larına dokunulmaz: Content-Length / Transfer-Encoding
    otomatik hesaplanmaz veya düzeltilmez, header sırası korunur, chunked gövde
    olduğu gibi gönderilir.
  * Tek bağlantıda (tek socket) arka arkaya birden çok istek gönderilebilir —
    CL.TE / TE.CL gibi desync testleri için şart.

Satır sonu modları (textarea'da literal CR yazılamadığı için):
  * crlf   — gerçek satır sonları CRLF'e çevrilir (normal istekler için).
  * lf     — gerçek satır sonları LF kalır (UTF-8).
  * escape — gerçek satır sonları yok sayılır; yalnızca \\r \\n \\t \\0 \\xHH \\\\
             escape'leri byte üretir; diğer karakterler UTF-8. Tam byte kontrolü.
"""
from __future__ import annotations

import base64
import socket
import ssl
import threading
import time
from collections import Counter
from typing import Optional

MAX_RACE = 255          # eşzamanlı bağlantı üst sınırı
RACE_BODY_CAP = 65536   # saklanan yanıt gövdesi üst sınırı (byte)


def _decode_escapes(text: str) -> bytes:
    out = bytearray()
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in ("\r", "\n"):
            # escape modunda gerçek satır sonları yalnızca görseldir, yok sayılır
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
            # bilinmeyen escape: ters taksimi aynen bırak
            out.append(0x5C)
            i += 1
            continue
        out.extend(c.encode("utf-8"))
        i += 1
    return bytes(out)


def encode_payload(text: str, mode: str) -> bytes:
    """Metni, satır sonu moduna göre ham byte'lara çevirir (başka değişiklik yok)."""
    if mode == "lf":
        return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
    if mode == "crlf":
        normalized = text.replace("\r\n", "\n").replace("\r", "\n")
        return normalized.replace("\n", "\r\n").encode("utf-8")
    if mode == "escape":
        return _decode_escapes(text)
    raise ValueError(f"bilinmeyen mod: {mode}")


def open_connection(
    host: str, port: int, use_tls: bool, timeout: float, sni: Optional[str] = None
) -> tuple[socket.socket, Optional[str]]:
    """Ham TCP (opsiyonel TLS) bağlantı açar. Hata OSError/SSLError olarak yükselir."""
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    tls_version: Optional[str] = None
    if use_tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # ALPN ayarlanmaz → sunucu HTTP/1.1 kullanır.
        server_hostname = sni if sni else host
        try:
            sock = ctx.wrap_socket(sock, server_hostname=server_hostname)
        except (ValueError, ssl.SSLError):
            sock = ctx.wrap_socket(sock, server_hostname=None)
        tls_version = sock.version()
    return sock, tls_version


def _recv_response(sock: socket.socket, total_timeout: float, read_idle: float) -> bytes:
    """Bağlantı kapanana, boşa çıkana (read_idle) ya da total_timeout dolana kadar okur."""
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
            break  # bir süredir veri yok → yanıt (şimdilik) tamam
        except ssl.SSLWantReadError:
            continue
        if not data:
            break  # karşı taraf kapattı
        chunks.append(data)
    return b"".join(chunks)


def _header_dict(block: bytes) -> dict[str, str]:
    """Yanıt başlık bloğunu (status satırı hariç) küçük harfli dict'e çevirir."""
    out: dict[str, str] = {}
    for line in block.split(b"\r\n")[1:]:
        if b":" not in line:
            continue
        k, _, v = line.partition(b":")
        out[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1")
    return out


def _chunked_end(data: bytes, start: int) -> Optional[int]:
    """chunked gövdenin bittiği indeksi döndürür (son 0-chunk + sonlandırıcı sonrası)."""
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
            # trailer'lar varsa boş satıra kadar tüket
            while i < n:
                le2 = data.find(b"\r\n", i)
                if le2 == -1:
                    return None
                if le2 == i:          # boş satır → chunked sonu
                    return i + 2
                i = le2 + 2
            return None
        i += size + 2                 # chunk verisi + ardından gelen \r\n
    return None


def split_http_responses(data: bytes) -> list[bytes]:
    """Tek socket'ten birbirine eklenmiş HTTP/1.1 yanıtlarını ayrı ayrı döndürür.

    Gövde uzunluğu Transfer-Encoding: chunked, yoksa Content-Length, o da yoksa
    EOF'a kadar (yalnızca son yanıt) kabul edilir.
    """
    responses: list[bytes] = []
    i, n = 0, len(data)
    while i < n:
        hdr_end = data.find(b"\r\n\r\n", i)
        if hdr_end == -1:
            responses.append(data[i:])        # eksik/ham kalan
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
                responses.append(data[i:]); break   # eksik gövde
            responses.append(data[i:end]); i = end
        else:
            responses.append(data[i:]); break        # CL/chunked yok → EOF'a kadar
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
    """Tek socket açar ve payload'ları gönderir.

    * Tek istek: gönder → yanıtı oku (mevcut davranış).
    * İki+ istek (smuggling): tüm istekler ilk yanıtı beklemeden art arda aynı
      sokete yazılır (pipeline), sonra gelen TÜM veri okunup yanıtlara ayrılır.
      Böylece `Connection: close` olsa bile ikinci yanıt (ör. 404) yakalanır.
    """
    result: dict = {"requests": [], "error": None, "tls": use_tls}
    sock: Optional[socket.socket] = None
    try:
        sock, tls_version = open_connection(host, port, use_tls, timeout, sni)
        if tls_version:
            result["tls_version"] = tls_version
    except OSError as exc:
        result["error"] = f"Bağlantı hatası: {type(exc).__name__}: {exc}"
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
    """Tek istek (ve genel sıralı) davranışı: gönder → yanıtı oku."""
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
    """Pipeline: tüm istekleri art arda yaz, sonra tüm veriyi oku ve yanıtlara ayır."""
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
    # Tüm payload'ları ilk yanıtı beklemeden art arda yaz.
    for i, payload in enumerate(payloads):
        if i > 0 and delay_ms > 0:
            time.sleep(delay_ms / 1000.0)
        try:
            sock.settimeout(timeout)
            sock.sendall(payload)
        except OSError as exc:
            entries[i]["send_error"] = f"{type(exc).__name__}: {exc}"
            break

    # Gelen TÜM veriyi oku (Connection: close ise EOF, değilse read_idle ile dur).
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

    # İstek sayısından fazla yanıt geldiyse (nadir) son isteğe ekle.
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
    """Last-byte synchronization ile race condition saldırısı.

    Her bağlantı isteğin SON baytı hariç tümünü gönderir, kısa bir süre bekler
    (sunucu prefix'i tamponlasın), sonra bir bariyerde buluşup son baytı aynı
    anda basar → istekler sunucuya ~eşzamanlı varır (HTTP/1.1).
    """
    if len(payload) < 1:
        return {"error": "boş istek gönderilemez", "results": [], "count": 0}
    count = max(2, min(count, MAX_RACE))
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
                barrier.abort()  # bekleyen diğer thread'leri serbest bırak
            except Exception:
                pass
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
            return

        # Senkronizasyon noktası: tüm bağlantılar hazır → son baytları birlikte bas
        try:
            barrier.wait(timeout=max(5.0, timeout))
        except threading.BrokenBarrierError:
            pass  # bir bağlantı düştü; yine de son baytı gönder

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
    # Race kazananı tespiti: en sık görülen (status, uzunluk) imzası "normal";
    # ondan farklı dönen satırlar ayırt edilir (distinct=True).
    sigs = Counter((r["status"], r["response_size"]) for r in final if r["error"] is None)
    majority = sigs.most_common(1)[0][0] if sigs else None
    for r in final:
        r["signature"] = f"{r['status']}·{r['response_size']}B"
        r["distinct"] = (
            r["error"] is None and majority is not None
            and (r["status"], r["response_size"]) != majority
        )
    # senkron kalitesi: son bayt gönderim zamanlarının yayılımı
    offsets = [r["sent_offset_ms"] for r in final if r["sent_offset_ms"] is not None]
    spread = (max(offsets) - min(offsets)) if len(offsets) >= 2 else 0.0
    return {
        "error": None,
        "results": final,
        "count": len(final),
        "majority": (f"{majority[0]}·{majority[1]}B" if majority else None),
        "sync_spread_ms": spread,
    }
