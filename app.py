#!/usr/bin/env python3
"""Blackwall masaüstü giriş noktası.

Tek komutla (ya da çift tıklamayla) çalışır:

    .venv/bin/python app.py

Şunları birlikte ayağa kaldırır:
  * mitmproxy (mitmdump) — proxy, varsayılan 127.0.0.1:8080
  * FastAPI + web UI (uvicorn) — varsayılan 127.0.0.1:8000, arka plan thread'inde
  * PyWebView penceresi — web UI'ı kendi masaüstü penceresinde açar

Pencere kapanınca proxy ve web sunucusu temiz şekilde kapatılır.

Ortam değişkenleri (opsiyonel):
  PROXY_PORT (8080), WEB_PORT (8000), BLACKWALL_DB (proje kökü/blackwall.db)
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PROXY_PORT = int(os.environ.get("PROXY_PORT", "8080"))
WEB_PORT = int(os.environ.get("WEB_PORT", "8000"))
WEB_HOST = "127.0.0.1"

# Alt süreçlerin ve addon'un aynı veritabanını kullanması için sabitle.
os.environ.setdefault("BLACKWALL_DB", str(ROOT / "blackwall.db"))
# Web süreci "Tarayıcı Aç"ta doğru proxy portunu bilsin.
os.environ["PROXY_PORT"] = str(PROXY_PORT)

# Proje kökü import yolunda olsun (addon ve web modülleri için).
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _venv_bin(name: str) -> str:
    """Çalışmakta olan yorumlayıcının yanındaki aracı bul (venv/bin/<name>)."""
    # .resolve() KULLANMA: venv/bin/python çoğu zaman sistem python'una sembolik
    # link; resolve edersek venv dışına çıkar ve mitmdump'ı bulamayız.
    cand = Path(sys.executable).parent / name
    return str(cand) if cand.exists() else name


def _port_open(host: str, port: int, timeout: float = 0.25) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0


def _wait_port(host: str, port: int, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _port_open(host, port):
            return True
        time.sleep(0.1)
    return False


def start_proxy() -> subprocess.Popen:
    """mitmdump'ı ayrı bir süreç olarak başlat (kendi asyncio döngüsü var)."""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    cmd = [
        _venv_bin("mitmdump"),
        "-s", str(ROOT / "blackwall" / "addon.py"),
        "--listen-host", "127.0.0.1",
        "--listen-port", str(PROXY_PORT),
    ]
    # Kendi oturum grubunda başlat ki temiz kapatabilelim.
    return subprocess.Popen(
        cmd,
        env=env,
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


class WebServer:
    """uvicorn'u arka plan thread'inde çalıştırır; temiz kapatma sağlar."""

    def __init__(self) -> None:
        import uvicorn

        from blackwall.web.app import app

        config = uvicorn.Config(
            app,
            host=WEB_HOST,
            port=WEB_PORT,
            log_level="warning",
            access_log=False,
        )
        self.server = uvicorn.Server(config)
        self.server.install_signal_handlers = lambda: None  # thread'de sinyal yok
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=5)


def main() -> int:
    import signal

    import webview

    proxy = start_proxy()
    web = WebServer()
    web.start()

    cleaned = threading.Event()

    def cleanup() -> None:
        if cleaned.is_set():
            return
        cleaned.set()
        # "Tarayıcı Aç" ile açılmış tarayıcıları kapat (web shutdown da yapar;
        # aynı süreçte olduğumuz için tekrar güvenli).
        try:
            from blackwall import browser
            browser.close_all()
        except Exception:
            pass
        try:
            if proxy.poll() is None:
                proxy.terminate()
                try:
                    proxy.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proxy.kill()
        except Exception:
            pass
        web.stop()

    if not _wait_port(WEB_HOST, WEB_PORT):
        print("Web sunucusu başlatılamadı.", file=sys.stderr)
        proxy.terminate()
        return 1

    proxy_ok = _wait_port("127.0.0.1", PROXY_PORT, timeout=10.0)
    if not proxy_ok:
        print(f"Uyarı: proxy {PROXY_PORT} portunda görünmüyor (yine de devam ediliyor).",
              file=sys.stderr)

    print(f"Proxy  : http://127.0.0.1:{PROXY_PORT}")
    print(f"Web UI : http://{WEB_HOST}:{WEB_PORT}")
    print(f"DB     : {os.environ['BLACKWALL_DB']}")

    window = webview.create_window(
        "Blackwall // Breach Protocol",
        url=f"http://{WEB_HOST}:{WEB_PORT}/",
        width=1400,
        height=900,
        min_size=(900, 600),
        background_color="#0a0a0a",  # yüklenirken beyaz parlama olmasın
    )

    window.events.closed += cleanup

    # Terminal'den Ctrl-C ya da SIGTERM gelirse de proxy'yi orphan bırakmadan kapat.
    def _on_signal(signum, frame) -> None:  # noqa: ANN001
        cleanup()
        os._exit(0)

    for _sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(_sig, _on_signal)
        except (ValueError, OSError):
            pass

    try:
        # Qt backend'i sabitle (GTK 'gi' modülü yoksa gürültülü traceback basmasın).
        webview.start(gui="qt")
    finally:
        cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
