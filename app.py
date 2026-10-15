#!/usr/bin/env python3
"""Blackwall desktop entry point.

Runs with a single command (or a double-click):

    .venv/bin/python app.py

Brings these up together:
  * mitmproxy (mitmdump) — proxy, default 127.0.0.1:8080
  * FastAPI + web UI (uvicorn) — default 127.0.0.1:8000, in a background thread
  * PyWebView window — opens the web UI in its own desktop window

When the window closes, the proxy and web server are shut down cleanly.

Environment variables (optional):
  PROXY_PORT (8080), WEB_PORT (8000), BLACKWALL_DB (project root/blackwall.db)
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

# Pin the DB path so child processes and the addon all use the same database.
os.environ.setdefault("BLACKWALL_DB", str(ROOT / "blackwall.db"))
# Let the web process know the correct proxy port for "Open Browser".
os.environ["PROXY_PORT"] = str(PROXY_PORT)

# Make sure the project root is on the import path (for the addon and web modules).
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _venv_bin(name: str) -> str:
    """Find a tool next to the running interpreter (venv/bin/<name>)."""
    # Do NOT use .resolve(): venv/bin/python is often a symlink to the system
    # python; resolving it would leave the venv and we would not find mitmdump.
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
    """Start mitmdump as a separate process (it has its own asyncio loop)."""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    cmd = [
        _venv_bin("mitmdump"),
        "-s", str(ROOT / "blackwall" / "addon.py"),
        "--listen-host", "127.0.0.1",
        "--listen-port", str(PROXY_PORT),
    ]
    # Start it in its own session group so we can shut it down cleanly.
    return subprocess.Popen(
        cmd,
        env=env,
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


class WebServer:
    """Run uvicorn in a background thread; provides clean shutdown."""

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
        self.server.install_signal_handlers = lambda: None  # no signals in a thread
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
        # Close browsers opened via "Open Browser" (the web shutdown also does this;
        # safe to repeat since we are in the same process).
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
        print("Failed to start the web server.", file=sys.stderr)
        proxy.terminate()
        return 1

    proxy_ok = _wait_port("127.0.0.1", PROXY_PORT, timeout=10.0)
    if not proxy_ok:
        print(f"Warning: proxy not visible on port {PROXY_PORT} (continuing anyway).",
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
        background_color="#0a0a0a",  # avoid a white flash while loading
    )

    window.events.closed += cleanup

    # If Ctrl-C or SIGTERM arrives from the terminal, close the proxy without orphaning it.
    def _on_signal(signum, frame) -> None:  # noqa: ANN001
        cleanup()
        os._exit(0)

    for _sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(_sig, _on_signal)
        except (ValueError, OSError):
            pass

    try:
        # Pin the Qt backend (avoid a noisy traceback when the GTK 'gi' module is missing).
        webview.start(gui="qt")
    finally:
        cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
