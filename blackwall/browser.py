"""Önceden proxy'ye ayarlı, kendi geçici profilinde bir Chromium/Chrome başlatır.

Burp'ün "Open Browser" özelliğinin karşılığı:
  * `--proxy-server=127.0.0.1:8080` ile tüm trafik Blackwall proxy'sinden geçer.
  * `--user-data-dir=<geçici>` ile kullanıcının normal tarayıcı profiline dokunulmaz.
  * mitmproxy CA sertifikası bu geçici profile (izole NSS DB) yüklenir; böylece
    kullanıcı hiçbir ayar yapmadan HTTPS sitelerini gezebilir ve trafik History'ye
    düşer. certutil ya da CA yoksa `--ignore-certificate-errors` fallback'ine düşülür.

Başlatılan süreçler kaydedilir; `close_all()` (uygulama kapanışında) hepsini
kapatır ve geçici profilleri siler.
"""
from __future__ import annotations

import atexit
import os
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path

# Aranacak tarayıcı ikilileri (Chromium tabanlı). İlk bulunan kullanılır.
_CANDIDATES = [
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "google-chrome-unstable",
    "chrome",
    "brave",
    "brave-browser",
    "microsoft-edge",
    "microsoft-edge-stable",
    "ungoogled-chromium",
    "thorium-browser",
    "vivaldi-stable",
    "vivaldi",
]

_procs: list[tuple[subprocess.Popen, Path]] = []
_lock = threading.Lock()


class BrowserNotFound(Exception):
    """Sistemde Chromium/Chrome bulunamadı."""


def find_browser() -> str | None:
    """PATH'te ilk bulunan Chromium tabanlı tarayıcının yolunu döndür."""
    for name in _CANDIDATES:
        path = shutil.which(name)
        if path:
            return path
    return None


def _mitm_ca() -> Path | None:
    """mitmproxy'nin PEM CA sertifikasını bul (proxy bir kez çalışınca oluşur)."""
    ca = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    return ca if ca.exists() else None


def _install_ca(profile_dir: Path, ca_path: Path | None) -> bool:
    """CA'yı profile ait izole NSS DB'sine yükle.

    Chromium (Linux) sertifika deposunu `$HOME/.pki/nssdb`'den okur. Tarayıcıyı
    HOME=profile_dir ile başlatacağımız için, DB'yi profile_dir/.pki/nssdb altına
    kurarız — kullanıcının gerçek NSS deposuna dokunmayız.
    """
    certutil = shutil.which("certutil")
    if not certutil or ca_path is None:
        return False
    nssdb = profile_dir / ".pki" / "nssdb"
    nssdb.mkdir(parents=True, exist_ok=True)
    db = f"sql:{nssdb}"
    try:
        # Boş parolalı yeni DB (zaten varsa -N hata verir, o yüzden yoksay).
        subprocess.run(
            [certutil, "-N", "--empty-password", "-d", db],
            check=False, capture_output=True,
        )
        res = subprocess.run(
            [certutil, "-A", "-n", "mitmproxy", "-t", "C,,", "-i", str(ca_path), "-d", db],
            check=False, capture_output=True,
        )
        return res.returncode == 0
    except OSError:
        return False


def open_browser(proxy_host: str = "127.0.0.1", proxy_port: int = 8080) -> dict:
    """Proxy'ye ayarlı, geçici profilli bir tarayıcı başlat.

    Döndürür: {browser, pid, cert_method, ca_found, profile}
    Tarayıcı yoksa BrowserNotFound yükseltir.
    """
    binary = find_browser()
    if not binary:
        raise BrowserNotFound(
            "Sistemde Chromium/Chrome bulunamadı. "
            "Lütfen chromium ya da google-chrome kurun."
        )

    profile_dir = Path(tempfile.mkdtemp(prefix="blackwall-browser-"))
    user_data = profile_dir / "chrome"
    user_data.mkdir(parents=True, exist_ok=True)

    ca = _mitm_ca()
    cert_ok = _install_ca(profile_dir, ca)

    args = [
        binary,
        f"--proxy-server={proxy_host}:{proxy_port}",
        # loopback dahil her şey proxy'den geçsin (Burp davranışı; localhost da yakalanır).
        "--proxy-bypass-list=<-loopback>",
        f"--user-data-dir={user_data}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-sync",
        "--disable-background-networking",
        "--no-service-autorun",
        "--password-store=basic",
    ]

    env = dict(os.environ)
    if cert_ok:
        # NSS DB'si profile_dir/.pki/nssdb'de; HOME'u oraya yönlendir.
        env["HOME"] = str(profile_dir)
    else:
        # CA kurulamadı: sertifika hatalarını yoksay (trafik yine yakalanır).
        args += ["--ignore-certificate-errors", "--test-type"]

    args.append("about:blank")

    proc = subprocess.Popen(
        args,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )

    with _lock:
        _procs.append((proc, profile_dir))

    return {
        "browser": binary,
        "pid": proc.pid,
        "cert_method": "nss" if cert_ok else "ignore",
        "ca_found": ca is not None,
        "profile": str(profile_dir),
    }


def close_all() -> None:
    """Başlatılan tüm tarayıcıları kapat ve geçici profilleri sil."""
    with _lock:
        procs = list(_procs)
        _procs.clear()
    for proc, profile_dir in procs:
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        except Exception:
            pass
        shutil.rmtree(profile_dir, ignore_errors=True)


atexit.register(close_all)
