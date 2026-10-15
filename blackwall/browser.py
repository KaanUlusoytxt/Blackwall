"""Launch a Chromium/Chrome pre-configured with the proxy, in its own throwaway profile.

Equivalent to Burp's "Open Browser" feature:
  * `--proxy-server=127.0.0.1:8080` routes all traffic through the Blackwall proxy.
  * `--user-data-dir=<temp>` leaves the user's normal browser profile untouched.
  * The mitmproxy CA certificate is loaded into this throwaway profile (an isolated
    NSS DB), so the user can browse HTTPS sites with no setup and the traffic shows
    up in History. If certutil or the CA is missing, it falls back to
    `--ignore-certificate-errors`.

Launched processes are tracked; `close_all()` (on app shutdown) closes them all
and deletes the temporary profiles.
"""
from __future__ import annotations

import atexit
import os
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path

# Browser binaries to look for (Chromium-based). The first one found is used.
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
    """No Chromium/Chrome found on the system."""


def find_browser() -> str | None:
    """Return the path of the first Chromium-based browser found on PATH."""
    for name in _CANDIDATES:
        path = shutil.which(name)
        if path:
            return path
    return None


def _mitm_ca() -> Path | None:
    """Find mitmproxy's PEM CA certificate (created once the proxy has run)."""
    ca = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    return ca if ca.exists() else None


def _install_ca(profile_dir: Path, ca_path: Path | None) -> bool:
    """Install the CA into the profile's isolated NSS DB.

    Chromium (Linux) reads its certificate store from `$HOME/.pki/nssdb`. Since we
    launch the browser with HOME=profile_dir, we install the DB under
    profile_dir/.pki/nssdb — the user's real NSS store is never touched.
    """
    certutil = shutil.which("certutil")
    if not certutil or ca_path is None:
        return False
    nssdb = profile_dir / ".pki" / "nssdb"
    nssdb.mkdir(parents=True, exist_ok=True)
    db = f"sql:{nssdb}"
    try:
        # New DB with empty password (-N errors if it already exists, so ignore).
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
    """Launch a browser pre-configured with the proxy and a throwaway profile.

    Returns: {browser, pid, cert_method, ca_found, profile}
    Raises BrowserNotFound if no browser is available.
    """
    binary = find_browser()
    if not binary:
        raise BrowserNotFound(
            "No Chromium/Chrome found on the system. "
            "Please install chromium or google-chrome."
        )

    profile_dir = Path(tempfile.mkdtemp(prefix="blackwall-browser-"))
    user_data = profile_dir / "chrome"
    user_data.mkdir(parents=True, exist_ok=True)

    ca = _mitm_ca()
    cert_ok = _install_ca(profile_dir, ca)

    args = [
        binary,
        f"--proxy-server={proxy_host}:{proxy_port}",
        # route everything through the proxy including loopback (Burp behavior; localhost captured too).
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
        # The NSS DB is at profile_dir/.pki/nssdb; point HOME there.
        env["HOME"] = str(profile_dir)
    else:
        # CA could not be installed: ignore certificate errors (traffic still captured).
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
    """Close all launched browsers and delete the temporary profiles."""
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
