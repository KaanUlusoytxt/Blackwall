"""interactsh (OAST) client — pure Python, no external binary.

Out-of-band Application Security Testing: used to capture externally triggered
DNS/HTTP requests for vulnerabilities that do not return a direct response, such
as SSRF, blind injection, and XXE.

Protocol (ProjectDiscovery interactsh):
  1. The client generates an RSA-2048 key pair.
  2. POST /register registers the public key + secret + correlation-id.
  3. The generated subdomain = correlationID(20) + nonce(13) + "." + server.
  4. GET /poll?id=<corr>&secret=<secret> fetches interactions. The aes_key in the
     response is decrypted with RSA-OAEP(SHA256); each data item is base64 -> (IV|ct)
     decrypted with AES-256-CTR (IV = initial counter block) -> interaction JSON.
  5. POST /deregister removes the registration.
"""
from __future__ import annotations

import base64
import json
import secrets
import string
import uuid
from typing import Any, Optional

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_ALPHABET = string.ascii_lowercase + string.digits
CORRELATION_ID_LEN = 20   # interactsh constant
NONCE_LEN = 13            # interactsh constant (total prefix = 33)


def _rand(n: int) -> str:
    # First character must be a letter (DNS label safety), the rest alphanumeric.
    first = secrets.choice(string.ascii_lowercase)
    return first + "".join(secrets.choice(_ALPHABET) for _ in range(n - 1))


class InteractshError(Exception):
    pass


class InteractshClient:
    def __init__(self, server: str = "oast.pro", token: str = "") -> None:
        self.server = server.strip().rstrip("/")
        self.token = token.strip()
        self.correlation_id = _rand(CORRELATION_ID_LEN)
        self.secret = str(uuid.uuid4())
        self.registered = False

        self._priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_pem = self._priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.pub_key_b64 = base64.b64encode(pub_pem).decode("ascii")

    # -- HTTP helpers -------------------------------------------------------
    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.token:
            h["Authorization"] = self.token
        return h

    def _base(self) -> str:
        return f"https://{self.server}"

    # -- Protocol -----------------------------------------------------------
    def register(self, timeout: float = 15.0) -> None:
        body = {
            "public-key": self.pub_key_b64,
            "secret-key": self.secret,
            "correlation-id": self.correlation_id,
        }
        try:
            r = httpx.post(
                f"{self._base()}/register",
                json=body,
                headers=self._headers(),
                timeout=timeout,
            )
        except httpx.HTTPError as exc:
            raise InteractshError(f"Registration connection failed: {exc}")
        if r.status_code != 200:
            raise InteractshError(f"Registration rejected (HTTP {r.status_code}): {r.text[:200]}")
        self.registered = True

    def new_url(self) -> str:
        """Generate a new subdomain under the same registration (same poll)."""
        return f"{self.correlation_id}{_rand(NONCE_LEN)}.{self.server}"

    def deregister(self, timeout: float = 10.0) -> None:
        if not self.registered:
            return
        body = {"correlation-id": self.correlation_id, "secret-key": self.secret}
        try:
            httpx.post(
                f"{self._base()}/deregister",
                json=body,
                headers=self._headers(),
                timeout=timeout,
            )
        except httpx.HTTPError:
            pass
        finally:
            self.registered = False

    def poll(self, timeout: float = 20.0) -> list[dict[str, Any]]:
        """Fetch pending interactions, decrypt them, and return a list of dicts."""
        try:
            r = httpx.get(
                f"{self._base()}/poll",
                params={"id": self.correlation_id, "secret": self.secret},
                headers=self._headers(),
                timeout=timeout,
            )
        except httpx.HTTPError as exc:
            raise InteractshError(f"Poll connection failed: {exc}")
        if r.status_code != 200:
            raise InteractshError(f"Poll error (HTTP {r.status_code}): {r.text[:200]}")

        payload = r.json()
        data = payload.get("data") or []
        if not data:
            return []

        aes_key_b64 = payload.get("aes_key")
        if not aes_key_b64:
            raise InteractshError("No aes_key in poll response")
        aes_key = self._decrypt_aes_key(aes_key_b64)

        out: list[dict[str, Any]] = []
        for item in data:
            try:
                raw = self._aes_decrypt(aes_key, base64.b64decode(item))
                out.append(json.loads(raw))
            except Exception as exc:  # one bad record should not drop the whole poll
                out.append({"protocol": "error", "raw-request": f"decrypt error: {exc}"})
        return out

    # -- Kripto -------------------------------------------------------------
    def _decrypt_aes_key(self, aes_key_b64: str) -> bytes:
        encrypted = base64.b64decode(aes_key_b64)
        return self._priv.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    @staticmethod
    def _aes_decrypt(key: bytes, blob: bytes) -> bytes:
        # interactsh: first 16 bytes are the counter (IV), the rest is AES-256-CTR ciphertext.
        iv, ct = blob[:16], blob[16:]
        dec = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
        return dec.update(ct) + dec.finalize()


def normalize_interaction(raw: dict[str, Any]) -> dict[str, Any]:
    """Flatten interactsh fields (hyphenated) for the UI."""
    return {
        "protocol": raw.get("protocol", "?"),
        "unique_id": raw.get("unique-id", ""),
        "full_id": raw.get("full-id", ""),
        "q_type": raw.get("q-type", ""),
        "remote_address": raw.get("remote-address", ""),
        "timestamp": raw.get("timestamp", ""),
        "raw_request": raw.get("raw-request", ""),
        "raw_response": raw.get("raw-response", ""),
    }
