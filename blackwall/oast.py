"""interactsh (OAST) istemcisi — saf Python, dış binary yok.

Out-of-band Application Security Testing: SSRF, kör (blind) enjeksiyon, XXE gibi
etkileşimleri doğrudan yanıt dönmeyen zafiyetlerde dışarıdan tetiklenen
DNS/HTTP isteklerini yakalamak için kullanılır.

Protokol (ProjectDiscovery interactsh):
  1. İstemci bir RSA-2048 anahtar çifti üretir.
  2. POST /register ile public key + secret + correlation-id kaydedilir.
  3. Üretilen subdomain = correlationID(20) + nonce(13) + "." + sunucu.
  4. GET /poll?id=<corr>&secret=<secret> ile etkileşimler çekilir. Yanıttaki
     aes_key RSA-OAEP(SHA256) ile çözülür; her data öğesi base64 → (IV|AES-CFB)
     olarak AES-256-CTR ile çözülür (IV = başlangıç sayaç bloğu) → etkileşim JSON'u.
  5. POST /deregister ile kayıt silinir.
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
CORRELATION_ID_LEN = 20   # interactsh sabiti
NONCE_LEN = 13            # interactsh sabiti (toplam prefix = 33)


def _rand(n: int) -> str:
    # İlk karakter harf olsun (DNS etiketi güvenliği), gerisi alfanümerik.
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

    # -- HTTP yardımcıları --------------------------------------------------
    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.token:
            h["Authorization"] = self.token
        return h

    def _base(self) -> str:
        return f"https://{self.server}"

    # -- Protokol -----------------------------------------------------------
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
            raise InteractshError(f"Kayıt bağlantısı başarısız: {exc}")
        if r.status_code != 200:
            raise InteractshError(f"Kayıt reddedildi (HTTP {r.status_code}): {r.text[:200]}")
        self.registered = True

    def new_url(self) -> str:
        """Aynı kayıt altında yeni bir subdomain üretir (aynı poll'a düşer)."""
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
        """Bekleyen etkileşimleri çeker, çözer ve dict listesi döndürür."""
        try:
            r = httpx.get(
                f"{self._base()}/poll",
                params={"id": self.correlation_id, "secret": self.secret},
                headers=self._headers(),
                timeout=timeout,
            )
        except httpx.HTTPError as exc:
            raise InteractshError(f"Poll bağlantısı başarısız: {exc}")
        if r.status_code != 200:
            raise InteractshError(f"Poll hatası (HTTP {r.status_code}): {r.text[:200]}")

        payload = r.json()
        data = payload.get("data") or []
        if not data:
            return []

        aes_key_b64 = payload.get("aes_key")
        if not aes_key_b64:
            raise InteractshError("Poll yanıtında aes_key yok")
        aes_key = self._decrypt_aes_key(aes_key_b64)

        out: list[dict[str, Any]] = []
        for item in data:
            try:
                raw = self._aes_decrypt(aes_key, base64.b64decode(item))
                out.append(json.loads(raw))
            except Exception as exc:  # tek bozuk kayıt tüm poll'u düşürmesin
                out.append({"protocol": "error", "raw-request": f"çözme hatası: {exc}"})
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
        # interactsh: ilk 16 bayt sayaç (IV), gerisi AES-256-CTR şifreli metin.
        iv, ct = blob[:16], blob[16:]
        dec = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
        return dec.update(ct) + dec.finalize()


def normalize_interaction(raw: dict[str, Any]) -> dict[str, Any]:
    """interactsh alanlarını (tireli) UI için sadeleştirir."""
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
