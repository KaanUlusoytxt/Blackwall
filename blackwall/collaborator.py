"""Burp Collaborator (public oastify.com) OOB client — pure Python, no binary.

A second OOB backend that runs alongside the interactsh client in ``blackwall.oast``.
It speaks the public Burp Collaborator protocol, which is different from interactsh
and closed-source; the wire format here was ported from the clean-room, reverse-
engineered open-source reference "OAST Community" (MIT, Groppoxx/OAST-Community).

Protocol (public server, no self-hosting):
  * The client holds a locally generated 32-byte identifier (the "biid"); there is
    no server-side registration handshake. ``base64(biid)`` is sent when polling.
  * A per-client key hash is derived as sha1(biid) -> base36 -> fixed 22-char form.
  * Each payload host is ``{interaction_id}.oastify.com`` where interaction_id is a
    salted substitution encoding of ``{key_hash}1g{counter:x}yz``.
  * Polling: ``GET https://polling.oastify.com/burpresults?biid=<base64 biid>``
    returns plaintext JSON ``{"responses": [ {interaction}, ... ]}``; the server
    matches interactions to this client via the key hash embedded in the payload,
    so no client-side decryption is required for the public server. Each interaction
    is returned once (polling consumes it).

This module exposes an interface compatible with ``oast.InteractshClient`` so the
web layer can drive either backend: ``register``, ``new_url``, ``poll``,
``deregister`` and a ``correlation_id`` attribute, plus ``normalize_interaction``.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from datetime import datetime, timezone
from typing import Any

import httpx

ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"  # base36 (letters first, then digits)
DEFAULT_DOMAIN = "oastify.com"


class CollaboratorError(Exception):
    pass


# -- payload scheme (ported from the OAST-Community reference) ---------------
def base36_encode(number: int) -> str:
    if number < 0:
        raise ValueError("Number must be non-negative")
    if number == 0:
        return ALPHABET[0]
    out: list[str] = []
    while number:
        number, rem = divmod(number, 36)
        out.append(ALPHABET[rem])
    return "".join(reversed(out))


def _checksum_char(value: str) -> str:
    return ALPHABET[sum(ord(c) for c in value) % 36]


def derive_key_hash(raw_biid: bytes) -> str:
    """sha1(biid) -> base36, padded to 20, split into two checksummed halves."""
    digest = hashlib.sha1(raw_biid).digest()
    encoded = base36_encode(int.from_bytes(digest, "big", signed=False)).rjust(20, "a")
    key = encoded[:20]
    left, right = key[:10], key[10:20]
    return left + _checksum_char(left) + right + _checksum_char(right)


def encrypt_interaction_id(plaintext: str) -> str:
    """Salted, position-dependent substitution over ALPHABET (Collaborator scheme)."""
    salt_1 = secrets.choice(ALPHABET)
    salt_2 = secrets.choice(ALPHABET)
    state = [salt_1, salt_2]
    encrypted: list[str] = []
    for index, character in enumerate(plaintext):
        if character not in ALPHABET:
            raise ValueError(f"Unsupported payload character: {character!r}")
        register = index % 2
        cipher_index = (ALPHABET.index(character) + ALPHABET.index(state[register])) % 36
        cipher_character = ALPHABET[cipher_index]
        encrypted.append(cipher_character)
        state[register] = cipher_character
    salt_checksum = ALPHABET[(ord(salt_1) + ord(salt_2)) % 36]
    return salt_1 + salt_2 + salt_checksum + "".join(encrypted)


# -- interaction helpers -----------------------------------------------------
_DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA"}


def _dns_type_name(value: Any) -> str:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return str(value or "?")
    return _DNS_TYPES.get(number, f"TYPE{number}")


def _format_time(value: Any) -> str:
    """Collaborator timestamps are epoch milliseconds -> ISO-8601 (UTC, 'Z')."""
    try:
        dt = datetime.fromtimestamp(int(value) / 1000, tz=timezone.utc)
        return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except (TypeError, ValueError, OSError, OverflowError):
        return str(value or "")


def _decode_b64_text(value: Any) -> str:
    if not isinstance(value, str) or not value:
        return ""
    try:
        return base64.b64decode(value, validate=False).decode("utf-8", errors="replace")
    except Exception:
        return ""


def normalize_interaction(raw: dict[str, Any]) -> dict[str, Any]:
    """Flatten a Collaborator interaction into the shared OAST panel shape."""
    protocol = str(raw.get("protocol", "?")).lower()
    interaction_id = str(raw.get("interactionString", ""))
    data = raw.get("data")
    if not isinstance(data, dict):
        data = {}

    client = raw.get("client", "")
    port = raw.get("clientPort")
    remote = f"{client}:{port}" if port not in (None, "") else str(client or "")

    q_type = ""
    raw_request = ""
    raw_response = ""

    if protocol == "dns":
        q_type = _dns_type_name(data.get("type"))
        sub = data.get("subDomain") or interaction_id
        raw_request = f"Query : {sub}\nType  : {q_type}"
    elif protocol in ("http", "https"):
        raw_request = _decode_b64_text(data.get("request"))
        raw_response = _decode_b64_text(data.get("response"))
    elif protocol == "smtp":
        raw_request = str(data.get("conversation") or _decode_b64_text(data.get("request")) or "")
    else:
        raw_request = json.dumps(data, indent=2, ensure_ascii=False) if data else ""

    return {
        # full_id == the generated label, so the existing OAST attribution
        # (full_id endswith label) maps this interaction back to its payload.
        "protocol": protocol,
        "unique_id": interaction_id,
        "full_id": interaction_id,
        "q_type": q_type,
        "remote_address": remote,
        "timestamp": _format_time(raw.get("time")),
        "raw_request": raw_request,
        "raw_response": raw_response,
    }


# -- client ------------------------------------------------------------------
class CollaboratorClient:
    def __init__(self, server: str = DEFAULT_DOMAIN, token: str = "", poll_host: str = "") -> None:
        self.server = (server or DEFAULT_DOMAIN).strip().rstrip(".").lower() or DEFAULT_DOMAIN
        self.poll_host = (poll_host or f"polling.{self.server}").strip().rstrip(".").lower()
        self.token = (token or "").strip()  # unused on the public server; kept for parity
        self._raw_biid = os.urandom(32)
        self.biid = base64.b64encode(self._raw_biid).decode("ascii")
        self.key_hash = derive_key_hash(self._raw_biid)
        self.counter = 0
        # short, display-friendly id for the UI/status line
        self.correlation_id = self.key_hash

    def _headers(self) -> dict:
        h = {"Accept": "application/json", "Connection": "close"}
        if self.token:
            h["Authorization"] = self.token
        return h

    def _poll_raw(self, timeout: float) -> list[dict[str, Any]]:
        url = f"https://{self.poll_host}/burpresults"
        try:
            r = httpx.get(url, params={"biid": self.biid}, headers=self._headers(), timeout=timeout)
        except httpx.HTTPError as exc:
            raise CollaboratorError(f"Collaborator connection failed: {exc}")
        if r.status_code != 200:
            raise CollaboratorError(f"Poll error (HTTP {r.status_code}): {r.text[:200]}")
        if not r.text.strip():
            return []
        try:
            parsed = r.json()
        except json.JSONDecodeError:
            raise CollaboratorError("Unexpected Collaborator response (not JSON)")
        responses = parsed.get("responses") if isinstance(parsed, dict) else None
        if not isinstance(responses, list):
            return []
        return [item for item in responses if isinstance(item, dict)]

    # -- interface compatible with oast.InteractshClient --------------------
    def register(self, timeout: float = 15.0) -> None:
        # No registration handshake on the public server; the biid is local. One
        # poll surfaces connectivity/server errors at start time, like interactsh.
        self._poll_raw(timeout=timeout)

    def new_url(self) -> str:
        plaintext = f"{self.key_hash}1g{self.counter:x}yz"
        interaction_id = encrypt_interaction_id(plaintext)
        self.counter += 1
        return f"{interaction_id}.{self.server}"

    def poll(self, timeout: float = 20.0) -> list[dict[str, Any]]:
        return self._poll_raw(timeout=timeout)

    def deregister(self, timeout: float = 10.0) -> None:
        return  # nothing to deregister on the public server
