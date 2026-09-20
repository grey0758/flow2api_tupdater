"""Signed, replay-resistant control messages for isolated login workers."""

import base64
import hashlib
import secrets
import time
from collections import deque
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


PROTOCOL_VERSION = "flow-login-worker-v1"
MAX_CLOCK_SKEW_SECONDS = 30


def _decode_key(value: str, size: int) -> bytes:
    try:
        raw = base64.urlsafe_b64decode(value.encode("ascii") + b"===")
    except Exception as exc:
        raise ValueError("invalid signing key") from exc
    if len(raw) != size:
        raise ValueError("invalid signing key size")
    return raw


def message(
    *, slot: int, generation: str, profile_id: int, timestamp: int,
    nonce: str, method: str, path: str, body: bytes = b"",
) -> bytes:
    digest = hashlib.sha256(body).hexdigest()
    return "\n".join([
        PROTOCOL_VERSION,
        str(slot),
        generation,
        str(profile_id),
        str(timestamp),
        nonce,
        method.upper(),
        path,
        digest,
    ]).encode("utf-8")


def sign_headers(
    private_key_b64: str, *, slot: int, generation: str, profile_id: int,
    method: str, path: str, body: bytes = b"", now: int | None = None,
) -> dict[str, str]:
    timestamp = int(time.time() if now is None else now)
    nonce = secrets.token_urlsafe(24)
    payload = message(
        slot=slot, generation=generation, profile_id=profile_id,
        timestamp=timestamp, nonce=nonce, method=method, path=path, body=body,
    )
    private_key = Ed25519PrivateKey.from_private_bytes(_decode_key(private_key_b64, 32))
    signature = base64.urlsafe_b64encode(private_key.sign(payload)).decode("ascii").rstrip("=")
    return {
        "X-Login-Slot": str(slot),
        "X-Login-Generation": generation,
        "X-Login-Profile": str(profile_id),
        "X-Login-Timestamp": str(timestamp),
        "X-Login-Nonce": nonce,
        "X-Login-Signature": signature,
    }


@dataclass
class ReplayGuard:
    public_key_b64: str
    slot: int
    limit: int = 512
    seen: set[str] = field(default_factory=set)
    order: deque[str] = field(default_factory=deque)

    def verify(self, headers, *, method: str, path: str, body: bytes = b"", now: int | None = None) -> tuple[str, int]:
        try:
            slot = int(headers["X-Login-Slot"])
            generation = str(headers["X-Login-Generation"])
            profile_id = int(headers["X-Login-Profile"])
            timestamp = int(headers["X-Login-Timestamp"])
            nonce = str(headers["X-Login-Nonce"])
            signature = _decode_key(str(headers["X-Login-Signature"]), 64)
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("missing or invalid control signature") from exc
        current = int(time.time() if now is None else now)
        if slot != self.slot or abs(current - timestamp) > MAX_CLOCK_SKEW_SECONDS:
            raise ValueError("control signature is outside its scope")
        if not generation or len(generation) > 128 or not nonce or len(nonce) > 128:
            raise ValueError("invalid control scope")
        if nonce in self.seen:
            raise ValueError("replayed control request")
        payload = message(
            slot=slot, generation=generation, profile_id=profile_id,
            timestamp=timestamp, nonce=nonce, method=method, path=path, body=body,
        )
        public_key = Ed25519PublicKey.from_public_bytes(_decode_key(self.public_key_b64, 32))
        try:
            public_key.verify(signature, payload)
        except Exception as exc:
            raise ValueError("invalid control signature") from exc
        self.seen.add(nonce)
        self.order.append(nonce)
        while len(self.order) > self.limit:
            self.seen.discard(self.order.popleft())
        return generation, profile_id
