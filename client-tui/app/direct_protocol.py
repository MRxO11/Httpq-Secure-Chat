import json
from enum import Enum
from dataclasses import dataclass
from typing import Any


class DirectProtocolError(Exception):
    pass


class DirectEnvelopeAlgorithm(str, Enum):
    AUTHENTICATED_STATIC_BRIDGE = "x25519+hkdf+aes-256-gcm+ed25519"
    SESSION_CHAIN_BRIDGE = "pqxdh-bridge+hkdf+aes-256-gcm+ed25519"

    @classmethod
    def classify(cls, algorithm: str) -> "DirectEnvelopeAlgorithm | None":
        normalized = algorithm.strip()
        for candidate in cls:
            if candidate.value == normalized:
                return candidate
        return None

    @classmethod
    def uses_session_chain(cls, algorithm: str) -> bool:
        return cls.classify(algorithm) == cls.SESSION_CHAIN_BRIDGE


@dataclass(frozen=True)
class DirectEnvelope:
    version: int
    algorithm: str
    session_id: str
    sequence: int
    message_number: int
    sender_key_b64: str
    sender_ratchet_key_b64: str | None
    sender_signing_key_b64: str
    salt_b64: str
    nonce_b64: str
    ciphertext_b64: str
    signature_b64: str | None = None
    bootstrap_payload: dict[str, Any] | None = None

    def classified_algorithm(self) -> DirectEnvelopeAlgorithm | None:
        return DirectEnvelopeAlgorithm.classify(self.algorithm)

    def uses_session_chain(self) -> bool:
        return DirectEnvelopeAlgorithm.uses_session_chain(self.algorithm)

    def validate(self) -> None:
        if self.version <= 0:
            raise DirectProtocolError("direct envelope version must be non-zero")
        if not self.algorithm.strip():
            raise DirectProtocolError("direct envelope is missing algorithm")
        if not self.session_id.strip():
            raise DirectProtocolError("direct envelope is missing session id")
        if self.sequence <= 0:
            raise DirectProtocolError("direct envelope sequence must be positive")
        if self.message_number <= 0:
            raise DirectProtocolError("direct envelope message number must be positive")
        if not self.sender_key_b64.strip() or not self.sender_signing_key_b64.strip():
            raise DirectProtocolError("direct envelope is missing sender public keys")
        if self.sender_ratchet_key_b64 is not None and not self.sender_ratchet_key_b64.strip():
            raise DirectProtocolError("direct envelope sender ratchet key is empty")
        if not self.salt_b64.strip() or not self.nonce_b64.strip():
            raise DirectProtocolError("direct envelope is missing salt or nonce")
        if not self.ciphertext_b64.strip():
            raise DirectProtocolError("direct envelope is missing ciphertext")
        if self.signature_b64 is not None and not self.signature_b64.strip():
            raise DirectProtocolError("direct envelope signature is empty")

    def to_payload_dict(self, include_signature: bool = True) -> dict[str, Any]:
        self.validate()
        payload: dict[str, Any] = {
            "v": self.version,
            "alg": self.algorithm,
            "sessionId": self.session_id,
            "sequence": self.sequence,
            "messageNumber": self.message_number,
            "senderKey": self.sender_key_b64,
            "senderRatchetKey": self.sender_ratchet_key_b64,
            "senderSigningKey": self.sender_signing_key_b64,
            "salt": self.salt_b64,
            "nonce": self.nonce_b64,
            "ciphertext": self.ciphertext_b64,
        }
        if self.bootstrap_payload is not None:
            payload["bootstrap"] = self.bootstrap_payload
        if include_signature and self.signature_b64 is not None:
            payload["signature"] = self.signature_b64
        return payload

    def to_json(self) -> str:
        if self.signature_b64 is None:
            raise DirectProtocolError("direct envelope cannot be serialized without a signature")
        return json.dumps(self.to_payload_dict(include_signature=True), separators=(",", ":"))

    @classmethod
    def from_payload_dict(cls, payload: dict[str, Any]) -> "DirectEnvelope":
        try:
            envelope = cls(
                version=int(payload["v"]),
                algorithm=str(payload["alg"]),
                session_id=str(payload["sessionId"]),
                sequence=int(payload["sequence"]),
                message_number=int(payload.get("messageNumber", payload["sequence"])),
                sender_key_b64=str(payload["senderKey"]),
                sender_ratchet_key_b64=(
                    str(payload["senderRatchetKey"])
                    if payload.get("senderRatchetKey") is not None
                    else None
                ),
                sender_signing_key_b64=str(payload["senderSigningKey"]),
                salt_b64=str(payload["salt"]),
                nonce_b64=str(payload["nonce"]),
                ciphertext_b64=str(payload["ciphertext"]),
                signature_b64=(
                    str(payload["signature"]) if payload.get("signature") is not None else None
                ),
                bootstrap_payload=payload.get("bootstrap"),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise DirectProtocolError("invalid direct-message envelope") from exc
        envelope.validate()
        return envelope

    @classmethod
    def from_json(cls, payload: str) -> "DirectEnvelope":
        try:
            raw = json.loads(payload)
        except Exception as exc:
            raise DirectProtocolError("invalid direct-message envelope") from exc
        if not isinstance(raw, dict):
            raise DirectProtocolError("direct-message envelope must be an object")
        return cls.from_payload_dict(raw)
