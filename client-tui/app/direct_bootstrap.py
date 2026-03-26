from dataclasses import dataclass
from typing import Any


class DirectBootstrapError(Exception):
    pass


@dataclass(frozen=True)
class PqxdhInitMessage:
    protocol: str
    sender_client_id: str
    receiver_client_id: str
    sender_encryption_identity_key: str
    sender_signing_identity_key: str
    sender_ephemeral_key_b64: str
    receiver_signed_prekey_id: int
    receiver_one_time_prekey_id: int | None
    receiver_pq_prekey_present: bool
    signature_b64: str

    def validate(self) -> None:
        if not self.protocol.strip():
            raise DirectBootstrapError("PQXDH init is missing protocol")
        if not self.sender_client_id.strip() or not self.receiver_client_id.strip():
            raise DirectBootstrapError("PQXDH init is missing sender or receiver client id")
        if (
            not self.sender_encryption_identity_key.strip()
            or not self.sender_signing_identity_key.strip()
        ):
            raise DirectBootstrapError("PQXDH init is missing sender identity keys")
        if not self.sender_ephemeral_key_b64.strip():
            raise DirectBootstrapError("PQXDH init is missing sender ephemeral key")
        if self.receiver_signed_prekey_id <= 0:
            raise DirectBootstrapError("PQXDH init is missing receiver signed prekey id")
        if not self.signature_b64.strip():
            raise DirectBootstrapError("PQXDH init is missing signature")

    def to_payload(self, *, include_signature: bool = True) -> dict[str, Any]:
        payload = {
            "type": "PqxdhInit",
            "protocol": self.protocol,
            "senderClientId": self.sender_client_id,
            "receiverClientId": self.receiver_client_id,
            "senderEncryptionIdentityKey": self.sender_encryption_identity_key,
            "senderSigningIdentityKey": self.sender_signing_identity_key,
            "senderEphemeralKey": self.sender_ephemeral_key_b64,
            "receiverSignedPrekeyId": self.receiver_signed_prekey_id,
            "receiverOneTimePrekeyId": self.receiver_one_time_prekey_id,
            "receiverPqPrekeyPresent": self.receiver_pq_prekey_present,
        }
        if include_signature:
            self.validate()
            payload["signature"] = self.signature_b64
        return payload

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "PqxdhInitMessage":
        message = cls(
            protocol=str(payload.get("protocol", "")),
            sender_client_id=str(payload.get("senderClientId", "")),
            receiver_client_id=str(payload.get("receiverClientId", "")),
            sender_encryption_identity_key=str(payload.get("senderEncryptionIdentityKey", "")),
            sender_signing_identity_key=str(payload.get("senderSigningIdentityKey", "")),
            sender_ephemeral_key_b64=str(payload.get("senderEphemeralKey", "")),
            receiver_signed_prekey_id=int(payload.get("receiverSignedPrekeyId", 0)),
            receiver_one_time_prekey_id=(
                int(payload["receiverOneTimePrekeyId"])
                if payload.get("receiverOneTimePrekeyId") is not None
                else None
            ),
            receiver_pq_prekey_present=bool(payload.get("receiverPqPrekeyPresent", False)),
            signature_b64=str(payload.get("signature", "")),
        )
        message.validate()
        return message


@dataclass(frozen=True)
class PqxdhInitAckMessage:
    protocol: str
    sender_client_id: str
    receiver_client_id: str
    session_id: str
    sender_encryption_identity_key: str
    sender_signing_identity_key: str
    sender_ephemeral_key_b64: str
    signature_b64: str

    def validate(self) -> None:
        if not self.protocol.strip():
            raise DirectBootstrapError("PQXDH init ack is missing protocol")
        if not self.sender_client_id.strip() or not self.receiver_client_id.strip():
            raise DirectBootstrapError("PQXDH init ack is missing sender or receiver client id")
        if not self.session_id.strip():
            raise DirectBootstrapError("PQXDH init ack is missing session id")
        if not self.sender_encryption_identity_key.strip() or not self.sender_signing_identity_key.strip():
            raise DirectBootstrapError("PQXDH init ack is missing sender identity keys")
        if not self.sender_ephemeral_key_b64.strip():
            raise DirectBootstrapError("PQXDH init ack is missing sender ephemeral key")
        if not self.signature_b64.strip():
            raise DirectBootstrapError("PQXDH init ack is missing signature")

    def to_payload(self, *, include_signature: bool = True) -> dict[str, Any]:
        payload = {
            "type": "PqxdhInitAck",
            "protocol": self.protocol,
            "senderClientId": self.sender_client_id,
            "receiverClientId": self.receiver_client_id,
            "sessionId": self.session_id,
            "senderEncryptionIdentityKey": self.sender_encryption_identity_key,
            "senderSigningIdentityKey": self.sender_signing_identity_key,
            "senderEphemeralKey": self.sender_ephemeral_key_b64,
        }
        if include_signature:
            self.validate()
            payload["signature"] = self.signature_b64
        return payload

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "PqxdhInitAckMessage":
        message = cls(
            protocol=str(payload.get("protocol", "")),
            sender_client_id=str(payload.get("senderClientId", "")),
            receiver_client_id=str(payload.get("receiverClientId", "")),
            session_id=str(payload.get("sessionId", "")),
            sender_encryption_identity_key=str(payload.get("senderEncryptionIdentityKey", "")),
            sender_signing_identity_key=str(payload.get("senderSigningIdentityKey", "")),
            sender_ephemeral_key_b64=str(payload.get("senderEphemeralKey", "")),
            signature_b64=str(payload.get("signature", "")),
        )
        message.validate()
        return message


BootstrapMessage = PqxdhInitMessage | PqxdhInitAckMessage


def parse_bootstrap_message(payload: Any) -> BootstrapMessage:
    if not isinstance(payload, dict):
        raise DirectBootstrapError("bootstrap payload must be an object")

    message_type = str(payload.get("type", "")).strip()
    if message_type == "PqxdhInit":
        return PqxdhInitMessage.from_payload(payload)
    if message_type == "PqxdhInitAck":
        return PqxdhInitAckMessage.from_payload(payload)
    raise DirectBootstrapError(f"unsupported bootstrap message type: {message_type or 'unknown'}")
