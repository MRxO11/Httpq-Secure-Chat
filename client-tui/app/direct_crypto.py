import base64
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

try:
    from .direct_math import (
        bootstrap_message_bytes,
        direct_message_bytes,
        peer_announcement_bytes,
    )
    from .direct_protocol import DirectEnvelope, DirectProtocolError
except ImportError:
    from direct_math import bootstrap_message_bytes, direct_message_bytes, peer_announcement_bytes
    from direct_protocol import DirectEnvelope, DirectProtocolError


class DirectCryptoError(Exception):
    pass


@dataclass
class DirectDecryptedMessage:
    sender_key_b64: str
    sender_ratchet_key_b64: str | None
    sender_signing_key_b64: str
    session_id: str
    sequence: int
    message_number: int
    bootstrap_message: dict | None
    plaintext: str


class DirectCipher:
    def __init__(self, encryption_private_key: X25519PrivateKey, signing_private_key: Ed25519PrivateKey) -> None:
        self.encryption_private_key = encryption_private_key
        self.encryption_public_key = encryption_private_key.public_key()
        self.signing_private_key = signing_private_key
        self.signing_public_key = signing_private_key.public_key()

    @property
    def encryption_public_key_b64(self) -> str:
        return base64.b64encode(
            self.encryption_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode("ascii")

    @property
    def signing_public_key_b64(self) -> str:
        return base64.b64encode(
            self.signing_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode("ascii")

    def sign_peer_announcement(self, *, client_id: str, username: str, room_id: str) -> str:
        message = peer_announcement_bytes(
            client_id=client_id,
            username=username,
            room_id=room_id,
            encryption_key_b64=self.encryption_public_key_b64,
            signing_key_b64=self.signing_public_key_b64,
        )
        signature = self.signing_private_key.sign(message)
        return base64.b64encode(signature).decode("ascii")

    def verify_peer_announcement(
        self,
        *,
        client_id: str,
        username: str,
        room_id: str,
        encryption_key_b64: str,
        signing_key_b64: str,
        signature_b64: str,
    ) -> None:
        signing_public_key = self._load_signing_public_key(signing_key_b64)
        try:
            signature = base64.b64decode(signature_b64)
        except Exception as exc:
            raise DirectCryptoError("invalid peer signature encoding") from exc

        message = peer_announcement_bytes(
            client_id=client_id,
            username=username,
            room_id=room_id,
            encryption_key_b64=encryption_key_b64,
            signing_key_b64=signing_key_b64,
        )
        try:
            signing_public_key.verify(signature, message)
        except Exception as exc:
            raise DirectCryptoError("peer announcement signature verification failed") from exc

    def generate_ephemeral_keypair(self) -> tuple[str, str]:
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return (
            base64.b64encode(private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode("ascii"),
            base64.b64encode(public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("ascii"),
        )

    def sign_bootstrap_payload(self, payload: dict) -> str:
        signature = self.signing_private_key.sign(bootstrap_message_bytes(payload=payload))
        return base64.b64encode(signature).decode("ascii")

    def verify_bootstrap_payload(self, *, payload: dict, signing_key_b64: str, signature_b64: str) -> None:
        signing_public_key = self._load_signing_public_key(signing_key_b64)
        try:
            signature = base64.b64decode(signature_b64)
        except Exception as exc:
            raise DirectCryptoError("invalid bootstrap signature encoding") from exc
        try:
            signing_public_key.verify(signature, bootstrap_message_bytes(payload=payload))
        except Exception as exc:
            raise DirectCryptoError("bootstrap signature verification failed") from exc

    def derive_bootstrap_secret_ref(
        self,
        *,
        local_ephemeral_private_key_b64: str,
        remote_ephemeral_public_key_b64: str,
        remote_static_public_key_b64: str,
    ) -> str:
        local_ephemeral_private_key = self._load_encryption_private_key(local_ephemeral_private_key_b64)
        remote_ephemeral_public_key = self._load_encryption_public_key(remote_ephemeral_public_key_b64)
        remote_static_public_key = self._load_encryption_public_key(remote_static_public_key_b64)

        dh1 = local_ephemeral_private_key.exchange(remote_ephemeral_public_key)
        dh2 = self.encryption_private_key.exchange(remote_ephemeral_public_key)
        dh3 = local_ephemeral_private_key.exchange(remote_static_public_key)
        combined = b"".join(sorted([dh1, dh2, dh3]))

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"secure-chat-pqxdh-bridge-v1",
        )
        secret = hkdf.derive(combined)
        return base64.b64encode(secret).decode("ascii")

    def encrypt_for_peer(
        self,
        *,
        peer_encryption_public_key_b64: str,
        target_client_id: str,
        room_id: str,
        session_id: str,
        sequence: int,
        message_number: int,
        sender_ratchet_key_b64: str | None,
        bootstrap_message: dict | None,
        session_secret_b64: str | None = None,
        plaintext: str,
    ) -> str:
        peer_public_key = self._load_encryption_public_key(peer_encryption_public_key_b64)
        sender_key_b64 = self.encryption_public_key_b64
        sender_signing_key_b64 = self.signing_public_key_b64
        salt = os.urandom(16)
        nonce = os.urandom(12)
        if session_secret_b64:
            key = self._derive_session_key(
                session_secret_b64=session_secret_b64,
                sender_key_b64=sender_key_b64,
                recipient_key_b64=peer_encryption_public_key_b64,
                message_number=message_number,
                salt=salt,
            )
            algorithm = "pqxdh-bridge+hkdf+aes-256-gcm+ed25519"
        else:
            shared_secret = self.encryption_private_key.exchange(peer_public_key)
            key = self._derive_key(shared_secret, sender_key_b64, peer_encryption_public_key_b64, salt)
            algorithm = "x25519+hkdf+aes-256-gcm+ed25519"
        ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
        envelope = DirectEnvelope(
            version=1,
            algorithm=algorithm,
            session_id=session_id,
            sequence=sequence,
            message_number=message_number,
            sender_key_b64=sender_key_b64,
            sender_ratchet_key_b64=sender_ratchet_key_b64,
            sender_signing_key_b64=sender_signing_key_b64,
            salt_b64=base64.b64encode(salt).decode("ascii"),
            nonce_b64=base64.b64encode(nonce).decode("ascii"),
            ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
            bootstrap_payload=bootstrap_message,
        )
        signature = self.signing_private_key.sign(
            direct_message_bytes(
                room_id=room_id,
                target_client_id=target_client_id,
                envelope=envelope.to_payload_dict(include_signature=False),
            )
        )
        signed_envelope = DirectEnvelope(
            version=envelope.version,
            algorithm=envelope.algorithm,
            session_id=envelope.session_id,
            sequence=envelope.sequence,
            message_number=envelope.message_number,
            sender_key_b64=envelope.sender_key_b64,
            sender_ratchet_key_b64=envelope.sender_ratchet_key_b64,
            sender_signing_key_b64=envelope.sender_signing_key_b64,
            salt_b64=envelope.salt_b64,
            nonce_b64=envelope.nonce_b64,
            ciphertext_b64=envelope.ciphertext_b64,
            signature_b64=base64.b64encode(signature).decode("ascii"),
            bootstrap_payload=envelope.bootstrap_payload,
        )
        return signed_envelope.to_json()

    def decrypt_from_peer(
        self,
        *,
        payload: str,
        room_id: str,
        target_client_id: str,
        session_secret_b64: str | None = None,
    ) -> DirectDecryptedMessage:
        try:
            envelope = DirectEnvelope.from_json(payload)
            if envelope.signature_b64 is None:
                raise DirectProtocolError("direct message envelope is missing signature")
            salt = base64.b64decode(envelope.salt_b64)
            nonce = base64.b64decode(envelope.nonce_b64)
            ciphertext = base64.b64decode(envelope.ciphertext_b64)
            signature = base64.b64decode(envelope.signature_b64)
        except (DirectProtocolError, ValueError) as exc:
            raise DirectCryptoError("invalid direct-message envelope") from exc

        signing_public_key = self._load_signing_public_key(envelope.sender_signing_key_b64)
        try:
            signing_public_key.verify(
                signature,
                direct_message_bytes(
                    room_id=room_id,
                    target_client_id=target_client_id,
                    envelope=envelope.to_payload_dict(include_signature=False),
                ),
            )
        except Exception as exc:
            raise DirectCryptoError("direct message signature verification failed") from exc

        if session_secret_b64 and envelope.algorithm.startswith("pqxdh-bridge"):
            key = self._derive_session_key(
                session_secret_b64=session_secret_b64,
                sender_key_b64=envelope.sender_key_b64,
                recipient_key_b64=self.encryption_public_key_b64,
                message_number=envelope.message_number,
                salt=salt,
            )
        else:
            sender_public_key = self._load_encryption_public_key(envelope.sender_key_b64)
            shared_secret = self.encryption_private_key.exchange(sender_public_key)
            key = self._derive_key(
                shared_secret,
                envelope.sender_key_b64,
                self.encryption_public_key_b64,
                salt,
            )
        try:
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, None).decode("utf-8")
        except Exception as exc:
            raise DirectCryptoError("unable to decrypt direct message") from exc

        return DirectDecryptedMessage(
            sender_key_b64=envelope.sender_key_b64,
            sender_ratchet_key_b64=envelope.sender_ratchet_key_b64,
            sender_signing_key_b64=envelope.sender_signing_key_b64,
            session_id=envelope.session_id,
            sequence=envelope.sequence,
            message_number=envelope.message_number,
            bootstrap_message=envelope.bootstrap_payload,
            plaintext=plaintext,
        )

    def _derive_key(
        self, shared_secret: bytes, sender_key_b64: str, recipient_key_b64: str, salt: bytes
    ) -> bytes:
        ordered = "|".join(sorted([sender_key_b64, recipient_key_b64])).encode("utf-8")
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"secure-chat-direct-v1|" + ordered,
        )
        return hkdf.derive(shared_secret)

    def _derive_session_key(
        self,
        *,
        session_secret_b64: str,
        sender_key_b64: str,
        recipient_key_b64: str,
        message_number: int,
        salt: bytes,
    ) -> bytes:
        try:
            session_secret = base64.b64decode(session_secret_b64)
        except Exception as exc:
            raise DirectCryptoError("invalid session secret encoding") from exc
        ordered = "|".join(sorted([sender_key_b64, recipient_key_b64])).encode("utf-8")
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"secure-chat-direct-session-v1|" + ordered + b"|" + str(message_number).encode("ascii"),
        )
        return hkdf.derive(session_secret)

    def _load_encryption_public_key(self, public_key_b64: str) -> X25519PublicKey:
        try:
            return X25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        except Exception as exc:
            raise DirectCryptoError("invalid peer encryption public key") from exc

    def _load_encryption_private_key(self, private_key_b64: str) -> X25519PrivateKey:
        try:
            return X25519PrivateKey.from_private_bytes(base64.b64decode(private_key_b64))
        except Exception as exc:
            raise DirectCryptoError("invalid local bootstrap private key") from exc

    def _load_signing_public_key(self, public_key_b64: str) -> Ed25519PublicKey:
        try:
            return Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        except Exception as exc:
            raise DirectCryptoError("invalid peer signing public key") from exc
