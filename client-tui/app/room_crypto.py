import base64
import json
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class RoomCryptoError(Exception):
    pass


@dataclass
class DecryptedMessage:
    room_id: str
    epoch: int
    epoch_key_ref: str | None
    epoch_secret_ref: str | None
    application_secret_ref: str | None
    mode: str
    plaintext: str


class RoomCipher:
    def __init__(self) -> None:
        self._room_keys: dict[str, str] = {}
        default_key = os.getenv("CHAT_ROOM_KEY", "").strip()
        default_room = os.getenv("CHAT_ROOM", "lobby").strip() or "lobby"
        if default_key:
            self._room_keys[default_room] = default_key

    def set_room_key(self, room_id: str, passphrase: str) -> None:
        room_id = self._normalize_room(room_id)
        passphrase = passphrase.strip()
        if not passphrase:
            raise RoomCryptoError("room key cannot be empty")

        self._room_keys[room_id] = passphrase

    def has_room_key(self, room_id: str) -> bool:
        return self._normalize_room(room_id) in self._room_keys

    def encrypt_for_room(
        self,
        room_id: str,
        plaintext: str,
        *,
        epoch: int = 0,
        epoch_key_ref: str | None = None,
        epoch_secret_ref: str | None = None,
        application_secret_ref: str | None = None,
        mode: str = "room-aes-256-gcm+scrypt",
    ) -> str:
        room_id = self._normalize_room(room_id)
        passphrase = self._room_keys.get(room_id)
        if not passphrase:
            raise RoomCryptoError(f"no room key configured for {room_id}")

        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = self._derive_key(
            passphrase,
            room_id,
            salt,
            epoch_key_ref,
            epoch_secret_ref,
            application_secret_ref,
        )
        ciphertext = AESGCM(key).encrypt(
            nonce,
            plaintext.encode("utf-8"),
            self._aad(room_id, epoch, epoch_key_ref, epoch_secret_ref, application_secret_ref),
        )

        envelope = {
            "v": 1,
            "alg": "aes-256-gcm+scrypt",
            "mode": mode,
            "roomId": room_id,
            "epoch": epoch,
            "epochKeyRef": epoch_key_ref,
            "epochSecretRef": epoch_secret_ref,
            "applicationSecretRef": application_secret_ref,
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }
        return json.dumps(envelope, separators=(",", ":"))

    def decrypt_from_room(
        self,
        payload: str,
        *,
        expected_epoch: int | None = None,
        expected_epoch_key_ref: str | None = None,
        expected_epoch_secret_ref: str | None = None,
        expected_application_secret_ref: str | None = None,
    ) -> DecryptedMessage:
        try:
            envelope = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise RoomCryptoError("payload is not a valid encrypted envelope") from exc

        room_id = self._normalize_room(str(envelope.get("roomId", "")))
        epoch = int(envelope.get("epoch", 0))
        epoch_key_ref = (
            str(envelope["epochKeyRef"]) if envelope.get("epochKeyRef") is not None else None
        )
        epoch_secret_ref = (
            str(envelope["epochSecretRef"])
            if envelope.get("epochSecretRef") is not None
            else None
        )
        application_secret_ref = (
            str(envelope["applicationSecretRef"])
            if envelope.get("applicationSecretRef") is not None
            else None
        )
        mode = str(envelope.get("mode", "room-aes-256-gcm+scrypt"))
        passphrase = self._room_keys.get(room_id)
        if not passphrase:
            raise RoomCryptoError(f"missing room key for {room_id}")

        if expected_epoch is not None and epoch != expected_epoch:
            raise RoomCryptoError(
                f"room epoch mismatch: expected {expected_epoch}, received {epoch}"
            )
        if expected_epoch_key_ref is not None and epoch_key_ref != expected_epoch_key_ref:
            raise RoomCryptoError("room epoch key ref mismatch")
        if expected_epoch_secret_ref is not None and epoch_secret_ref != expected_epoch_secret_ref:
            raise RoomCryptoError("room epoch secret ref mismatch")
        if (
            expected_application_secret_ref is not None
            and application_secret_ref != expected_application_secret_ref
        ):
            raise RoomCryptoError("room application secret ref mismatch")

        try:
            salt = base64.b64decode(envelope["salt"])
            nonce = base64.b64decode(envelope["nonce"])
            ciphertext = base64.b64decode(envelope["ciphertext"])
        except Exception as exc:
            raise RoomCryptoError("invalid encrypted envelope encoding") from exc

        key = self._derive_key(
            passphrase,
            room_id,
            salt,
            epoch_key_ref,
            epoch_secret_ref,
            application_secret_ref,
        )
        try:
            plaintext = AESGCM(key).decrypt(
                nonce,
                ciphertext,
                self._aad(
                    room_id,
                    epoch,
                    epoch_key_ref,
                    epoch_secret_ref,
                    application_secret_ref,
                ),
            )
        except Exception as exc:
            raise RoomCryptoError("unable to decrypt payload with current room key") from exc

        return DecryptedMessage(
            room_id=room_id,
            epoch=epoch,
            epoch_key_ref=epoch_key_ref,
            epoch_secret_ref=epoch_secret_ref,
            application_secret_ref=application_secret_ref,
            mode=mode,
            plaintext=plaintext.decode("utf-8"),
        )

    def _derive_key(
        self,
        passphrase: str,
        room_id: str,
        salt: bytes,
        epoch_key_ref: str | None,
        epoch_secret_ref: str | None,
        application_secret_ref: str | None,
    ) -> bytes:
        kdf = Scrypt(
            salt=(
                salt
                + room_id.encode("utf-8")
                + (epoch_key_ref or "").encode("utf-8")
                + (epoch_secret_ref or "").encode("utf-8")
                + (application_secret_ref or "").encode("utf-8")
            ),
            length=32,
            n=2**14,
            r=8,
            p=1,
        )
        return kdf.derive(passphrase.encode("utf-8"))

    def _normalize_room(self, room_id: str) -> str:
        room_id = room_id.strip()
        return room_id or "lobby"

    def _aad(
        self,
        room_id: str,
        epoch: int,
        epoch_key_ref: str | None,
        epoch_secret_ref: str | None,
        application_secret_ref: str | None,
    ) -> bytes:
        return "|".join(
            [
                room_id,
                str(epoch),
                epoch_key_ref or "",
                epoch_secret_ref or "",
                application_secret_ref or "",
            ]
        ).encode("utf-8")
