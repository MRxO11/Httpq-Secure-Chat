from dataclasses import dataclass
import hashlib

try:
    from .direct_adapter import DirectMessageAdapter
    from .direct_crypto import DirectCipher, DirectCryptoError
    from .peer_pin_store import PeerPin, PeerPinStore
    from .room_crypto import DecryptedMessage, RoomCipher, RoomCryptoError
    from .trust_adapter import TrustAdapter
except ImportError:
    from direct_adapter import DirectMessageAdapter
    from direct_crypto import DirectCipher, DirectCryptoError
    from peer_pin_store import PeerPin, PeerPinStore
    from room_crypto import DecryptedMessage, RoomCipher, RoomCryptoError
    from trust_adapter import TrustAdapter


class ClientSessionAdapterError(Exception):
    pass


@dataclass(frozen=True)
class JoinIdentity:
    direct_key: str
    direct_signing_key: str
    direct_signature: str


class ClientSessionAdapter:
    def __init__(
        self,
        *,
        trust: TrustAdapter,
        direct: DirectMessageAdapter,
        direct_cipher: DirectCipher,
        room_cipher: RoomCipher,
        peer_pin_store: PeerPinStore | None = None,
    ) -> None:
        self.trust = trust
        self.direct = direct
        self.direct_cipher = direct_cipher
        self.room_cipher = room_cipher
        self.peer_pin_store = peer_pin_store or PeerPinStore()

    def build_join_identity(self, *, client_id: str, username: str, room_id: str) -> JoinIdentity:
        return JoinIdentity(
            direct_key=self.direct_cipher.encryption_public_key_b64,
            direct_signing_key=self.direct_cipher.signing_public_key_b64,
            direct_signature=self.direct_cipher.sign_peer_announcement(
                client_id=client_id,
                username=username,
                room_id=room_id,
            ),
        )

    def peer_safety_number(
        self,
        *,
        username: str,
        encryption_key_b64: str,
        signing_key_b64: str,
    ) -> str:
        digest = hashlib.sha256(
            f"{username}|{encryption_key_b64}|{signing_key_b64}".encode("utf-8")
        ).hexdigest()[:24]
        return " ".join(digest[i : i + 4] for i in range(0, len(digest), 4))

    def reset_peer_trust(self, *, room_id: str, username: str) -> bool:
        removed = self.peer_pin_store.remove(room_id=room_id, username=username)
        return removed is not None

    def verify_peer(self, *, peer: dict, room_id: str) -> None:
        client_id = str(peer.get("clientId", ""))
        username = str(peer.get("username", ""))
        direct_key = str(peer.get("directKey", ""))
        direct_signing_key = str(peer.get("directSigningKey", ""))
        direct_signature = str(peer.get("directSignature", ""))
        if not client_id or not direct_key or not direct_signing_key or not direct_signature:
            raise ClientSessionAdapterError(
                f"incomplete peer identity data for {client_id or 'unknown'}"
            )

        try:
            self.direct_cipher.verify_peer_announcement(
                client_id=client_id,
                username=username,
                room_id=room_id,
                encryption_key_b64=direct_key,
                signing_key_b64=direct_signing_key,
                signature_b64=direct_signature,
            )
        except DirectCryptoError as exc:
            raise ClientSessionAdapterError(str(exc)) from exc

        self._verify_peer_pin(
            room_id=room_id,
            username=username,
            encryption_key_b64=direct_key,
            signing_key_b64=direct_signing_key,
        )

    def encrypt_room_message(
        self,
        *,
        room_id: str,
        plaintext: str,
        epoch: int = 0,
        epoch_key_ref: str | None = None,
        epoch_secret_ref: str | None = None,
        application_secret_ref: str | None = None,
        mode: str = "room-aes-256-gcm+scrypt",
    ) -> str:
        try:
            return self.room_cipher.encrypt_for_room(
                room_id,
                plaintext,
                epoch=epoch,
                epoch_key_ref=epoch_key_ref,
                epoch_secret_ref=epoch_secret_ref,
                application_secret_ref=application_secret_ref,
                mode=mode,
            )
        except RoomCryptoError as exc:
            raise ClientSessionAdapterError(str(exc)) from exc

    def _verify_peer_pin(
        self,
        *,
        room_id: str,
        username: str,
        encryption_key_b64: str,
        signing_key_b64: str,
    ) -> None:
        pinned = self.peer_pin_store.get(room_id=room_id, username=username)
        if pinned is None:
            self.peer_pin_store.save(
                PeerPin(
                    room_id=room_id,
                    username=username,
                    encryption_key_b64=encryption_key_b64,
                    signing_key_b64=signing_key_b64,
                )
            )
            return
        if (
            pinned.encryption_key_b64 != encryption_key_b64
            or pinned.signing_key_b64 != signing_key_b64
        ):
            previous_safety = self.peer_safety_number(
                username=username,
                encryption_key_b64=pinned.encryption_key_b64,
                signing_key_b64=pinned.signing_key_b64,
            )
            new_safety = self.peer_safety_number(
                username=username,
                encryption_key_b64=encryption_key_b64,
                signing_key_b64=signing_key_b64,
            )
            raise ClientSessionAdapterError(
                "security warning: "
                f"peer identity for {username} changed from {previous_safety} to {new_safety}"
            )

    def decrypt_room_message(
        self,
        *,
        payload: str,
        expected_epoch: int | None = None,
        expected_epoch_key_ref: str | None = None,
        expected_epoch_secret_ref: str | None = None,
        expected_application_secret_ref: str | None = None,
    ) -> DecryptedMessage:
        try:
            return self.room_cipher.decrypt_from_room(
                payload,
                expected_epoch=expected_epoch,
                expected_epoch_key_ref=expected_epoch_key_ref,
                expected_epoch_secret_ref=expected_epoch_secret_ref,
                expected_application_secret_ref=expected_application_secret_ref,
            )
        except RoomCryptoError as exc:
            raise ClientSessionAdapterError(str(exc)) from exc
