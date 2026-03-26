from dataclasses import dataclass
from typing import Any

try:
    from .direct_bootstrap import (
        BootstrapMessage,
        PqxdhInitAckMessage,
        PqxdhInitMessage,
        parse_bootstrap_message,
    )
    from .direct_crypto import DirectCipher, DirectCryptoError, DirectDecryptedMessage
    from .direct_protocol import DirectEnvelope, DirectProtocolError
    from .direct_session import DirectSessionSnapshot, DirectSessionStore
except ImportError:
    from direct_bootstrap import (
        BootstrapMessage,
        PqxdhInitAckMessage,
        PqxdhInitMessage,
        parse_bootstrap_message,
    )
    from direct_crypto import DirectCipher, DirectCryptoError, DirectDecryptedMessage
    from direct_protocol import DirectEnvelope, DirectProtocolError
    from direct_session import DirectSessionSnapshot, DirectSessionStore


class DirectAdapterError(Exception):
    pass


@dataclass(frozen=True)
class OutboundDirectPlan:
    target_client_id: str
    session_id: str
    sequence: int
    mode: str
    ratchet_generation: int
    message_number: int
    message_key_ref: str | None
    ratchet_public_key_b64: str
    encrypted_payload: str
    bootstrap_message: PqxdhInitMessage | None

    def to_contract_dict(self) -> dict[str, object | None]:
        return {
            "peer_client_id": self.target_client_id,
            "session_id": self.session_id,
            "sequence": self.sequence,
            "mode": self.mode,
            "ratchet_generation": self.ratchet_generation,
            "ratchet_message_number": self.message_number,
            "message_key_ref": self.message_key_ref,
            "ratchet_public_key_b64": self.ratchet_public_key_b64,
            "has_bootstrap_message": self.bootstrap_message is not None,
        }


@dataclass(frozen=True)
class InboundDirectPlan:
    peer_client_id: str
    decrypted: DirectDecryptedMessage
    mode: str
    ratchet_generation: int
    message_number: int
    message_key_ref: str | None
    used_skipped_key: bool
    ratchet_public_key_b64: str

    def to_contract_dict(self) -> dict[str, object | None]:
        return {
            "peer_client_id": self.peer_client_id,
            "session_id": self.decrypted.session_id,
            "sequence": self.decrypted.sequence,
            "mode": self.mode,
            "ratchet_generation": self.ratchet_generation,
            "used_skipped_message_key": self.used_skipped_key,
            "ratchet_message_number": self.message_number,
            "message_key_ref": self.message_key_ref,
            "ratchet_public_key_b64": self.ratchet_public_key_b64,
        }


@dataclass(frozen=True)
class BootstrapHandleResult:
    peer_client_id: str
    mode: str
    received: BootstrapMessage
    ack_message: PqxdhInitAckMessage | None
    ack_sequence: int | None
    ack_ratchet_generation: int | None
    ack_message_number: int | None
    effective_session_id: str

    def to_contract_dict(self) -> dict[str, object | None]:
        return {
            "peer_client_id": self.peer_client_id,
            "session_id": self.effective_session_id,
            "mode": self.mode,
            "received_type": type(self.received).__name__.removesuffix("Message"),
            "has_response": self.ack_message is not None,
            "response_type": (
                type(self.ack_message).__name__.removesuffix("Message")
                if self.ack_message is not None
                else None
            ),
            "response_sequence": self.ack_sequence,
            "response_ratchet_generation": self.ack_ratchet_generation,
            "response_message_number": self.ack_message_number,
        }


class DirectMessageAdapter:
    def __init__(self, cipher: DirectCipher, sessions: DirectSessionStore) -> None:
        self.cipher = cipher
        self.sessions = sessions

    def session_id_for(self, local_client_id: str, peer_client_id: str, room_id: str) -> str:
        ordered = sorted([local_client_id, peer_client_id])
        return f"dm::{room_id}::{ordered[0]}::{ordered[1]}"

    def session_snapshot(self, peer_client_id: str) -> DirectSessionSnapshot | None:
        return self.sessions.snapshot_view(peer_client_id)

    def prepare_outbound_message(
        self,
        *,
        local_client_id: str,
        peer_client_id: str,
        peer_encryption_public_key_b64: str,
        room_id: str,
        plaintext: str,
    ) -> OutboundDirectPlan:
        session_id = self.session_id_for(local_client_id, peer_client_id, room_id)
        (
            sequence,
            ratchet_generation,
            message_number,
            needs_bootstrap,
            ratchet_public_key_b64,
        ) = self.sessions.next_outbound(peer_client_id, session_id)
        session = self.sessions.get_or_create(peer_client_id, session_id)
        bootstrap_message = None
        if needs_bootstrap:
            bootstrap_private_key_b64, bootstrap_public_key_b64 = self.cipher.generate_ephemeral_keypair()
            self.sessions.set_local_bootstrap_material(
                peer_client_id,
                session_id,
                bootstrap_private_key_b64,
                bootstrap_public_key_b64,
            )
            bootstrap_message = PqxdhInitMessage(
                protocol="PQXDH/1",
                sender_client_id=local_client_id,
                receiver_client_id=peer_client_id,
                sender_encryption_identity_key=self.cipher.encryption_public_key_b64,
                sender_signing_identity_key=self.cipher.signing_public_key_b64,
                sender_ephemeral_key_b64=bootstrap_public_key_b64,
                receiver_signed_prekey_id=1,
                receiver_one_time_prekey_id=None,
                receiver_pq_prekey_present=False,
                signature_b64="",
            )
            bootstrap_message = PqxdhInitMessage(
                **{
                    **bootstrap_message.__dict__,
                    "signature_b64": self.cipher.sign_bootstrap_payload(
                        bootstrap_message.to_payload(include_signature=False)
                    ),
                }
            )
        try:
            session_secret_b64 = self.sessions.current_send_chain_secret(peer_client_id, session_id)
            encrypted_payload = self.cipher.encrypt_for_peer(
                peer_encryption_public_key_b64=peer_encryption_public_key_b64,
                target_client_id=peer_client_id,
                room_id=room_id,
                session_id=session_id,
                sequence=sequence,
                message_number=message_number,
                sender_ratchet_key_b64=ratchet_public_key_b64,
                bootstrap_message=None,
                session_secret_b64=session_secret_b64,
                plaintext=plaintext,
            )
            if session_secret_b64 is not None:
                self.sessions.advance_send_chain(peer_client_id, session_id)
        except DirectCryptoError as exc:
            raise DirectAdapterError(str(exc)) from exc

        snapshot = self.sessions.snapshot_view(peer_client_id)

        return OutboundDirectPlan(
            target_client_id=peer_client_id,
            session_id=session_id,
            sequence=sequence,
            mode=snapshot.mode if snapshot is not None else "signed-static-session",
            ratchet_generation=ratchet_generation,
            message_number=message_number,
            message_key_ref=(
                snapshot.last_send_message_key_ref if snapshot is not None else None
            ),
            ratchet_public_key_b64=ratchet_public_key_b64,
            encrypted_payload=encrypted_payload,
            bootstrap_message=bootstrap_message,
        )

    def accept_inbound_message(
        self,
        *,
        peer_client_id: str,
        payload: str,
        room_id: str,
        target_client_id: str,
        expected_signing_key_b64: str | None = None,
    ) -> InboundDirectPlan:
        try:
            envelope = DirectEnvelope.from_json(payload)
            uses_session_chain = envelope.uses_session_chain()
            receive_chain_secret, _preview_used_skipped = self.sessions.preview_inbound_chain_secret(
                peer_client_id,
                envelope.session_id,
                envelope.sequence,
                envelope.message_number,
                uses_session_chain,
                envelope.sender_ratchet_key_b64,
            )
            decrypted = self.cipher.decrypt_from_peer(
                payload=payload,
                room_id=room_id,
                target_client_id=target_client_id,
                session_secret_b64=receive_chain_secret,
            )
        except (DirectCryptoError, DirectProtocolError) as exc:
            raise DirectAdapterError(str(exc)) from exc

        accepted, ratchet_generation, message_number, used_skipped, ratchet_public_key_b64 = self.sessions.accept_inbound(
            peer_client_id,
            decrypted.session_id,
            decrypted.sequence,
            decrypted.message_number,
            uses_session_chain,
            decrypted.sender_ratchet_key_b64,
        )
        if not accepted:
            raise DirectAdapterError("replayed or out-of-order direct message rejected")
        if expected_signing_key_b64 and decrypted.sender_signing_key_b64 != expected_signing_key_b64:
            raise DirectAdapterError("direct message signing key does not match peer record")

        snapshot = self.sessions.snapshot_view(peer_client_id)

        return InboundDirectPlan(
            peer_client_id=peer_client_id,
            decrypted=decrypted,
            mode=snapshot.mode if snapshot is not None else "signed-static-session",
            ratchet_generation=ratchet_generation,
            message_number=message_number,
            message_key_ref=(
                snapshot.last_receive_message_key_ref if snapshot is not None else None
            ),
            used_skipped_key=used_skipped,
            ratchet_public_key_b64=ratchet_public_key_b64,
        )

    def handle_bootstrap_message(
        self,
        *,
        local_client_id: str,
        peer_client_id: str,
        room_id: str,
        bootstrap_payload: dict[str, Any] | BootstrapMessage,
        session_id: str | None = None,
    ) -> BootstrapHandleResult:
        if isinstance(bootstrap_payload, dict):
            bootstrap = parse_bootstrap_message(bootstrap_payload)
        else:
            bootstrap = bootstrap_payload

        effective_session_id = session_id or self.session_id_for(
            local_client_id, peer_client_id, room_id
        )

        if isinstance(bootstrap, PqxdhInitMessage):
            existing_session = self.sessions.get_or_create(peer_client_id, effective_session_id)
            if existing_session.bootstrap_secret_ref is not None:
                if existing_session.remote_bootstrap_public_key_b64 == bootstrap.sender_ephemeral_key_b64:
                    raise DirectAdapterError("duplicate bootstrap init rejected")
                raise DirectAdapterError("conflicting bootstrap init rejected for active session")
            self.cipher.verify_bootstrap_payload(
                payload=bootstrap.to_payload(include_signature=False),
                signing_key_b64=bootstrap.sender_signing_identity_key,
                signature_b64=bootstrap.signature_b64,
            )
            bootstrap_private_key_b64, bootstrap_public_key_b64 = self.cipher.generate_ephemeral_keypair()
            self.sessions.set_local_bootstrap_material(
                peer_client_id,
                effective_session_id,
                bootstrap_private_key_b64,
                bootstrap_public_key_b64,
            )
            secret_ref = self.cipher.derive_bootstrap_secret_ref(
                local_ephemeral_private_key_b64=bootstrap_private_key_b64,
                remote_ephemeral_public_key_b64=bootstrap.sender_ephemeral_key_b64,
                remote_static_public_key_b64=bootstrap.sender_encryption_identity_key,
            )
            self.sessions.set_bootstrap_secret(
                peer_client_id,
                effective_session_id,
                bootstrap.sender_ephemeral_key_b64,
                secret_ref,
                local_is_initiator=False,
            )
            ack = PqxdhInitAckMessage(
                protocol="PQXDH/1",
                sender_client_id=local_client_id,
                receiver_client_id=peer_client_id,
                session_id=effective_session_id,
                sender_encryption_identity_key=self.cipher.encryption_public_key_b64,
                sender_signing_identity_key=self.cipher.signing_public_key_b64,
                sender_ephemeral_key_b64=bootstrap_public_key_b64,
                signature_b64="",
            )
            ack = PqxdhInitAckMessage(
                **{
                    **ack.__dict__,
                    "signature_b64": self.cipher.sign_bootstrap_payload(
                        ack.to_payload(include_signature=False)
                    ),
                }
            )
            (
                sequence,
                ratchet_generation,
                message_number,
                _needs_bootstrap,
                _ratchet_public_key_b64,
            ) = self.sessions.next_outbound(
                peer_client_id, effective_session_id
            )
            return BootstrapHandleResult(
                peer_client_id=peer_client_id,
                mode="pqxdh-control",
                received=bootstrap,
                ack_message=ack,
                ack_sequence=sequence,
                ack_ratchet_generation=ratchet_generation,
                ack_message_number=message_number,
                effective_session_id=effective_session_id,
            )

        self.cipher.verify_bootstrap_payload(
            payload=bootstrap.to_payload(include_signature=False),
            signing_key_b64=bootstrap.sender_signing_identity_key,
            signature_b64=bootstrap.signature_b64,
        )
        session = self.sessions.get_or_create(peer_client_id, effective_session_id)
        if session.bootstrap_acked:
            raise DirectAdapterError("duplicate bootstrap ack rejected")
        if not session.local_bootstrap_private_key_b64:
            raise DirectAdapterError("missing local bootstrap private key for ack processing")
        if (
            session.remote_bootstrap_public_key_b64 is not None
            and session.remote_bootstrap_public_key_b64 != bootstrap.sender_ephemeral_key_b64
        ):
            raise DirectAdapterError("conflicting bootstrap ack rejected for active session")
        secret_ref = self.cipher.derive_bootstrap_secret_ref(
            local_ephemeral_private_key_b64=session.local_bootstrap_private_key_b64,
            remote_ephemeral_public_key_b64=bootstrap.sender_ephemeral_key_b64,
            remote_static_public_key_b64=bootstrap.sender_encryption_identity_key,
        )
        self.sessions.set_bootstrap_secret(
            peer_client_id,
            effective_session_id,
            bootstrap.sender_ephemeral_key_b64,
            secret_ref,
            local_is_initiator=True,
        )
        self.sessions.mark_bootstrap_acked(peer_client_id, effective_session_id)
        return BootstrapHandleResult(
            peer_client_id=peer_client_id,
            mode="pqxdh-control",
            received=bootstrap,
            ack_message=None,
            ack_sequence=None,
            ack_ratchet_generation=None,
            ack_message_number=None,
            effective_session_id=effective_session_id,
        )
