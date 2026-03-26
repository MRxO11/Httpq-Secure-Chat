from dataclasses import dataclass

try:
    from .client_session_adapter import ClientSessionAdapter, ClientSessionAdapterError
    from .mls_backend import MlsBackendError, ensure_mls_mode_allowed
    from .peer_directory import PeerDirectory, PeerDirectoryError, SnapshotResult
    from .room_control import (
        PortableRoomControlEvent,
        RoomCommitMessage,
        RoomEpochUpdateMessage,
        RoomProposalMessage,
        RoomWelcomeMessage,
        parse_room_control_message,
    )
    from .room_state import RoomStateStore
    from .room_state import RoomStateError
    from .traffic_events import TrafficEventMetadata, TrafficMessage
except ImportError:
    from client_session_adapter import ClientSessionAdapter, ClientSessionAdapterError
    from mls_backend import MlsBackendError, ensure_mls_mode_allowed
    from peer_directory import PeerDirectory, PeerDirectoryError, SnapshotResult
    from room_control import (
        PortableRoomControlEvent,
        RoomCommitMessage,
        RoomEpochUpdateMessage,
        RoomProposalMessage,
        RoomWelcomeMessage,
        parse_room_control_message,
    )
    from room_state import RoomStateStore
    from room_state import RoomStateError
    from traffic_events import TrafficEventMetadata, TrafficMessage


class ClientAppControllerError(Exception):
    pass


@dataclass(frozen=True)
class JoinRequest:
    room_id: str
    username: str
    direct_key: str
    direct_signing_key: str
    direct_signature: str


@dataclass(frozen=True)
class OutboundRoomMessage:
    payload: str
    plaintext: str
    metadata: TrafficEventMetadata
    traffic_message: TrafficMessage


@dataclass(frozen=True)
class InboundRoomMessage:
    plaintext: str
    metadata: TrafficEventMetadata
    traffic_message: TrafficMessage


@dataclass(frozen=True)
class RoomControlPlan:
    payload: dict
    snapshot_epoch: int
    epoch_key_ref: str | None
    epoch_secret_ref: str | None
    commit_secret_ref: str | None
    welcome_secret_ref: str | None
    application_secret_ref: str | None
    message_type: str

    def to_contract_dict(self) -> dict[str, object | None]:
        return PortableRoomControlEvent(
            room_id=str(self.payload.get("roomId", "")),
            message_type=self.message_type,
            mode=str(self.payload.get("mode", "")),
            epoch=self.snapshot_epoch,
            epoch_key_ref=self.epoch_key_ref,
            epoch_secret_ref=self.epoch_secret_ref,
            commit_secret_ref=self.commit_secret_ref,
            welcome_secret_ref=self.welcome_secret_ref,
            application_secret_ref=self.application_secret_ref,
        ).to_contract_dict()

    @classmethod
    def from_contract_dict(
        cls,
        payload: dict[str, object | None],
        *,
        room_payload: dict,
    ) -> "RoomControlPlan":
        portable = PortableRoomControlEvent.from_contract_dict(payload)
        return cls(
            payload=room_payload,
            snapshot_epoch=portable.epoch,
            epoch_key_ref=portable.epoch_key_ref,
            epoch_secret_ref=portable.epoch_secret_ref,
            commit_secret_ref=portable.commit_secret_ref,
            welcome_secret_ref=portable.welcome_secret_ref,
            application_secret_ref=portable.application_secret_ref,
            message_type=portable.message_type,
        )


class ClientAppController:
    def __init__(self, session: ClientSessionAdapter, room_state_store: RoomStateStore | None = None) -> None:
        self.session = session
        self.peers = PeerDirectory(self.session.verify_peer)
        self.rooms = room_state_store or RoomStateStore()

    def build_join_request(self, *, client_id: str, username: str, room_id: str) -> JoinRequest:
        identity = self.session.build_join_identity(
            client_id=client_id,
            username=username,
            room_id=room_id,
        )
        return JoinRequest(
            room_id=room_id,
            username=username,
            direct_key=identity.direct_key,
            direct_signing_key=identity.direct_signing_key,
            direct_signature=identity.direct_signature,
        )

    def peer_safety_number(self, peer: dict) -> str | None:
        username = str(peer.get("username", "")).strip()
        direct_key = str(peer.get("directKey", "")).strip()
        direct_signing_key = str(peer.get("directSigningKey", "")).strip()
        if not username or not direct_key or not direct_signing_key:
            return None
        return self.session.peer_safety_number(
            username=username,
            encryption_key_b64=direct_key,
            signing_key_b64=direct_signing_key,
        )

    def reset_peer_trust(self, peer: dict, *, room_id: str) -> bool:
        username = str(peer.get("username", "")).strip()
        if not username:
            raise ClientAppControllerError("peer is missing username")
        return self.session.reset_peer_trust(room_id=room_id, username=username)

    def encrypt_room_message(self, *, room_id: str, plaintext: str) -> OutboundRoomMessage:
        snapshot = self.rooms.snapshot(room_id)
        portable_snapshot = snapshot.from_contract_dict(snapshot.to_contract_dict())
        self._ensure_room_mode_allowed(
            mode=portable_snapshot.mode,
            context="room application encryption",
        )
        try:
            payload = self.session.encrypt_room_message(
                room_id=room_id,
                plaintext=plaintext,
                epoch=portable_snapshot.epoch,
                epoch_key_ref=portable_snapshot.epoch_key_ref,
                epoch_secret_ref=portable_snapshot.epoch_secret_ref,
                application_secret_ref=portable_snapshot.application_secret_ref,
                mode=portable_snapshot.mode,
            )
        except ClientSessionAdapterError as exc:
            raise ClientAppControllerError(str(exc)) from exc
        metadata = TrafficEventMetadata(
            conversation_kind="room",
            transport_kind="application",
            mode=portable_snapshot.mode,
            room_id=portable_snapshot.room_id,
        )
        return OutboundRoomMessage(
            payload=payload,
            plaintext=plaintext,
            metadata=metadata,
            traffic_message=TrafficMessage(
                metadata=metadata,
                display_name="room",
                plaintext=plaintext,
                outgoing=True,
            ),
        )

    def decrypt_room_message(self, *, payload: str) -> InboundRoomMessage:
        room_id = "lobby"
        try:
            import json

            envelope = json.loads(payload)
            room_id = str(envelope.get("roomId", "lobby"))
        except Exception:
            pass
        snapshot = self.rooms.snapshot(room_id)
        portable_snapshot = snapshot.from_contract_dict(snapshot.to_contract_dict())
        self._ensure_room_mode_allowed(
            mode=portable_snapshot.mode,
            context="room application decryption",
        )
        try:
            decrypted = self.session.decrypt_room_message(
                payload=payload,
                expected_epoch=portable_snapshot.epoch,
                expected_epoch_key_ref=portable_snapshot.epoch_key_ref,
                expected_epoch_secret_ref=portable_snapshot.epoch_secret_ref,
                expected_application_secret_ref=portable_snapshot.application_secret_ref,
            )
        except ClientSessionAdapterError as exc:
            raise ClientAppControllerError(str(exc)) from exc
        metadata = TrafficEventMetadata(
            conversation_kind="room",
            transport_kind="application",
            mode=decrypted.mode,
            room_id=decrypted.room_id,
        )
        return InboundRoomMessage(
            plaintext=decrypted.plaintext,
            metadata=metadata,
            traffic_message=TrafficMessage(
                metadata=metadata,
                display_name="room",
                plaintext=decrypted.plaintext,
            ),
        )

    def set_room_key(self, *, room_id: str, secret: str) -> None:
        try:
            self.session.room_cipher.set_room_key(room_id, secret)
            self.rooms.set_room_key_present(room_id, True)
        except Exception as exc:
            raise ClientAppControllerError(str(exc)) from exc

    def apply_peer_snapshot(self, *, peers: list[dict], room_id: str) -> SnapshotResult:
        return self.peers.snapshot(peers=peers, room_id=room_id)

    def apply_peer_upsert(self, *, peer: dict, room_id: str) -> dict:
        try:
            return self.peers.upsert(peer=peer, room_id=room_id)
        except PeerDirectoryError as exc:
            raise ClientAppControllerError(str(exc)) from exc

    def remove_peer(self, client_id: str) -> dict | None:
        return self.peers.remove(client_id)

    def get_peer(self, client_id: str) -> dict | None:
        return self.peers.get(client_id)

    def get_peer_by_route_token(self, route_token: str) -> dict | None:
        return self.peers.get_by_route_token(route_token)

    def resolve_peer(self, handle: str) -> dict | None:
        try:
            return self.peers.resolve(handle)
        except PeerDirectoryError as exc:
            raise ClientAppControllerError(str(exc)) from exc

    def peer_values(self) -> list[dict]:
        return self.peers.values()

    def peer_count(self) -> int:
        return len(self.peers)

    def room_snapshot(self, room_id: str):
        snapshot = self.rooms.snapshot(room_id)
        return snapshot.from_contract_dict(snapshot.to_contract_dict())

    def record_room_members(self, *, room_id: str, member_count: int):
        snapshot = self.rooms.record_members(room_id, member_count)
        return snapshot.from_contract_dict(snapshot.to_contract_dict())

    def _portable_room_control(
        self,
        *,
        room_id: str,
        message_type: str,
    ) -> PortableRoomControlEvent:
        snapshot = self.rooms.snapshot(room_id)
        portable_snapshot = snapshot.from_contract_dict(snapshot.to_contract_dict())
        self._ensure_room_mode_allowed(
            mode=portable_snapshot.mode,
            context="room control export",
        )
        return PortableRoomControlEvent(
            room_id=portable_snapshot.room_id,
            message_type=message_type,
            mode=portable_snapshot.mode,
            epoch=portable_snapshot.epoch,
            epoch_key_ref=portable_snapshot.epoch_key_ref,
            epoch_secret_ref=portable_snapshot.epoch_secret_ref,
            commit_secret_ref=portable_snapshot.commit_secret_ref,
            welcome_secret_ref=portable_snapshot.welcome_secret_ref,
            application_secret_ref=portable_snapshot.application_secret_ref,
        )

    def prepare_room_epoch_update(self, *, room_id: str, sender_client_id: str) -> RoomControlPlan:
        snapshot = self.rooms.advance_epoch(room_id, mode="mls-placeholder")
        portable_snapshot = snapshot.from_contract_dict(snapshot.to_contract_dict())
        self._ensure_room_mode_allowed(
            mode=portable_snapshot.mode,
            context="room epoch update",
        )
        portable_control = self._portable_room_control(
            room_id=portable_snapshot.room_id,
            message_type="RoomEpochUpdate",
        )
        message = RoomEpochUpdateMessage(
            room_id=portable_snapshot.room_id,
            epoch=portable_snapshot.epoch,
            epoch_key_ref=portable_snapshot.epoch_key_ref or "",
            sender_client_id=sender_client_id,
            mode=portable_snapshot.mode,
        )
        return RoomControlPlan.from_contract_dict(
            portable_control.to_contract_dict(),
            room_payload=message.to_payload(),
        )

    def prepare_room_proposal(
        self,
        *,
        room_id: str,
        sender_client_id: str,
        target_client_id: str | None,
        proposal_kind: str = "add-member",
    ) -> RoomControlPlan:
        proposal_id = f"proposal::{room_id}::{sender_client_id}::{target_client_id or 'room'}"
        snapshot = self.rooms.mark_pending_commit(
            room_id,
            proposal_id=proposal_id,
            mode="mls-placeholder",
        )
        portable_snapshot = snapshot.from_contract_dict(snapshot.to_contract_dict())
        self._ensure_room_mode_allowed(
            mode=portable_snapshot.mode,
            context="room proposal",
        )
        portable_control = self._portable_room_control(
            room_id=portable_snapshot.room_id,
            message_type="RoomProposal",
        )
        message = RoomProposalMessage(
            room_id=portable_snapshot.room_id,
            proposal_id=proposal_id,
            proposal_kind=proposal_kind,
            sender_client_id=sender_client_id,
            target_client_id=target_client_id,
            mode=portable_snapshot.mode,
        )
        return RoomControlPlan.from_contract_dict(
            portable_control.to_contract_dict(),
            room_payload=message.to_payload(),
        )

    def prepare_room_commit(
        self,
        *,
        room_id: str,
        sender_client_id: str,
    ) -> RoomControlPlan:
        snapshot = self.rooms.advance_epoch(room_id, mode="mls-placeholder")
        portable_snapshot = snapshot.from_contract_dict(snapshot.to_contract_dict())
        self._ensure_room_mode_allowed(
            mode=portable_snapshot.mode,
            context="room commit",
        )
        portable_control = self._portable_room_control(
            room_id=portable_snapshot.room_id,
            message_type="RoomCommit",
        )
        proposal_ids = (
            [portable_snapshot.last_proposal_id]
            if portable_snapshot.last_proposal_id
            else []
        )
        message = RoomCommitMessage(
            room_id=portable_snapshot.room_id,
            epoch=portable_snapshot.epoch,
            epoch_key_ref=portable_snapshot.epoch_key_ref or "",
            sender_client_id=sender_client_id,
            mode=portable_snapshot.mode,
            proposal_ids=proposal_ids,
        )
        return RoomControlPlan.from_contract_dict(
            portable_control.to_contract_dict(),
            room_payload=message.to_payload(),
        )

    def prepare_room_welcome(
        self,
        *,
        room_id: str,
        sender_client_id: str,
        recipient_client_id: str,
    ) -> RoomControlPlan:
        snapshot = self.rooms.snapshot(room_id)
        portable_snapshot = snapshot.from_contract_dict(snapshot.to_contract_dict())
        self._ensure_room_mode_allowed(
            mode=portable_snapshot.mode,
            context="room welcome",
        )
        portable_control = self._portable_room_control(
            room_id=portable_snapshot.room_id,
            message_type="RoomWelcome",
        )
        message = RoomWelcomeMessage(
            room_id=portable_snapshot.room_id,
            epoch=portable_snapshot.epoch,
            epoch_key_ref=portable_snapshot.epoch_key_ref or "",
            sender_client_id=sender_client_id,
            recipient_client_id=recipient_client_id,
            mode=portable_snapshot.mode,
        )
        return RoomControlPlan.from_contract_dict(
            portable_control.to_contract_dict(),
            room_payload=message.to_payload(),
        )

    def apply_room_control(self, *, payload: dict) -> RoomControlPlan:
        message = parse_room_control_message(payload)
        self._ensure_room_mode_allowed(
            mode=message.mode,
            context=f"inbound {payload.get('type', 'room control')}",
        )
        if isinstance(message, RoomProposalMessage):
            snapshot = self.rooms.mark_pending_commit(
                message.room_id,
                proposal_id=message.proposal_id,
                mode=message.mode,
            )
        elif isinstance(message, (RoomCommitMessage, RoomEpochUpdateMessage, RoomWelcomeMessage)):
            try:
                snapshot = self.rooms.apply_remote_epoch(
                    message.room_id,
                    epoch=message.epoch,
                    epoch_key_ref=message.epoch_key_ref,
                    mode=message.mode,
                )
            except RoomStateError as exc:
                raise ClientAppControllerError(str(exc)) from exc
        else:
            raise ClientAppControllerError("unsupported room control message")
        portable_control = self._portable_room_control(
            room_id=snapshot.room_id,
            message_type=type(message).__name__.removesuffix("Message"),
        )
        return RoomControlPlan.from_contract_dict(
            portable_control.to_contract_dict(),
            room_payload=message.to_payload(),
        )

    def _ensure_room_mode_allowed(self, *, mode: str, context: str) -> None:
        try:
            ensure_mls_mode_allowed(mode=mode, context=context)
        except MlsBackendError as exc:
            raise ClientAppControllerError(str(exc)) from exc
