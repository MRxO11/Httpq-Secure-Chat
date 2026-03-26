import json
from dataclasses import dataclass
from typing import Any

try:
    from .direct_adapter import DirectAdapterError, DirectMessageAdapter
    from .direct_crypto import DirectDecryptedMessage
    from .direct_frames import DirectApplicationFrame, DirectControlFrame
    from .traffic_events import TrafficEventMetadata, TrafficMessage
except ImportError:
    from direct_adapter import DirectAdapterError, DirectMessageAdapter
    from direct_crypto import DirectDecryptedMessage
    from direct_frames import DirectApplicationFrame, DirectControlFrame
    from traffic_events import TrafficEventMetadata, TrafficMessage


class ChatSessionControllerError(Exception):
    pass


@dataclass(frozen=True)
class OutboundDirectSend:
    control_frame: DirectControlFrame | None
    control_metadata: TrafficEventMetadata | None
    application_frame: DirectApplicationFrame
    metadata: TrafficEventMetadata
    traffic_message: TrafficMessage
    target_client_id: str
    target_display_name: str
    plaintext: str


@dataclass(frozen=True)
class InboundDirectReceive:
    decrypted: DirectDecryptedMessage
    metadata: TrafficEventMetadata
    traffic_message: TrafficMessage
    used_skipped_key: bool
    ack_frame: DirectControlFrame | None
    ack_metadata: TrafficEventMetadata | None
    bootstrap_log: str | None
    ack_log: str | None


@dataclass(frozen=True)
class InboundControlReceive:
    metadata: TrafficEventMetadata
    ack_frame: DirectControlFrame | None
    ack_metadata: TrafficEventMetadata | None
    bootstrap_log: str | None
    ack_log: str | None


class ChatSessionController:
    def __init__(self, direct: DirectMessageAdapter) -> None:
        self.direct = direct

    def session_id_for(self, *, local_client_id: str, peer_client_id: str, room_id: str) -> str:
        return self.direct.session_id_for(local_client_id, peer_client_id, room_id)

    def prepare_outbound_direct(
        self,
        *,
        local_client_id: str,
        peer_client_id: str,
        peer_display_name: str,
        peer_encryption_public_key_b64: str,
        peer_route_token: str | None = None,
        room_id: str,
        plaintext: str,
    ) -> OutboundDirectSend:
        try:
            outbound = self.direct.prepare_outbound_message(
                local_client_id=local_client_id,
                peer_client_id=peer_client_id,
                peer_encryption_public_key_b64=peer_encryption_public_key_b64,
                room_id=room_id,
                plaintext=plaintext,
            )
        except DirectAdapterError as exc:
            raise ChatSessionControllerError(str(exc)) from exc

        outbound_contract = outbound.to_contract_dict()

        control_frame = None
        control_metadata = None
        if outbound.bootstrap_message is not None:
            control_frame = DirectControlFrame(
                target_client_id=peer_client_id,
                target_route_token=peer_route_token,
                payload=outbound.bootstrap_message.to_payload(),
            )
            control_metadata = TrafficEventMetadata(
                conversation_kind="control",
                transport_kind="control",
                mode="pqxdh-control",
                room_id=room_id,
                peer_client_id=str(outbound_contract["peer_client_id"]),
                sequence=int(outbound_contract["sequence"]),
                ratchet_generation=int(outbound_contract["ratchet_generation"]),
                message_number=int(outbound_contract["ratchet_message_number"]),
                message_key_ref=None,
            )

        metadata = TrafficEventMetadata(
            conversation_kind="direct",
            transport_kind="application",
            mode=str(outbound_contract["mode"]),
            room_id=room_id,
            peer_client_id=str(outbound_contract["peer_client_id"]),
            sequence=int(outbound_contract["sequence"]),
            ratchet_generation=int(outbound_contract["ratchet_generation"]),
            message_number=int(outbound_contract["ratchet_message_number"]),
            message_key_ref=outbound_contract["message_key_ref"],  # type: ignore[arg-type]
        )
        return OutboundDirectSend(
            control_frame=control_frame,
            control_metadata=control_metadata,
            application_frame=DirectApplicationFrame(
                target_client_id=peer_client_id,
                target_route_token=peer_route_token,
                payload=outbound.encrypted_payload,
            ),
            metadata=metadata,
            traffic_message=TrafficMessage(
                metadata=metadata,
                display_name=peer_display_name,
                plaintext=plaintext,
                outgoing=True,
            ),
            target_client_id=peer_client_id,
            target_display_name=peer_display_name,
            plaintext=plaintext,
        )

    def handle_inbound_direct(
        self,
        *,
        peer_client_id: str,
        peer_display_name: str,
        payload: str,
        room_id: str,
        target_client_id: str,
        peer_route_token: str | None = None,
        expected_signing_key_b64: str | None = None,
    ) -> InboundDirectReceive:
        try:
            inbound = self.direct.accept_inbound_message(
                peer_client_id=peer_client_id,
                payload=payload,
                room_id=room_id,
                target_client_id=target_client_id,
                expected_signing_key_b64=expected_signing_key_b64,
            )
            ack_frame, bootstrap_log, ack_log = self._handle_bootstrap_payload(
                local_client_id=target_client_id,
                peer_client_id=peer_client_id,
                peer_display_name=peer_display_name,
                room_id=room_id,
                bootstrap_payload=inbound.decrypted.bootstrap_message,
                session_id=inbound.decrypted.session_id,
                peer_route_token=peer_route_token,
            )
        except DirectAdapterError as exc:
            raise ChatSessionControllerError(str(exc)) from exc

        inbound_contract = inbound.to_contract_dict()

        metadata = TrafficEventMetadata(
            conversation_kind="direct",
            transport_kind="application",
            mode=str(inbound_contract["mode"]),
            room_id=room_id,
            peer_client_id=str(inbound_contract["peer_client_id"]),
            sequence=int(inbound_contract["sequence"]),
            ratchet_generation=int(inbound_contract["ratchet_generation"]),
            message_number=int(inbound_contract["ratchet_message_number"]),
            message_key_ref=inbound_contract["message_key_ref"],  # type: ignore[arg-type]
        )
        return InboundDirectReceive(
            decrypted=inbound.decrypted,
            metadata=metadata,
            traffic_message=TrafficMessage(
                metadata=metadata,
                display_name=peer_display_name,
                plaintext=inbound.decrypted.plaintext,
                used_skipped_key=inbound.used_skipped_key,
            ),
            used_skipped_key=inbound.used_skipped_key,
            ack_frame=ack_frame,
            ack_metadata=(
                TrafficEventMetadata(
                    conversation_kind="control",
                    transport_kind="control",
                    mode="pqxdh-control",
                    room_id=room_id,
                    peer_client_id=peer_client_id,
                    sequence=0,
                    ratchet_generation=0,
                    message_number=0,
                    message_key_ref=None,
                )
                if ack_frame is not None
                else None
            ),
            bootstrap_log=bootstrap_log,
            ack_log=ack_log,
        )

    def handle_inbound_control(
        self,
        *,
        local_client_id: str,
        peer_client_id: str,
        peer_display_name: str,
        room_id: str,
        payload: str | dict[str, Any],
        peer_route_token: str | None = None,
    ) -> InboundControlReceive:
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except (TypeError, ValueError) as exc:
                raise ChatSessionControllerError(str(exc)) from exc

        ack_frame, bootstrap_log, ack_log = self._handle_bootstrap_payload(
            local_client_id=local_client_id,
            peer_client_id=peer_client_id,
            peer_display_name=peer_display_name,
            room_id=room_id,
            bootstrap_payload=payload,
            session_id=self.session_id_for(
                local_client_id=local_client_id,
                peer_client_id=peer_client_id,
                room_id=room_id,
            ),
            peer_route_token=peer_route_token,
        )
        return InboundControlReceive(
            metadata=TrafficEventMetadata(
                conversation_kind="control",
                transport_kind="control",
                mode="pqxdh-control",
                room_id=room_id,
                peer_client_id=peer_client_id,
                sequence=0,
                ratchet_generation=0,
                message_number=0,
                message_key_ref=None,
            ),
            ack_frame=ack_frame,
            ack_metadata=(
                TrafficEventMetadata(
                    conversation_kind="control",
                    transport_kind="control",
                    mode="pqxdh-control",
                    room_id=room_id,
                    peer_client_id=peer_client_id,
                    sequence=0,
                    ratchet_generation=0,
                    message_number=0,
                    message_key_ref=None,
                )
                if ack_frame is not None
                else None
            ),
            bootstrap_log=bootstrap_log,
            ack_log=ack_log,
        )

    def _handle_bootstrap_payload(
        self,
        *,
        local_client_id: str,
        peer_client_id: str,
        peer_display_name: str,
        room_id: str,
        bootstrap_payload: dict[str, Any] | None,
        session_id: str,
        peer_route_token: str | None,
    ) -> tuple[DirectControlFrame | None, str | None, str | None]:
        if bootstrap_payload is None:
            return None, None, None

        try:
            result = self.direct.handle_bootstrap_message(
                local_client_id=local_client_id,
                peer_client_id=peer_client_id,
                room_id=room_id,
                bootstrap_payload=bootstrap_payload,
                session_id=session_id,
            )
        except DirectAdapterError as exc:
            raise ChatSessionControllerError(str(exc)) from exc

        result_contract = result.to_contract_dict()

        if result.ack_message is not None:
            return (
                DirectControlFrame(
                    target_client_id=peer_client_id,
                    target_route_token=peer_route_token,
                    payload=result.ack_message.to_payload(),
                ),
                (
                    f"[pqxdh-init <- {peer_display_name}] bootstrap received for session "
                    f"{result_contract['session_id']}"
                ),
                (
                    f"[pqxdh-ack -> {peer_display_name}] seq={result_contract['response_sequence']} "
                    f"msg={result_contract['response_message_number']} "
                    f"ratchet={result_contract['response_ratchet_generation']}"
                ),
            )

        return (
            None,
            None,
            (
                f"[pqxdh-ack <- {peer_display_name}] bootstrap acknowledged for session "
                f"{result_contract['session_id']}"
            ),
        )
