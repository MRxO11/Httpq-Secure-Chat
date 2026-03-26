from dataclasses import dataclass, field
from typing import Any

try:
    from .client_app_controller import ClientAppController, ClientAppControllerError, JoinRequest
    from .room_control import PortableRoomControlEvent
    from .traffic_events import RuntimeNotice, TrafficMessage
    from .trust_adapter import TrustAdapter, TrustAdapterError
except ImportError:
    from client_app_controller import ClientAppController, ClientAppControllerError, JoinRequest
    from room_control import PortableRoomControlEvent
    from traffic_events import RuntimeNotice, TrafficMessage
    from trust_adapter import TrustAdapter, TrustAdapterError


class RelayEventCoordinatorError(Exception):
    pass


@dataclass(frozen=True)
class RelayEventOutcome:
    logs: list[str] = field(default_factory=list)
    notices: list[RuntimeNotice] = field(default_factory=list)
    traffic_messages: list[TrafficMessage] = field(default_factory=list)
    status: str | None = None
    client_nonce: str | None = None
    join_request: JoinRequest | None = None
    assigned_client_id: str | None = None
    close_connection: bool = False
    handled: bool = False


class RelayEventCoordinator:
    def __init__(self, *, trust: TrustAdapter, app: ClientAppController) -> None:
        self.trust = trust
        self.app = app

    def handle_event(
        self,
        *,
        event: dict[str, Any],
        client_id: str,
        username: str,
        room_id: str,
    ) -> RelayEventOutcome:
        event_type = str(event.get("type", "unknown"))

        if event_type == "auth/hello":
            plan = self.trust.handle_server_hello(event)
            return RelayEventOutcome(
                handled=True,
                client_nonce=plan.client_nonce,
                status="authenticating",
                notices=[
                    RuntimeNotice(
                        kind="auth",
                        message=(
                            f"Relay hello received for realm '{plan.realm}' via relay id "
                            f"'{plan.relay_id}'. KT log: {plan.kt_log_url} Witness: {plan.witness_url}"
                        ),
                    )
                ],
            )

        if event_type == "auth/proof":
            try:
                result = self.trust.handle_server_proof(event)
                portable_result = result.from_contract_dict(result.to_contract_dict())
                join_request = self.app.build_join_request(
                    client_id=portable_result.client_id,
                    username=username,
                    room_id=room_id,
                )
            except (TrustAdapterError, ClientAppControllerError) as exc:
                return RelayEventOutcome(
                    handled=True,
                    status="verification-failed",
                    logs=[str(exc)],
                    close_connection=True,
                )
            return RelayEventOutcome(
                handled=True,
                status="connected",
                assigned_client_id=portable_result.client_id,
                join_request=join_request,
                notices=[
                    RuntimeNotice(
                        kind="auth",
                        message=(
                            "Relay identity, KT inclusion, and witness checkpoint verified. "
                            f"Assigned client id {portable_result.client_id}."
                        ),
                    )
                ],
            )

        if event_type == "peer/snapshot":
            result = self.app.apply_peer_snapshot(
                peers=event.get("peers", []),
                room_id=event.get("roomId", room_id),
            )
            return RelayEventOutcome(
                handled=True,
                logs=[f"Ignoring peer: {entry}" for entry in result.rejected],
                notices=[
                    RuntimeNotice(
                        kind="peer",
                        message=f"Peer snapshot loaded: {result.accepted_count} verified peer(s)",
                    )
                ],
            )

        if event_type == "peer/upsert":
            peer = event.get("peer", {})
            try:
                accepted = self.app.apply_peer_upsert(
                    peer=peer,
                    room_id=event.get("roomId", room_id),
                )
            except ClientAppControllerError as exc:
                client_id = peer.get("clientId", "")
                message = str(exc)
                if "security warning:" in message.lower():
                    message = message[0].upper() + message[1:]
                return RelayEventOutcome(
                    handled=True,
                    logs=[f"Ignoring peer {peer.get('username', client_id) or client_id}: {message}"],
                )
            client_id = accepted.get("clientId", "")
            safety_number = self.app.peer_safety_number(accepted)
            available_message = f"Peer available: {accepted.get('username', client_id)} ({client_id})"
            if safety_number is not None:
                available_message += f" safety={safety_number}"
            return RelayEventOutcome(
                handled=True,
                notices=[
                    RuntimeNotice(
                        kind="peer",
                        message=available_message,
                    )
                ],
            )

        if event_type == "peer/left":
            peer = event.get("peer", {})
            client_id = peer.get("clientId", "")
            if client_id:
                self.app.remove_peer(client_id)
            return RelayEventOutcome(
                handled=True,
                notices=[
                    RuntimeNotice(
                        kind="peer",
                        message=f"Peer left: {peer.get('username', client_id)} ({client_id})",
                    )
                ],
            )

        if event_type == "room/joined":
            user = event.get("username", event.get("clientId", "unknown"))
            joined_room = event.get("roomId", "?")
            member_ids = event.get("memberIds")
            if isinstance(member_ids, list):
                self.app.record_room_members(
                    room_id=str(joined_room),
                    member_count=len(member_ids),
                )
            return RelayEventOutcome(
                handled=True,
                notices=[RuntimeNotice(kind="room", message=f"{user} joined {joined_room}")],
                status="connected",
            )

        if event_type == "room/left":
            user = event.get("username", event.get("clientId", "unknown"))
            left_room = event.get("roomId", "?")
            member_ids = event.get("memberIds")
            if isinstance(member_ids, list):
                self.app.record_room_members(
                    room_id=str(left_room),
                    member_count=len(member_ids),
                )
            return RelayEventOutcome(
                handled=True,
                notices=[RuntimeNotice(kind="room", message=f"{user} left {left_room}")],
                status="connected",
            )

        if event_type == "room/snapshot":
            snapshot_room = event.get("roomId", "?")
            member_ids = event.get("memberIds", [])
            if isinstance(member_ids, list):
                self.app.record_room_members(
                    room_id=str(snapshot_room),
                    member_count=len(member_ids),
                )
            members = ", ".join(member_ids) or "nobody"
            return RelayEventOutcome(
                handled=True,
                notices=[RuntimeNotice(kind="room", message=f"Room {snapshot_room} members: {members}")],
                status="connected",
            )

        if event_type == "msg/opaque":
            username = event.get("username", event.get("clientId", "unknown"))
            payload = event.get("payload", "")
            try:
                inbound = self.app.decrypt_room_message(payload=payload)
                traffic = TrafficMessage(
                    metadata=inbound.metadata,
                    display_name=username,
                    plaintext=inbound.plaintext,
                )
            except ClientAppControllerError as exc:
                return RelayEventOutcome(
                    handled=True,
                    logs=[f"{username}: [encrypted payload: {exc}]"],
                )
            return RelayEventOutcome(handled=True, traffic_messages=[traffic])

        if event_type == "msg/room-control":
            payload = event.get("payload", {})
            if isinstance(payload, str):
                try:
                    import json

                    payload = json.loads(payload)
                except (TypeError, ValueError) as exc:
                    return RelayEventOutcome(
                        handled=True,
                        logs=[f"room-control parse failed: {exc}"],
                    )
            try:
                control = self.app.apply_room_control(payload=payload)
                portable_control = PortableRoomControlEvent.from_room_control_plan(control)
            except ClientAppControllerError as exc:
                return RelayEventOutcome(
                    handled=True,
                    logs=[f"room-control rejected: {exc}"],
                )
            return RelayEventOutcome(
                handled=True,
                notices=[
                    RuntimeNotice(
                        kind="room",
                        message=self._render_room_control_notice(portable_control),
                    )
                ],
            )

        return RelayEventOutcome(handled=False)

    def _render_room_control_notice(self, control: PortableRoomControlEvent) -> str:
        if control.message_type == "RoomProposal":
            return "Room proposal recorded and pending commit"
        if control.message_type == "RoomCommit":
            return (
                f"Room commit applied at epoch {control.epoch} "
                f"({control.epoch_key_ref or 'no-key-ref'})"
            )
        if control.message_type == "RoomWelcome":
            return (
                f"Room welcome applied at epoch {control.epoch} "
                f"({control.epoch_key_ref or 'no-key-ref'})"
            )
        return (
            f"Room epoch updated to {control.epoch} "
            f"({control.epoch_key_ref or 'no-key-ref'})"
        )
