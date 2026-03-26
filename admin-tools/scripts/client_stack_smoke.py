import argparse
import asyncio
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CLIENT_TUI_ROOT = REPO_ROOT / "client-tui"
if str(CLIENT_TUI_ROOT) not in sys.path:
    sys.path.insert(0, str(CLIENT_TUI_ROOT))

from app.chat_session_controller import ChatSessionController, ChatSessionControllerError  # noqa: E402
from app.client_app_controller import ClientAppController  # noqa: E402
from app.client_app_controller import ClientAppControllerError  # noqa: E402
from app.client_session_adapter import ClientSessionAdapter  # noqa: E402
from app.direct_adapter import DirectMessageAdapter  # noqa: E402
from app.direct_crypto import DirectCipher  # noqa: E402
from app.direct_identity import DirectIdentityStore  # noqa: E402
from app.direct_session import DirectSessionStore  # noqa: E402
from app.httpq_client import HTTPQVerifier  # noqa: E402
from app.peer_pin_store import PeerPinStore  # noqa: E402
from app.pin_store import PinStore  # noqa: E402
from app.relay_client import RelayClient, RelayConfig  # noqa: E402
from app.relay_event_coordinator import RelayEventCoordinator  # noqa: E402
from app.room_crypto import RoomCipher  # noqa: E402
from app.trust_adapter import TrustAdapter  # noqa: E402


class ClientStackSmokeError(Exception):
    pass


class HeadlessClient:
    def __init__(
        self,
        *,
        name: str,
        room_id: str,
        ws_url: str,
        state_dir: Path,
        send_ratchet_rotation_interval: int | None = None,
    ) -> None:
        self.name = name
        self.room_id = room_id
        self.ws_url = ws_url
        self.logs: list[str] = []
        self.room_messages: list[str] = []
        self.direct_messages: list[str] = []
        self.client_id = "unknown"
        self.connected = False
        self.httpq_verified = False

        config = RelayConfig(ws_url=ws_url, room_id=room_id, username=name)
        self.relay = RelayClient(config)
        pin_store = PinStore(path=str(state_dir / "relay-pins.json"))
        httpq = HTTPQVerifier(ws_url, pin_store)
        trust = TrustAdapter(httpq)
        identity = DirectIdentityStore(path=str(state_dir / "direct-identity.json")).load_or_create()
        sessions = DirectSessionStore(
            path=str(state_dir / "direct-sessions.json"),
            max_skipped_message_keys=32,
        )
        if send_ratchet_rotation_interval is not None:
            sessions.send_ratchet_rotation_interval = send_ratchet_rotation_interval
        direct_cipher = DirectCipher(identity.encryption_private_key, identity.signing_private_key)
        direct_adapter = DirectMessageAdapter(direct_cipher, sessions)
        room_cipher = RoomCipher()
        session_adapter = ClientSessionAdapter(
            trust=trust,
            direct=direct_adapter,
            direct_cipher=direct_cipher,
            room_cipher=room_cipher,
            peer_pin_store=PeerPinStore(path=str(state_dir / "peer-pins.json")),
        )
        self.app_controller = ClientAppController(session_adapter)
        self.chat_sessions = ChatSessionController(direct_adapter)
        self.relay_events = RelayEventCoordinator(trust=trust, app=self.app_controller)

    async def connect(self) -> None:
        await self.relay.connect()
        self.connected = True

    async def close(self) -> None:
        await self.relay.close()
        self.connected = False

    def set_room_key(self, secret: str) -> None:
        self.app_controller.set_room_key(room_id=self.room_id, secret=secret)

    async def pump_once(self, timeout: float = 5.0) -> dict:
        event = await asyncio.wait_for(self.relay.recv(), timeout=timeout)
        await self.handle_event(event)
        return event

    async def pump_until(self, predicate, timeout: float = 8.0) -> dict:
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise ClientStackSmokeError(f"{self.name} timed out waiting for event condition")
            event = await self.pump_once(timeout=remaining)
            if predicate(event):
                return event

    async def send_room_message(self, plaintext: str) -> None:
        outbound = self.app_controller.encrypt_room_message(
            room_id=self.room_id,
            plaintext=plaintext,
        )
        await self.relay.send_message(outbound.payload)

    async def prepare_and_send_room_epoch_update(self) -> tuple[dict, object]:
        control = self.app_controller.prepare_room_epoch_update(
            room_id=self.room_id,
            sender_client_id=self.client_id,
        )
        await self.relay.send_room_control(control.payload)
        return control.payload, self.app_controller.room_snapshot(self.room_id)

    async def send_direct_message(self, target_client_id: str, plaintext: str) -> str:
        peer = self.app_controller.get_peer(target_client_id)
        if peer is None:
            raise ClientStackSmokeError(f"{self.name} does not know peer {target_client_id}")
        outbound = self.chat_sessions.prepare_outbound_direct(
            local_client_id=self.client_id,
            peer_client_id=target_client_id,
            peer_display_name=peer.get("username", target_client_id),
            peer_encryption_public_key_b64=peer.get("directKey", ""),
            peer_route_token=peer.get("directRouteToken"),
            room_id=self.room_id,
            plaintext=plaintext,
        )
        if outbound.control_frame is not None:
            await self.relay.send_direct_control_frame(outbound.control_frame)
        await self.relay.send_direct_application(outbound.application_frame)
        return outbound.application_frame.payload

    def session_snapshot(self, peer_client_id: str):
        return self.chat_sessions.direct.session_snapshot(peer_client_id)

    async def handle_event(self, event: dict) -> None:
        event_type = event.get("type", "unknown")

        if event_type in {
            "auth/hello",
            "auth/proof",
            "peer/snapshot",
            "peer/upsert",
            "peer/left",
            "room/joined",
            "room/left",
            "room/snapshot",
            "msg/opaque",
            "msg/room-control",
        }:
            outcome = self.relay_events.handle_event(
                event=event,
                client_id=self.client_id,
                username=self.name,
                room_id=self.room_id,
            )
            self.logs.extend(outcome.logs)
            for notice in outcome.notices:
                self.logs.append(notice.render())
            for line in outcome.logs:
                if ": " in line and not line.startswith("Peer ") and not line.startswith("Relay "):
                    self.room_messages.append(line)
            for traffic in outcome.traffic_messages:
                rendered = traffic.render()
                self.logs.append(rendered)
                if traffic.metadata.conversation_kind == "room":
                    self.room_messages.append(rendered)
            if outcome.assigned_client_id is not None:
                self.client_id = outcome.assigned_client_id
                self.httpq_verified = True
            if outcome.client_nonce is not None:
                await self.relay.send_client_hello(outcome.client_nonce)
            if outcome.join_request is not None:
                await self.relay.join(
                    room_id=outcome.join_request.room_id,
                    username=outcome.join_request.username,
                    direct_key=outcome.join_request.direct_key,
                    direct_signing_key=outcome.join_request.direct_signing_key,
                    direct_signature=outcome.join_request.direct_signature,
                )
            if outcome.close_connection:
                await self.relay.close()
            return

        if event_type == "msg/direct":
            sender_route_token = str(event.get("senderRouteToken", ""))
            peer = (
                self.app_controller.get_peer_by_route_token(sender_route_token)
                or self.app_controller.get_peer(event.get("clientId", ""))
                or {}
            )
            peer_client_id = peer.get("clientId", event.get("clientId", ""))
            inbound = self.chat_sessions.handle_inbound_direct(
                peer_client_id=peer_client_id,
                peer_display_name=peer.get("username", peer_client_id) or peer_client_id,
                payload=event.get("payload", ""),
                room_id=event.get("roomId", self.room_id),
                target_client_id=event.get("targetClientId", self.client_id),
                peer_route_token=peer.get("directRouteToken"),
                expected_signing_key_b64=peer.get("directSigningKey") or None,
            )
            if inbound.ack_frame is not None:
                await self.relay.send_direct_control_frame(inbound.ack_frame)
            if inbound.decrypted.plaintext:
                self.direct_messages.append(inbound.decrypted.plaintext)
            return

        if event_type == "msg/direct-control":
            sender_route_token = str(event.get("senderRouteToken", ""))
            peer = (
                self.app_controller.get_peer_by_route_token(sender_route_token)
                or self.app_controller.get_peer(event.get("clientId", ""))
                or {}
            )
            peer_client_id = peer.get("clientId", event.get("clientId", ""))
            result = self.chat_sessions.handle_inbound_control(
                local_client_id=self.client_id,
                peer_client_id=peer_client_id,
                peer_display_name=peer.get("username", peer_client_id) or peer_client_id,
                room_id=self.room_id,
                payload=event.get("payload", ""),
                peer_route_token=peer.get("directRouteToken"),
            )
            if result.ack_frame is not None:
                await self.relay.send_direct_control_frame(result.ack_frame)
            return

        if event_type == "sys/error":
            raise ClientStackSmokeError(f"{self.name} got relay error: {event.get('error', 'unknown')}")

    async def wait_for_peer(self, peer_client_id: str, timeout: float = 8.0) -> None:
        if self.app_controller.get_peer(peer_client_id) is not None:
            return
        await self.pump_until(
            lambda _event: self.app_controller.get_peer(peer_client_id) is not None,
            timeout=timeout,
        )

    async def wait_for_room_message(self, plaintext: str, timeout: float = 8.0) -> None:
        if any(entry.endswith(f": {plaintext}") for entry in self.room_messages):
            return
        await self.pump_until(
            lambda _event: any(entry.endswith(f": {plaintext}") for entry in self.room_messages),
            timeout=timeout,
        )

    async def wait_for_direct_message(self, plaintext: str, timeout: float = 8.0) -> None:
        if plaintext in self.direct_messages:
            return
        await self.pump_until(
            lambda _event: plaintext in self.direct_messages,
            timeout=timeout,
        )


async def drive_clients_until(
    clients: list[HeadlessClient],
    predicate,
    timeout: float = 8.0,
    description: str = "client-stack condition",
) -> None:
    if predicate():
        return

    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        if predicate():
            return

        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            details: list[str] = [f"timed out waiting for {description}"]
            for client in clients:
                peers = ", ".join(
                    sorted(peer.get("clientId", "?") for peer in client.app_controller.peer_values())
                ) or "none"
                recent_logs = " | ".join(client.logs[-6:]) or "no logs"
                details.append(
                    f"{client.name}: client_id={client.client_id} verified={client.httpq_verified} "
                    f"peers=[{peers}] logs=[{recent_logs}]"
                )
            raise ClientStackSmokeError(" ; ".join(details))

        progress = False
        for client in clients:
            try:
                await client.pump_once(timeout=min(0.5, remaining))
                progress = True
            except asyncio.TimeoutError:
                continue

        if not progress:
            await asyncio.sleep(0.05)


async def run_client_stack_smoke(
    ws_url: str,
    room_id: str,
    room_secret: str,
    send_ratchet_rotation_interval: int,
) -> None:
    with tempfile.TemporaryDirectory() as tempdir:
        state_root = Path(tempdir)
        alice = HeadlessClient(
            name="alice",
            room_id=room_id,
            ws_url=ws_url,
            state_dir=state_root / "alice",
            send_ratchet_rotation_interval=send_ratchet_rotation_interval,
        )
        bob = HeadlessClient(
            name="bob",
            room_id=room_id,
            ws_url=ws_url,
            state_dir=state_root / "bob",
            send_ratchet_rotation_interval=send_ratchet_rotation_interval,
        )
        alice.set_room_key(room_secret)
        bob.set_room_key(room_secret)

        await alice.connect()
        await bob.connect()

        try:
            await drive_clients_until(
                [alice, bob],
                lambda: (
                    alice.httpq_verified
                    and alice.client_id != "unknown"
                    and bob.httpq_verified
                    and bob.client_id != "unknown"
                ),
                description="both clients to complete HTTPq verification",
            )

            await drive_clients_until(
                [alice, bob],
                lambda: (
                    alice.app_controller.get_peer(bob.client_id) is not None
                    and bob.app_controller.get_peer(alice.client_id) is not None
                ),
                description="mutual peer discovery",
            )

            await alice.send_room_message("hello-room")
            await drive_clients_until(
                [alice, bob],
                lambda: any(entry.endswith(": hello-room") for entry in bob.room_messages),
                description="room message delivery to bob",
            )

            old_room_payload = alice.app_controller.encrypt_room_message(
                room_id=alice.room_id,
                plaintext="before-room-epoch",
            ).payload
            alice_room_before = alice.app_controller.room_snapshot(alice.room_id)
            bob_room_before = bob.app_controller.room_snapshot(bob.room_id)
            if alice_room_before.application_secret_ref != bob_room_before.application_secret_ref:
                raise ClientStackSmokeError("room application secrets diverged before epoch update")

            _, alice_room_after_local = await alice.prepare_and_send_room_epoch_update()
            await drive_clients_until(
                [alice, bob],
                lambda: (
                    bob.app_controller.room_snapshot(bob.room_id).epoch
                    >= alice_room_after_local.epoch
                ),
                description="room epoch update delivery to bob",
            )

            bob_room_after = bob.app_controller.room_snapshot(bob.room_id)
            if bob_room_after.application_secret_ref == bob_room_before.application_secret_ref:
                raise ClientStackSmokeError("room application secret did not rotate after epoch update")
            try:
                bob.app_controller.decrypt_room_message(payload=old_room_payload)
            except ClientAppControllerError:
                pass
            else:
                raise ClientStackSmokeError("stale room payload decrypted after epoch update")

            await alice.send_room_message("after-room-epoch")
            await drive_clients_until(
                [alice, bob],
                lambda: any(entry.endswith(": after-room-epoch") for entry in bob.room_messages),
                description="post-epoch room message delivery to bob",
            )

            await alice.send_direct_message(bob.client_id, "hello-direct")
            await drive_clients_until(
                [alice, bob],
                lambda: "hello-direct" in bob.direct_messages,
                description="direct message delivery to bob",
            )
            await drive_clients_until(
                [alice, bob],
                lambda: (
                    alice.session_snapshot(bob.client_id) is not None
                    and alice.session_snapshot(bob.client_id).bootstrap_ready
                ),
                description="alice direct bootstrap acknowledgement",
            )

            alice_session_before = alice.session_snapshot(bob.client_id)
            first_ratchet_key = alice_session_before.local_ratchet_public_key_b64

            await alice.send_direct_message(bob.client_id, "rotation-trigger")
            await drive_clients_until(
                [alice, bob],
                lambda: "rotation-trigger" in bob.direct_messages,
                description="second direct message delivery to bob",
            )

            await alice.send_direct_message(bob.client_id, "rotated-direct")
            await drive_clients_until(
                [alice, bob],
                lambda: "rotated-direct" in bob.direct_messages,
                description="rotated direct message delivery to bob",
            )

            alice_session_after = alice.session_snapshot(bob.client_id)
            bob_session_after = bob.session_snapshot(alice.client_id)
            if alice_session_after.local_ratchet_public_key_b64 == first_ratchet_key:
                raise ClientStackSmokeError("alice sender ratchet key did not rotate during client smoke")
            if bob_session_after.remote_ratchet_public_key_b64 != alice_session_after.local_ratchet_public_key_b64:
                raise ClientStackSmokeError("bob did not record alice rotated ratchet key during client smoke")

            print("client stack smoke test passed")
            print(f"alice={alice.client_id} bob={bob.client_id} room={room_id}")
        finally:
            await alice.close()
            await bob.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a headless client-stack smoke test")
    parser.add_argument("--ws-url", default="ws://127.0.0.1:8443/ws")
    parser.add_argument("--room-id", default="client-smoke")
    parser.add_argument("--room-secret", default="smoke-secret")
    parser.add_argument("--send-ratchet-rotation-interval", type=int, default=2)
    args = parser.parse_args()
    asyncio.run(
        run_client_stack_smoke(
            args.ws_url,
            args.room_id,
            args.room_secret,
            args.send_ratchet_rotation_interval,
        )
    )


if __name__ == "__main__":
    main()
