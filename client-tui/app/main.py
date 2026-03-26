import asyncio
import os
from datetime import datetime

from textual.app import App, ComposeResult
from textual.containers import Container
from textual.widgets import Footer, Header, Input, RichLog, Static

try:
    from .chat_session_controller import ChatSessionController, ChatSessionControllerError
    from .client_app_controller import ClientAppController, ClientAppControllerError
    from .client_session_adapter import ClientSessionAdapter, ClientSessionAdapterError
    from .direct_adapter import DirectAdapterError, DirectMessageAdapter
    from .direct_crypto import DirectCipher
    from .direct_identity import DirectIdentityStore
    from .direct_session import DirectSessionStore
    from .httpq_client import HTTPQVerifier
    from .network_privacy import cover_traffic_enabled, cover_traffic_interval_seconds
    from .peer_pin_store import PeerPinStore
    from .pin_store import PinStore
    from .relay_event_coordinator import RelayEventCoordinator
    from .relay_client import RelayClient, RelayConfig
    from .runtime_policy import is_direct_only_mode, room_messaging_allowed
    from .runtime_state import runtime_state_path, runtime_state_profile
    from .room_control import PortableRoomControlEvent
    from .room_crypto import RoomCipher
    from .room_state import RoomStateStore
    from .trust_adapter import TrustAdapter, TrustAdapterError
    from .ui_privacy import hide_ui_metadata, show_protocol_details
except ImportError:
    from chat_session_controller import ChatSessionController, ChatSessionControllerError
    from client_app_controller import ClientAppController, ClientAppControllerError
    from client_session_adapter import ClientSessionAdapter, ClientSessionAdapterError
    from direct_adapter import DirectAdapterError, DirectMessageAdapter
    from direct_crypto import DirectCipher
    from direct_identity import DirectIdentityStore
    from direct_session import DirectSessionStore
    from httpq_client import HTTPQVerifier
    from network_privacy import cover_traffic_enabled, cover_traffic_interval_seconds
    from peer_pin_store import PeerPinStore
    from pin_store import PinStore
    from relay_event_coordinator import RelayEventCoordinator
    from relay_client import RelayClient, RelayConfig
    from runtime_policy import is_direct_only_mode, room_messaging_allowed
    from runtime_state import runtime_state_path, runtime_state_profile
    from room_control import PortableRoomControlEvent
    from room_crypto import RoomCipher
    from room_state import RoomStateStore
    from trust_adapter import TrustAdapter, TrustAdapterError
    from ui_privacy import hide_ui_metadata, show_protocol_details


class SecureChatTUI(App):
    CSS = """
    Screen {
        layout: vertical;
        background: #09111f;
        color: #e5eefc;
    }

    Container {
        height: 1fr;
    }

    #status {
        height: 3;
        padding: 1;
        background: #14213d;
        color: #dbe7ff;
    }

    #messages {
        height: 1fr;
        border: round #4f8cff;
        background: #0f172a;
    }
    """

    BINDINGS = [("ctrl+c", "quit", "Quit")]

    def __init__(self) -> None:
        super().__init__()
        self.config = RelayConfig(
            ws_url=os.getenv("RELAY_WS_URL", "ws://127.0.0.1:8443/ws"),
            room_id=os.getenv("CHAT_ROOM", "lobby"),
            username=os.getenv("CHAT_NAME", "anonymous"),
        )
        self.state_profile = runtime_state_profile(self.config.username)
        self.relay = RelayClient(self.config)
        self.pin_store = PinStore(path=runtime_state_path("relay-pins.json", self.config.username))
        self.httpq = HTTPQVerifier(self.config.ws_url, self.pin_store)
        self.trust_adapter = TrustAdapter(self.httpq)
        self.direct_identity = DirectIdentityStore(
            path=runtime_state_path("direct-identity.json", self.config.username)
        ).load_or_create()
        self.direct_sessions = DirectSessionStore(
            path=runtime_state_path("direct-sessions.json", self.config.username)
        )
        self.direct_cipher = DirectCipher(
            self.direct_identity.encryption_private_key,
            self.direct_identity.signing_private_key,
        )
        self.direct_adapter = DirectMessageAdapter(self.direct_cipher, self.direct_sessions)
        self.chat_sessions = ChatSessionController(self.direct_adapter)
        self.room_cipher = RoomCipher()
        self.session_adapter = ClientSessionAdapter(
            trust=self.trust_adapter,
            direct=self.direct_adapter,
            direct_cipher=self.direct_cipher,
            room_cipher=self.room_cipher,
            peer_pin_store=PeerPinStore(
                path=runtime_state_path("peer-pins.json", self.config.username)
            ),
        )
        self.app_controller = ClientAppController(
            self.session_adapter,
            room_state_store=RoomStateStore(
                path=runtime_state_path("room-state.json", self.config.username)
            ),
        )
        self.relay_events = RelayEventCoordinator(trust=self.trust_adapter, app=self.app_controller)
        self.listener_task: asyncio.Task | None = None
        self.cover_traffic_task: asyncio.Task | None = None
        self.connected = False
        self.httpq_ready = False
        self.httpq_verified = False
        self.client_id = "unknown"
        self.direct_only_mode = is_direct_only_mode()
        self.hide_metadata = hide_ui_metadata()
        self.show_protocol_details = show_protocol_details()
        self.cover_traffic_enabled = cover_traffic_enabled()
        self.cover_traffic_interval_seconds = cover_traffic_interval_seconds()

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("", id="status")
        with Container():
            yield RichLog(id="messages", wrap=True, markup=False)
            yield Input(
                placeholder="/dm NICKNAME_OR_CLIENT_ID msg, /peers, /join room, /name alice"
            )
        yield Footer()

    async def on_mount(self) -> None:
        self.update_status("connecting")
        self.write_log("Connecting to relay...")
        if self.direct_only_mode:
            self.write_log(
                "Discovery-only room mode is enabled. Rooms are used for peer discovery; "
                "use /dm for secure 1-to-1 messages."
            )
        if self.hide_metadata:
            self.write_log("UI metadata redaction is enabled for normal chat usage.")
        if self.cover_traffic_enabled:
            self.write_log(
                f"Cover traffic is enabled every {self.cover_traffic_interval_seconds:g}s."
            )
            self.cover_traffic_task = asyncio.create_task(self.cover_traffic_loop())
        await self.connect_to_relay()

    async def on_unmount(self) -> None:
        if self.listener_task is not None:
            self.listener_task.cancel()
        if self.cover_traffic_task is not None:
            self.cover_traffic_task.cancel()
        await self.relay.close()

    async def connect_to_relay(self) -> None:
        try:
            await self.relay.connect()
            self.connected = True
            self.write_log(f"Connected to {self.config.ws_url}")
            self.listener_task = asyncio.create_task(self.listen_loop())
        except Exception as exc:
            self.connected = False
            self.write_log(f"Connection failed: {exc}")
            self.update_status("disconnected")

    async def listen_loop(self) -> None:
        try:
            while True:
                event = await self.relay.recv()
                await self.handle_event(event)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.connected = False
            self.write_log(f"Relay listener stopped: {exc}")
            self.update_status("disconnected")

    async def cover_traffic_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(self.cover_traffic_interval_seconds)
                if not self.cover_traffic_enabled or not self.connected or not self.httpq_verified:
                    continue
                await self.relay.send_cover()
        except asyncio.CancelledError:
            raise

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
                username=self.config.username,
                room_id=self.config.room_id,
            )
            for line in outcome.logs:
                self.write_log(self._render_log_for_ui(line))
            for notice in outcome.notices:
                self.write_log(self._render_notice_for_ui(notice))
            for traffic in outcome.traffic_messages:
                self.write_log(self._render_traffic_for_ui(traffic))
            if outcome.assigned_client_id is not None:
                self.client_id = outcome.assigned_client_id
                self.httpq_ready = True
                self.httpq_verified = True
            if outcome.client_nonce is not None:
                await self.relay.send_client_hello(outcome.client_nonce)
            if outcome.join_request is not None:
                await self.relay.join(
                    direct_key=outcome.join_request.direct_key,
                    direct_signing_key=outcome.join_request.direct_signing_key,
                    direct_signature=outcome.join_request.direct_signature,
                )
            if outcome.close_connection:
                self.httpq_ready = False
                self.httpq_verified = False
                await self.relay.close()
            if outcome.status is not None:
                self.update_status(outcome.status)
            if outcome.handled:
                return

        if event_type == "msg/direct":
            sender_route_token = str(event.get("senderRouteToken", ""))
            peer = (
                self.app_controller.get_peer_by_route_token(sender_route_token)
                or self.app_controller.get_peer(event.get("clientId", ""))
                or {}
            )
            peer_client_id = peer.get("clientId", event.get("clientId", ""))
            username = peer.get("username", event.get("username", peer_client_id or "unknown"))
            expected_signing_key = peer.get("directSigningKey", "")
            try:
                inbound = self.chat_sessions.handle_inbound_direct(
                    peer_client_id=peer_client_id,
                    peer_display_name=peer.get("username", peer_client_id) or peer_client_id,
                    payload=event.get("payload", ""),
                    room_id=event.get("roomId", self.config.room_id),
                    target_client_id=event.get("targetClientId", self.client_id),
                    peer_route_token=peer.get("directRouteToken"),
                    expected_signing_key_b64=expected_signing_key or None,
                )
                if inbound.bootstrap_log:
                    self.write_log(
                        self._render_protocol_log_for_ui(
                            inbound.bootstrap_log,
                            default=f"Secure session initialized with {peer.get('username', event.get('clientId', 'peer')) or event.get('clientId', 'peer')}.",
                        )
                    )
                if inbound.ack_frame is not None:
                    await self.relay.send_direct_control_frame(inbound.ack_frame)
                if inbound.ack_log:
                    self.write_log(
                        self._render_protocol_log_for_ui(
                            inbound.ack_log,
                            default=f"Secure session ready with {peer.get('username', event.get('clientId', 'peer')) or event.get('clientId', 'peer')}.",
                        )
                    )
                if inbound.decrypted.plaintext:
                    self.write_log(self._render_traffic_for_ui(inbound.traffic_message))
            except ChatSessionControllerError as exc:
                self.write_log(f"[dm] {username}: [encrypted payload: {exc}]")
            return

        if event_type == "msg/direct-control":
            sender_route_token = str(event.get("senderRouteToken", ""))
            peer = (
                self.app_controller.get_peer_by_route_token(sender_route_token)
                or self.app_controller.get_peer(event.get("clientId", ""))
                or {}
            )
            peer_client_id = peer.get("clientId", event.get("clientId", ""))
            try:
                result = self.chat_sessions.handle_inbound_control(
                    local_client_id=self.client_id,
                    peer_client_id=peer_client_id,
                    peer_display_name=peer.get("username", peer_client_id) or peer_client_id,
                    room_id=self.config.room_id,
                    payload=event.get("payload", ""),
                    peer_route_token=peer.get("directRouteToken"),
                )
                if result.bootstrap_log:
                    self.write_log(
                        self._render_protocol_log_for_ui(
                            result.bootstrap_log,
                            default=f"Secure session initialized with {peer.get('username', peer_client_id) or peer_client_id}.",
                        )
                    )
                if result.ack_frame is not None:
                    await self.relay.send_direct_control_frame(result.ack_frame)
                if result.ack_log:
                    self.write_log(
                        self._render_protocol_log_for_ui(
                            result.ack_log,
                            default=f"Secure session ready with {peer.get('username', peer_client_id) or peer_client_id}.",
                        )
                    )
            except ChatSessionControllerError as exc:
                self.write_log(f"[dm-control] {event.get('username', peer_client_id)}: {exc}")
            return

        if event_type == "sys/error":
            self.write_log(f"Server error: {event.get('error', 'unknown error')}")
            return

        self.write_log(f"Unhandled event: {event}")

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        value = event.value.strip()
        event.input.value = ""
        if not value:
            return

        if value.startswith("/"):
            await self.handle_command(value)
            return

        if not self.connected:
            self.write_log("Not connected to the relay.")
            return

        if not room_messaging_allowed():
            self.write_log(
                "Rooms are for discovery only in this profile. Use /dm NICKNAME_OR_CLIENT_ID MESSAGE."
            )
            return

        try:
            outbound = self.app_controller.encrypt_room_message(
                room_id=self.config.room_id,
                plaintext=value,
            )
        except ClientAppControllerError as exc:
            self.write_log(f"Cannot send message: {exc}")
            self.write_log("Set a room key with /key YOUR_SECRET")
            return

        await self.relay.send_message(outbound.payload)
        self.write_log(self._render_traffic_for_ui(outbound.traffic_message))

    async def handle_command(self, command_line: str) -> None:
        parts = command_line.split(maxsplit=1)
        command = parts[0].lower()
        argument = parts[1].strip() if len(parts) > 1 else ""

        if command == "/help":
            self.write_log(
                "Commands: /join ROOM, /leave, /name NAME, /peers, /verify HANDLE, /trust-reset HANDLE, /dm HANDLE MSG, /help"
            )
            if room_messaging_allowed():
                self.write_log(
                    "Developer-only room commands: /key SECRET, /room-epoch, "
                    "/room-propose CLIENT_ID, /room-commit, /room-welcome CLIENT_ID"
                )
            else:
                self.write_log(
                    "Rooms are discovery-only by default. Set "
                    "EXPERIMENTAL_ROOMS_ENABLED=1 only for developer testing."
                )
            return

        if command == "/join":
            room_id = argument or "lobby"
            join_request = self.app_controller.build_join_request(
                client_id=self.client_id,
                username=self.config.username,
                room_id=room_id,
            )
            await self.relay.join(
                room_id=join_request.room_id,
                direct_key=join_request.direct_key,
                direct_signing_key=join_request.direct_signing_key,
                direct_signature=join_request.direct_signature,
            )
            self.write_log(f"Joining room {room_id}...")
            self.update_status("connected")
            return

        if command == "/leave":
            await self.relay.leave()
            self.write_log("Leaving current room...")
            return

        if command == "/name":
            if not argument:
                self.write_log("Usage: /name YOUR_NAME")
                return

            self.config.username = argument
            self.write_log(f"Display name set to {argument}")
            if self.connected:
                join_request = self.app_controller.build_join_request(
                    client_id=self.client_id,
                    username=argument,
                    room_id=self.config.room_id,
                )
                await self.relay.join(
                    username=join_request.username,
                    direct_key=join_request.direct_key,
                    direct_signing_key=join_request.direct_signing_key,
                    direct_signature=join_request.direct_signature,
                )
            return

        if command == "/key":
            if not room_messaging_allowed():
                self.write_log(
                    "Rooms are discovery-only in this profile. Set "
                    "EXPERIMENTAL_ROOMS_ENABLED=1 only for developer testing."
                )
                return
            if not argument:
                self.write_log("Usage: /key ROOM_SECRET")
                return

            self.app_controller.set_room_key(room_id=self.config.room_id, secret=argument)
            self.write_log(f"Room key set for {self.config.room_id}")
            self.update_status("key-updated")
            return

        if command == "/room-epoch":
            if not room_messaging_allowed():
                self.write_log("Rooms are discovery-only in this profile.")
                return
            try:
                control = self.app_controller.prepare_room_epoch_update(
                    room_id=self.config.room_id,
                    sender_client_id=self.client_id,
                )
            except ClientAppControllerError as exc:
                self.write_log(f"Cannot advance room epoch: {exc}")
                return
            await self.relay.send_room_control(control.payload)
            portable = PortableRoomControlEvent.from_room_control_plan(control)
            self.write_log(
                f"[room-control -> room] epoch={portable.epoch} "
                f"key={portable.epoch_key_ref or 'none'}"
            )
            return

        if command == "/room-propose":
            if not room_messaging_allowed():
                self.write_log("Rooms are discovery-only in this profile.")
                return
            if not argument:
                self.write_log("Usage: /room-propose CLIENT_ID")
                return
            try:
                control = self.app_controller.prepare_room_proposal(
                    room_id=self.config.room_id,
                    sender_client_id=self.client_id,
                    target_client_id=argument,
                )
            except ClientAppControllerError as exc:
                self.write_log(f"Cannot create room proposal: {exc}")
                return
            await self.relay.send_room_control(control.payload)
            portable = PortableRoomControlEvent.from_room_control_plan(control)
            self.write_log(
                f"[room-proposal -> room] target={argument} "
                f"epoch={portable.epoch}"
            )
            return

        if command == "/room-commit":
            if not room_messaging_allowed():
                self.write_log("Rooms are discovery-only in this profile.")
                return
            try:
                control = self.app_controller.prepare_room_commit(
                    room_id=self.config.room_id,
                    sender_client_id=self.client_id,
                )
            except ClientAppControllerError as exc:
                self.write_log(f"Cannot commit room update: {exc}")
                return
            await self.relay.send_room_control(control.payload)
            portable = PortableRoomControlEvent.from_room_control_plan(control)
            self.write_log(
                f"[room-commit -> room] epoch={portable.epoch} "
                f"key={portable.epoch_key_ref or 'none'}"
            )
            return

        if command == "/room-welcome":
            if not room_messaging_allowed():
                self.write_log("Rooms are discovery-only in this profile.")
                return
            if not argument:
                self.write_log("Usage: /room-welcome CLIENT_ID")
                return
            try:
                control = self.app_controller.prepare_room_welcome(
                    room_id=self.config.room_id,
                    sender_client_id=self.client_id,
                    recipient_client_id=argument,
                )
            except ClientAppControllerError as exc:
                self.write_log(f"Cannot prepare room welcome: {exc}")
                return
            await self.relay.send_room_control(control.payload)
            portable = PortableRoomControlEvent.from_room_control_plan(control)
            self.write_log(
                f"[room-welcome -> room] recipient={argument} "
                f"epoch={portable.epoch}"
            )
            return

        if command == "/peers":
            if self.app_controller.peer_count() == 0:
                self.write_log("No peers known in the current room yet.")
                return
            for peer in self.app_controller.peer_values():
                self.write_log(
                    self._render_peer_for_ui(peer)
                )
            return

        if command == "/verify":
            if not argument:
                self.write_log("Usage: /verify NICKNAME_OR_CLIENT_ID")
                return
            try:
                peer = self.app_controller.resolve_peer(argument)
            except ClientAppControllerError as exc:
                self.write_log(str(exc))
                return
            if peer is None:
                self.write_log(f"Unknown peer: {argument}")
                return
            safety_number = self.app_controller.peer_safety_number(peer)
            if safety_number is None:
                self.write_log(f"Peer {argument} does not have a complete verified identity yet.")
                return
            self.write_log(
                f"Safety number for {peer.get('username', peer.get('clientId', argument))}: {safety_number}"
            )
            self.write_log("Compare this safety number out-of-band for this session if needed.")
            return

        if command == "/trust-reset":
            if not argument:
                self.write_log("Usage: /trust-reset NICKNAME_OR_CLIENT_ID")
                return
            try:
                peer = self.app_controller.resolve_peer(argument)
            except ClientAppControllerError as exc:
                self.write_log(str(exc))
                return
            if peer is None:
                self.write_log(f"Unknown peer: {argument}")
                return
            try:
                removed = self.app_controller.reset_peer_trust(
                    peer,
                    room_id=self.config.room_id,
                )
            except ClientAppControllerError as exc:
                self.write_log(str(exc))
                return
            if removed:
                self.write_log(
                    f"Trust reset for {peer.get('username', peer.get('clientId', argument))}. "
                    "The next verified identity will be pinned as new."
                )
            else:
                self.write_log(
                    f"No existing trust pin found for {peer.get('username', peer.get('clientId', argument))}."
                )
            return

        if command == "/dm":
            bits = argument.split(maxsplit=1)
            if len(bits) != 2:
                self.write_log("Usage: /dm NICKNAME_OR_CLIENT_ID MESSAGE")
                return
            target_handle, message = bits
            try:
                peer = self.app_controller.resolve_peer(target_handle)
            except ClientAppControllerError as exc:
                self.write_log(str(exc))
                return
            if peer is None:
                self.write_log(f"Unknown peer: {target_handle}")
                return
            target_client_id = peer.get("clientId", "")
            direct_key = peer.get("directKey", "")
            if not direct_key:
                self.write_log(f"Peer {target_client_id} has no direct key published")
                return
            try:
                outbound = self.chat_sessions.prepare_outbound_direct(
                    local_client_id=self.client_id,
                    peer_client_id=target_client_id,
                    peer_display_name=peer.get("username", target_client_id),
                    peer_encryption_public_key_b64=direct_key,
                    peer_route_token=peer.get("directRouteToken"),
                    room_id=self.config.room_id,
                    plaintext=message,
                )
            except ChatSessionControllerError as exc:
                self.write_log(f"Cannot send direct message: {exc}")
                return
            if outbound.control_frame is not None:
                await self.relay.send_direct_control_frame(outbound.control_frame)
                self.write_log(
                    self._render_protocol_log_for_ui(
                        f"[pqxdh-init -> {outbound.target_display_name}] sent over direct-control channel",
                        default=f"Secure session bootstrap sent to {outbound.target_display_name}.",
                    )
                )
            await self.relay.send_direct_application(outbound.application_frame)
            self.write_log(self._render_traffic_for_ui(outbound.traffic_message))
            return

        self.write_log(f"Unknown command: {command}")

    def update_status(self, state: str) -> None:
        status = self.query_one("#status", Static)
        relay_state = "Connected" if self.connected else "Disconnected"
        if self.httpq_verified:
            httpq_state = "verified"
        elif self.httpq_ready:
            httpq_state = "hello-ok"
        else:
            httpq_state = "pending"
        room_key_state = "set" if self.room_cipher.has_room_key(self.config.room_id) else "missing"
        profile = "DM-first" if self.direct_only_mode else "hybrid"
        status.update(
            f"{relay_state} | Relay: {self.config.ws_url} | Room: {self.config.room_id} | "
            f"Name: {self.config.username} | Peers: {self.app_controller.peer_count()} | "
            f"HTTPq: {httpq_state} | Profile: {profile} | RoomKey: {room_key_state} | State: {state}"
        )

    def write_log(self, message: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        log = self.query_one("#messages", RichLog)
        log.write(f"[{stamp}] {message}")

    def _fingerprint(self, key_b64: str) -> str:
        if not key_b64:
            return "unknown"
        short = key_b64[:12]
        return f"{short}..."

    def _render_peer_for_ui(self, peer: dict) -> str:
        username = str(peer.get("username", peer.get("clientId", "unknown")))
        if not self.hide_metadata:
            return (
                f"Peer: {username} "
                f"({peer.get('clientId', 'unknown')}) "
                f"fp={self._fingerprint(peer.get('directSigningKey', ''))}"
            )
        return f"Peer: {username}"

    def _render_notice_for_ui(self, notice) -> str:
        if not self.hide_metadata:
            return notice.render()
        message = notice.render()
        if notice.kind == "auth":
            if "Relay hello received" in message:
                return "Relay identity check started."
            if "verified" in message.lower():
                return "Relay identity verified."
        if notice.kind == "peer":
            if message.startswith("Peer available: "):
                return f"Peer available: {message.split(': ', 1)[1].split(' (', 1)[0]}"
            if message.startswith("Peer left: "):
                return f"Peer left: {message.split(': ', 1)[1].split(' (', 1)[0]}"
        if notice.kind == "room":
            if " members:" in message:
                return "Room membership updated."
            if " joined " in message:
                return f"{message.split(' joined ', 1)[0]} joined."
            if " left " in message:
                return f"{message.split(' left ', 1)[0]} left."
        return message

    def _render_traffic_for_ui(self, traffic) -> str:
        if not self.hide_metadata:
            return traffic.render()
        if traffic.metadata.conversation_kind == "direct":
            if traffic.outgoing:
                return f"[dm -> {traffic.display_name}] {traffic.plaintext}"
            return f"[dm] {traffic.display_name}: {traffic.plaintext}"
        if traffic.metadata.conversation_kind == "room":
            if traffic.outgoing:
                return f"[room -> room] {traffic.plaintext}"
            return f"[room] {traffic.display_name}: {traffic.plaintext}"
        return traffic.render()

    def _render_log_for_ui(self, message: str) -> str:
        if not self.hide_metadata:
            return message
        if message.startswith("room-control rejected:"):
            return "Room control rejected."
        return message

    def _render_protocol_log_for_ui(self, message: str, *, default: str) -> str:
        if self.show_protocol_details or not self.hide_metadata:
            return message
        return default

if __name__ == "__main__":
    SecureChatTUI().run()
