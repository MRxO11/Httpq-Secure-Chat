import asyncio
import json
from dataclasses import dataclass
from typing import Any

import websockets

try:
    from .direct_frames import DirectApplicationFrame, DirectControlFrame
    from .network_privacy import (
        build_cover_payload,
        unwrap_direct_application_payload,
        unwrap_direct_control_payload,
        wrap_direct_application_payload,
        wrap_direct_control_payload,
    )
except ImportError:
    from direct_frames import DirectApplicationFrame, DirectControlFrame
    from network_privacy import (
        build_cover_payload,
        unwrap_direct_application_payload,
        unwrap_direct_control_payload,
        wrap_direct_application_payload,
        wrap_direct_control_payload,
    )


@dataclass
class RelayConfig:
    ws_url: str
    room_id: str
    username: str


class RelayClient:
    def __init__(self, config: RelayConfig) -> None:
        self.config = config
        self._conn: Any = None
        self._lock = asyncio.Lock()

    async def connect(self) -> None:
        self._conn = await websockets.connect(self.config.ws_url)

    async def recv(self) -> dict[str, Any]:
        if self._conn is None:
            raise RuntimeError("relay connection is not established")

        raw = await self._conn.recv()
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        event = json.loads(raw)
        event_type = str(event.get("type", ""))
        payload = event.get("payload")
        if event_type == "msg/direct" and isinstance(payload, str):
            event["payload"] = unwrap_direct_application_payload(payload)
        elif event_type == "msg/direct-control" and isinstance(payload, str):
            event["payload"] = unwrap_direct_control_payload(payload)
        return event

    async def send(self, payload: dict[str, Any]) -> None:
        if self._conn is None:
            raise RuntimeError("relay connection is not established")

        async with self._lock:
            await self._conn.send(json.dumps(payload))

    async def join(
        self,
        room_id: str | None = None,
        username: str | None = None,
        direct_key: str | None = None,
        direct_signing_key: str | None = None,
        direct_signature: str | None = None,
    ) -> None:
        if room_id:
            self.config.room_id = room_id
        if username:
            self.config.username = username

        payload = {
            "type": "room/join",
            "roomId": self.config.room_id,
            "username": self.config.username,
        }
        if direct_key:
            payload["directKey"] = direct_key
        if direct_signing_key:
            payload["directSigningKey"] = direct_signing_key
        if direct_signature:
            payload["directSignature"] = direct_signature

        await self.send(payload)

    async def leave(self) -> None:
        await self.send({"type": "room/leave"})

    async def send_message(self, payload: str) -> None:
        await self.send({"type": "msg/send", "payload": payload})

    async def send_room_control(self, payload: dict[str, Any]) -> None:
        await self.send(
            {
                "type": "msg/room-control",
                "payload": json.dumps(payload, separators=(",", ":")),
            }
        )

    async def send_direct_message(self, target_client_id: str, payload: str) -> None:
        await self.send_direct_application(
            DirectApplicationFrame(target_client_id=target_client_id, payload=payload)
        )

    async def send_direct_application(self, frame: DirectApplicationFrame) -> None:
        frame.validate()
        await self.send(
            {
                "type": "msg/direct",
                "targetClientId": frame.target_client_id,
                "targetRouteToken": frame.target_route_token,
                "payload": wrap_direct_application_payload(frame.payload),
            }
        )

    async def send_direct_control(self, target_client_id: str, payload: dict[str, Any]) -> None:
        await self.send_direct_control_frame(
            DirectControlFrame(target_client_id=target_client_id, payload=payload)
        )

    async def send_direct_control_frame(self, frame: DirectControlFrame) -> None:
        frame.validate()
        await self.send(
            {
                "type": "msg/direct-control",
                "targetClientId": frame.target_client_id,
                "targetRouteToken": frame.target_route_token,
                "payload": wrap_direct_control_payload(frame.payload),
            }
        )

    async def send_client_hello(self, client_nonce: str) -> None:
        await self.send({"type": "auth/client-hello", "clientNonce": client_nonce})

    async def send_cover(self) -> None:
        await self.send({"type": "msg/cover", "payload": build_cover_payload()})

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None
