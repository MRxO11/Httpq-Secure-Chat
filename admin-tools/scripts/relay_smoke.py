import argparse
import asyncio
import base64
import json
from dataclasses import dataclass
from typing import Any

import websockets


class SmokeTestError(Exception):
    pass


@dataclass
class SmokeClient:
    name: str
    room_id: str
    ws_url: str
    conn: Any | None = None
    client_id: str = ""

    async def connect(self) -> None:
        self.conn = await websockets.connect(self.ws_url)
        await self._authenticate()

    async def connect_raw(self) -> None:
        self.conn = await websockets.connect(self.ws_url)

    async def close(self) -> None:
        if self.conn is not None:
            await self.conn.close()
            self.conn = None

    async def join(self) -> None:
        await self.send(
            {
                "type": "room/join",
                "roomId": self.room_id,
                "username": self.name,
                "directKey": f"fake-direct-key-{self.name}",
                "directSigningKey": f"fake-signing-key-{self.name}",
                "directSignature": f"fake-signature-{self.name}",
            }
        )

    async def send(self, payload: dict[str, Any]) -> None:
        if self.conn is None:
            raise SmokeTestError(f"{self.name} is not connected")
        await self.conn.send(json.dumps(payload))

    async def recv(self, timeout: float = 5.0) -> dict[str, Any]:
        if self.conn is None:
            raise SmokeTestError(f"{self.name} is not connected")
        raw = await asyncio.wait_for(self.conn.recv(), timeout=timeout)
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        return json.loads(raw)

    async def wait_for_event(self, event_type: str, timeout: float = 5.0) -> dict[str, Any]:
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise SmokeTestError(f"{self.name} timed out waiting for {event_type}")
            event = await self.recv(timeout=remaining)
            if event.get("type") == event_type:
                return event

    async def wait_for_error(self, contains: str, timeout: float = 5.0) -> dict[str, Any]:
        event = await self.wait_for_event("sys/error", timeout=timeout)
        error = str(event.get("error", ""))
        if contains not in error:
            raise SmokeTestError(
                f"{self.name} expected sys/error containing {contains!r}, got {error!r}"
            )
        return event

    async def _authenticate(self) -> None:
        hello = await self.wait_for_event("auth/hello")
        if not hello.get("serverNonce"):
            raise SmokeTestError(f"{self.name} did not receive relay server nonce")

        client_nonce = base64.b64encode(f"nonce-{self.name}".encode("utf-8")).decode("ascii")
        await self.send({"type": "auth/client-hello", "clientNonce": client_nonce})

        proof = await self.wait_for_event("auth/proof")
        self.client_id = str(proof.get("clientId", "")).strip()
        if not self.client_id:
            raise SmokeTestError(f"{self.name} did not receive an assigned client id")


async def run_smoke_test(ws_url: str, room_id: str) -> None:
    alice = SmokeClient(name="alice", room_id=room_id, ws_url=ws_url)
    bob = SmokeClient(name="bob", room_id=room_id, ws_url=ws_url)
    mallory = SmokeClient(name="mallory", room_id=f"{room_id}-other", ws_url=ws_url)
    unauth = SmokeClient(name="unauth", room_id=room_id, ws_url=ws_url)

    await alice.connect()
    await bob.connect()
    await mallory.connect()
    await unauth.connect_raw()

    try:
        await alice.join()
        await bob.join()
        await mallory.join()

        await alice.wait_for_event("room/joined")
        await bob.wait_for_event("room/joined")
        await mallory.wait_for_event("room/joined")

        alice_snapshot = await alice.wait_for_event("peer/snapshot")
        bob_snapshot = await bob.wait_for_event("peer/snapshot")
        if len(alice_snapshot.get("peers", [])) < 1 or len(bob_snapshot.get("peers", [])) < 1:
            raise SmokeTestError("peer snapshot did not include expected peer records")

        await alice.send({"type": "msg/send", "payload": "room-smoke"})
        opaque = await bob.wait_for_event("msg/opaque")
        if opaque.get("payload") != "room-smoke":
            raise SmokeTestError("room message payload mismatch")

        await alice.send(
            {
                "type": "msg/direct-control",
                "targetClientId": bob.client_id,
                "payload": json.dumps(
                    {
                        "type": "PqxdhInit",
                        "protocol": "PQXDH/1",
                        "senderClientId": alice.client_id,
                        "receiverClientId": bob.client_id,
                        "senderEncryptionIdentityKey": "fake-enc",
                        "senderSigningIdentityKey": "fake-sig",
                        "receiverSignedPrekeyId": 1,
                        "receiverOneTimePrekeyId": None,
                        "receiverPqPrekeyPresent": False,
                    },
                    separators=(",", ":"),
                ),
            }
        )
        control = await bob.wait_for_event("msg/direct-control")
        if not control.get("senderRouteToken"):
            raise SmokeTestError("direct-control sender route token missing")

        await bob.send(
            {
                "type": "msg/direct",
                "targetClientId": alice.client_id,
                "payload": "direct-smoke",
            }
        )
        direct = await alice.wait_for_event("msg/direct")
        if direct.get("payload") != "direct-smoke":
            raise SmokeTestError("direct message payload mismatch")

        await unauth.send({"type": "room/join", "roomId": room_id, "username": "unauth"})
        await unauth.wait_for_error("authentication required before joining a room")

        await alice.send(
            {
                "type": "msg/direct",
                "targetClientId": mallory.client_id,
                "payload": "cross-room",
            }
        )
        await alice.wait_for_error("target client is not available in the current room")

        await bob.send({"type": "unsupported/test"})
        await bob.wait_for_error("unsupported message type")

        print("relay smoke test passed")
        print(f"alice={alice.client_id} bob={bob.client_id} room={room_id}")
    finally:
        await alice.close()
        await bob.close()
        await mallory.close()
        await unauth.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a local relay smoke test")
    parser.add_argument("--ws-url", default="ws://127.0.0.1:8443/ws")
    parser.add_argument("--room-id", default="smoke-room")
    args = parser.parse_args()
    asyncio.run(run_smoke_test(args.ws_url, args.room_id))


if __name__ == "__main__":
    main()
