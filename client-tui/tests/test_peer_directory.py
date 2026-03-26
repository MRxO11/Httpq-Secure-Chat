import sys
import unittest
from pathlib import Path


CLIENT_TUI_ROOT = Path(__file__).resolve().parents[1]
if str(CLIENT_TUI_ROOT) not in sys.path:
    sys.path.insert(0, str(CLIENT_TUI_ROOT))

from app.peer_directory import PeerDirectory, PeerDirectoryError  # noqa: E402


class PeerDirectoryTests(unittest.TestCase):
    def test_snapshot_keeps_only_valid_peers(self):
        def validator(peer: dict, room_id: str) -> None:
            if peer.get("clientId") == "bad":
                raise ValueError("invalid peer")

        directory = PeerDirectory(validator)
        result = directory.snapshot(
            peers=[
                {"clientId": "good", "username": "alice"},
                {"clientId": "bad", "username": "mallory"},
                {"username": "missing-id"},
            ],
            room_id="lobby",
        )

        self.assertEqual(result.accepted_count, 1)
        self.assertEqual(len(directory), 1)
        self.assertEqual(len(result.rejected), 1)
        self.assertEqual(directory.get("good")["username"], "alice")

    def test_upsert_requires_client_id(self):
        directory = PeerDirectory(lambda peer, room_id: None)

        with self.assertRaises(PeerDirectoryError):
            directory.upsert(peer={"username": "alice"}, room_id="lobby")

    def test_remove_returns_previous_peer(self):
        directory = PeerDirectory(lambda peer, room_id: None)
        directory.upsert(peer={"clientId": "peer-a", "username": "alice"}, room_id="lobby")

        removed = directory.remove("peer-a")

        self.assertEqual(removed["username"], "alice")
        self.assertEqual(len(directory), 0)

    def test_resolve_accepts_username(self):
        directory = PeerDirectory(lambda peer, room_id: None)
        directory.upsert(peer={"clientId": "peer-a", "username": "alice"}, room_id="lobby")

        resolved = directory.resolve("alice")

        self.assertEqual(resolved["clientId"], "peer-a")

    def test_resolve_rejects_ambiguous_username(self):
        directory = PeerDirectory(lambda peer, room_id: None)
        directory.upsert(peer={"clientId": "peer-a", "username": "alice"}, room_id="lobby")
        directory.upsert(peer={"clientId": "peer-b", "username": "Alice"}, room_id="lobby")

        with self.assertRaises(PeerDirectoryError):
            directory.resolve("alice")

    def test_get_by_route_token_returns_matching_peer(self):
        directory = PeerDirectory(lambda peer, room_id: None)
        directory.upsert(
            peer={
                "clientId": "peer-a",
                "username": "alice",
                "directRouteToken": "route-a",
            },
            room_id="lobby",
        )

        resolved = directory.get_by_route_token("route-a")

        self.assertEqual(resolved["clientId"], "peer-a")


if __name__ == "__main__":
    unittest.main()
