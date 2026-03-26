import sys
import tempfile
import unittest
import base64
import io
import json
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


CLIENT_TUI_ROOT = Path(__file__).resolve().parents[1]
if str(CLIENT_TUI_ROOT) not in sys.path:
    sys.path.insert(0, str(CLIENT_TUI_ROOT))

from app.client_app_controller import ClientAppController  # noqa: E402
from app.client_session_adapter import ClientSessionAdapter  # noqa: E402
from app.direct_adapter import DirectMessageAdapter  # noqa: E402
from app.direct_crypto import DirectCipher  # noqa: E402
from app.direct_session import DirectSessionStore  # noqa: E402
from app.httpq_client import HTTPQVerifier  # noqa: E402
from app.peer_pin_store import PeerPinStore  # noqa: E402
from app.pin_store import PinStore  # noqa: E402
from app.relay_event_coordinator import RelayEventCoordinator  # noqa: E402
from app.room_crypto import RoomCipher  # noqa: E402
from app.room_state import RoomStateStore  # noqa: E402
from app.trust_adapter import TrustAdapter  # noqa: E402
from app.httpq_math import hash_leaf, hash_node, httpq_transcript_bytes, sth_message, witness_message  # noqa: E402


class MockHTTPResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False


def json_response(payload: dict) -> MockHTTPResponse:
    return MockHTTPResponse(json.dumps(payload).encode("utf-8"))


def sample_handshake(client_nonce_b64: str):
    relay_key = Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)
    kt_key = Ed25519PrivateKey.from_private_bytes(bytes([9]) * 32)
    witness_key = Ed25519PrivateKey.from_private_bytes(bytes([10]) * 32)

    relay_public_key_b64 = base64.b64encode(
        relay_key.public_key().public_bytes_raw()
    ).decode("ascii")
    kt_public_key_b64 = base64.b64encode(
        kt_key.public_key().public_bytes_raw()
    ).decode("ascii")

    hello = {
        "relayId": "relay-local",
        "realm": "secure-chat",
        "protocolVersion": "HTTPq/1",
        "ktLogUrl": "http://127.0.0.1:8081",
        "witnessUrl": "http://127.0.0.1:8082",
        "serverNonce": base64.b64encode(bytes([2]) * 32).decode("ascii"),
        "relayPublicKey": relay_public_key_b64,
    }
    proof = {
        "relayId": hello["relayId"],
        "realm": hello["realm"],
        "clientId": "anon-1",
        "clientNonce": client_nonce_b64,
        "serverNonce": hello["serverNonce"],
        "relayPublicKey": relay_public_key_b64,
        "signature": base64.b64encode(
            relay_key.sign(
                httpq_transcript_bytes(
                    realm=hello["realm"],
                    client_id="anon-1",
                    client_nonce_b64=client_nonce_b64,
                    server_nonce_b64=hello["serverNonce"],
                    public_key_b64=relay_public_key_b64,
                )
            )
        ).decode("ascii"),
    }

    record = {
        "relayId": hello["relayId"],
        "publicKey": relay_public_key_b64,
        "algorithm": "Ed25519",
        "createdAt": "2026-03-25T00:00:00Z",
    }
    sibling = {
        "relayId": "relay-peer",
        "publicKey": base64.b64encode(bytes([8]) * 32).decode("ascii"),
        "algorithm": "Ed25519",
        "createdAt": "2026-03-25T00:00:01Z",
    }
    record_bytes = json.dumps(record, separators=(",", ":")).encode("utf-8")
    sibling_bytes = json.dumps(sibling, separators=(",", ":")).encode("utf-8")
    sibling_leaf = hash_leaf(sibling_bytes)
    root_hash = hash_node(hash_leaf(record_bytes), sibling_leaf)
    inclusion = {
        "record": record,
        "index": 0,
        "proof": [base64.b64encode(sibling_leaf).decode("ascii")],
        "sth": {
            "treeSize": 2,
            "rootHash": base64.b64encode(root_hash).decode("ascii"),
            "signature": base64.b64encode(kt_key.sign(sth_message(2, root_hash))).decode("ascii"),
        },
        "signingPublicKey": kt_public_key_b64,
    }
    checkpoint = {
        "logId": hello["ktLogUrl"],
        "treeSize": 2,
        "rootHash": inclusion["sth"]["rootHash"],
        "signingPublicKey": kt_public_key_b64,
        "witnessPublicKey": base64.b64encode(
            witness_key.public_key().public_bytes_raw()
        ).decode("ascii"),
        "witnessSignature": base64.b64encode(
            witness_key.sign(
                witness_message(
                    log_id=hello["ktLogUrl"],
                    tree_size=2,
                    root_hash_b64=inclusion["sth"]["rootHash"],
                    signing_public_key_b64=kt_public_key_b64,
                )
            )
        ).decode("ascii"),
    }
    return hello, proof, inclusion, checkpoint


class RelayEventCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        pin_store = PinStore(path=str(Path(self.tempdir.name) / "pins.json"))
        room_cipher = RoomCipher()
        room_cipher.set_room_key("lobby", "secret-passphrase")
        trust = TrustAdapter(HTTPQVerifier("ws://127.0.0.1:8443/ws", pin_store))
        direct_cipher = DirectCipher(X25519PrivateKey.generate(), Ed25519PrivateKey.generate())
        direct = DirectMessageAdapter(
            direct_cipher,
            DirectSessionStore(path=str(Path(self.tempdir.name) / "sessions.json")),
        )
        session = ClientSessionAdapter(
            trust=trust,
            direct=direct,
            direct_cipher=direct_cipher,
            room_cipher=room_cipher,
            peer_pin_store=PeerPinStore(path=str(Path(self.tempdir.name) / "peer-pins.json")),
        )
        self.app = ClientAppController(
            session,
            room_state_store=RoomStateStore(path=str(Path(self.tempdir.name) / "room-state.json")),
        )
        self.coordinator = RelayEventCoordinator(trust=trust, app=self.app)

    def tearDown(self):
        self.tempdir.cleanup()

    def test_auth_hello_returns_client_nonce(self):
        outcome = self.coordinator.handle_event(
            event={
                "type": "auth/hello",
                "relayId": "relay-local",
                "realm": "secure-chat",
                "protocolVersion": "HTTPq/1",
                "ktLogUrl": "http://127.0.0.1:8081",
                "witnessUrl": "http://127.0.0.1:8082",
                "serverNonce": "nonce",
                "relayPublicKey": "key",
            },
            client_id="unknown",
            username="alice",
            room_id="lobby",
        )

        self.assertTrue(outcome.handled)
        self.assertTrue(outcome.client_nonce)
        self.assertEqual(outcome.status, "authenticating")
        self.assertEqual(len(outcome.notices), 1)
        self.assertIn("Relay hello received", outcome.notices[0].render())

    def test_room_opaque_decrypts_through_app_controller(self):
        payload = self.app.encrypt_room_message(room_id="lobby", plaintext="hello").payload

        outcome = self.coordinator.handle_event(
            event={"type": "msg/opaque", "username": "alice", "payload": payload},
            client_id="client-a",
            username="alice",
            room_id="lobby",
        )

        self.assertEqual(outcome.logs, [])
        self.assertEqual(outcome.notices, [])
        self.assertEqual(len(outcome.traffic_messages), 1)
        self.assertEqual(
            outcome.traffic_messages[0].render(),
            "[room room-aes-256-gcm+scrypt lobby] alice: hello",
        )

    def test_room_control_updates_epoch_notice(self):
        self.app.set_room_key(room_id="lobby", secret="secret-passphrase")
        control = self.app.prepare_room_epoch_update(
            room_id="lobby",
            sender_client_id="client-a",
        )

        outcome = self.coordinator.handle_event(
            event={"type": "msg/room-control", "payload": json.dumps(control.payload)},
            client_id="client-a",
            username="alice",
            room_id="lobby",
        )

        self.assertTrue(outcome.handled)
        self.assertEqual(len(outcome.notices), 1)
        self.assertIn("Room epoch updated to", outcome.notices[0].render())

    def test_room_snapshot_updates_member_count(self):
        outcome = self.coordinator.handle_event(
            event={"type": "room/snapshot", "roomId": "lobby", "memberIds": ["a", "b", "c"]},
            client_id="client-a",
            username="alice",
            room_id="lobby",
        )

        self.assertTrue(outcome.handled)
        self.assertEqual(self.app.room_snapshot("lobby").member_count, 3)

    def test_room_control_notice_uses_portable_contract_epoch(self):
        self.app.set_room_key(room_id="lobby", secret="secret-passphrase")
        control = self.app.prepare_room_commit(
            room_id="lobby",
            sender_client_id="client-a",
        )

        outcome = self.coordinator.handle_event(
            event={"type": "msg/room-control", "payload": json.dumps(control.payload)},
            client_id="client-a",
            username="alice",
            room_id="lobby",
        )

        self.assertTrue(outcome.handled)
        self.assertIn(f"epoch {control.snapshot_epoch}", outcome.notices[0].render())

    def test_conflicting_same_epoch_room_control_logs_rejection(self):
        self.app.set_room_key(room_id="lobby", secret="secret-passphrase")
        control = self.app.prepare_room_commit(
            room_id="lobby",
            sender_client_id="client-a",
        )
        conflicting_payload = dict(control.payload)
        conflicting_payload["epochKeyRef"] = "room-epoch::lobby::forged"

        outcome = self.coordinator.handle_event(
            event={"type": "msg/room-control", "payload": json.dumps(conflicting_payload)},
            client_id="client-a",
            username="alice",
            room_id="lobby",
        )

        self.assertTrue(outcome.handled)
        self.assertIn("room-control rejected", outcome.logs[0])

    def test_peer_upsert_notice_includes_safety_number(self):
        identity = self.app.session.build_join_identity(
            client_id="peer-a",
            username="alice",
            room_id="lobby",
        )

        outcome = self.coordinator.handle_event(
            event={
                "type": "peer/upsert",
                "peer": {
                    "clientId": "peer-a",
                    "username": "alice",
                    "directKey": identity.direct_key,
                    "directSigningKey": identity.direct_signing_key,
                    "directSignature": identity.direct_signature,
                },
            },
            client_id="client-a",
            username="alice",
            room_id="lobby",
        )

        self.assertTrue(outcome.handled)
        self.assertIn("safety=", outcome.notices[0].render())


    def test_room_control_proposal_notice(self):
        self.app.set_room_key(room_id="lobby", secret="secret-passphrase")
        control = self.app.prepare_room_proposal(
            room_id="lobby",
            sender_client_id="client-a",
            target_client_id="client-b",
        )

        outcome = self.coordinator.handle_event(
            event={"type": "msg/room-control", "payload": json.dumps(control.payload)},
            client_id="client-a",
            username="alice",
            room_id="lobby",
        )

        self.assertTrue(outcome.handled)
        self.assertEqual(len(outcome.notices), 1)
        self.assertIn("proposal recorded", outcome.notices[0].render())

    def test_peer_upsert_logs_rejection_from_app_controller(self):
        self.coordinator.app.apply_peer_upsert = MagicMock(side_effect=Exception("bad peer"))

        with self.assertRaises(Exception):
            self.coordinator.handle_event(
                event={"type": "peer/upsert", "peer": {"clientId": "peer-a", "username": "alice"}},
                client_id="client-a",
                username="alice",
                room_id="lobby",
            )

    def test_auth_proof_round_trips_portable_trust_contract(self):
        hello, _, _, _ = sample_handshake("placeholder")
        hello_outcome = self.coordinator.handle_event(
            event={"type": "auth/hello", **hello},
            client_id="unknown",
            username="alice",
            room_id="lobby",
        )
        _, proof, inclusion, checkpoint = sample_handshake(hello_outcome.client_nonce)

        def fake_urlopen(request, timeout=5):
            url = request.full_url if hasattr(request, "full_url") else request
            if url.endswith("/proof"):
                return json_response(inclusion)
            if "/v1/checkpoints/" in url:
                return json_response(checkpoint)
            if url.endswith("/v1/checkpoints"):
                return json_response(checkpoint)
            raise AssertionError(f"unexpected URL {url}")

        with mock.patch("app.httpq_client.urllib.request.urlopen", side_effect=fake_urlopen):
            outcome = self.coordinator.handle_event(
                event={"type": "auth/proof", **proof},
                client_id="unknown",
                username="alice",
                room_id="lobby",
            )

        self.assertTrue(outcome.handled)
        self.assertEqual(outcome.status, "connected")
        self.assertEqual(outcome.assigned_client_id, "anon-1")
        self.assertEqual(outcome.join_request.room_id, "lobby")
        self.assertEqual(outcome.join_request.username, "alice")
        self.assertTrue(outcome.join_request.direct_key)
        self.assertIn("Assigned client id anon-1", outcome.notices[0].render())


if __name__ == "__main__":
    unittest.main()
