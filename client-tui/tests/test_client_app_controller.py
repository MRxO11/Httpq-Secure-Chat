import sys
import tempfile
import unittest
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


CLIENT_TUI_ROOT = Path(__file__).resolve().parents[1]
if str(CLIENT_TUI_ROOT) not in sys.path:
    sys.path.insert(0, str(CLIENT_TUI_ROOT))

from app.client_app_controller import ClientAppController, ClientAppControllerError  # noqa: E402
from app.client_session_adapter import ClientSessionAdapter  # noqa: E402
from app.direct_adapter import DirectMessageAdapter  # noqa: E402
from app.direct_crypto import DirectCipher  # noqa: E402
from app.direct_session import DirectSessionStore  # noqa: E402
from app.httpq_client import HTTPQVerifier  # noqa: E402
from app.peer_pin_store import PeerPinStore  # noqa: E402
from app.pin_store import PinStore  # noqa: E402
from app.room_crypto import RoomCipher  # noqa: E402
from app.room_state import RoomStateStore  # noqa: E402
from app.trust_adapter import TrustAdapter  # noqa: E402


class ClientAppControllerTests(unittest.TestCase):
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
        )
        self.controller = ClientAppController(
            ClientSessionAdapter(
                trust=trust,
                direct=direct,
                direct_cipher=direct_cipher,
                room_cipher=room_cipher,
                peer_pin_store=PeerPinStore(path=str(Path(self.tempdir.name) / "peer-pins.json")),
            ),
            room_state_store=RoomStateStore(path=str(Path(self.tempdir.name) / "room-state.json")),
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def test_build_join_request_contains_identity_fields(self):
        request = self.controller.build_join_request(
            client_id="client-a",
            username="alice",
            room_id="lobby",
        )

        self.assertEqual(request.room_id, "lobby")
        self.assertEqual(request.username, "alice")
        self.assertTrue(request.direct_key)
        self.assertTrue(request.direct_signing_key)
        self.assertTrue(request.direct_signature)

    def test_room_encrypt_decrypt_round_trip(self):
        outbound = self.controller.encrypt_room_message(room_id="lobby", plaintext="hello world")
        inbound = self.controller.decrypt_room_message(payload=outbound.payload)

        self.assertEqual(outbound.metadata.mode, "room-aes-256-gcm+scrypt")
        self.assertEqual(outbound.metadata.conversation_kind, "room")
        self.assertEqual(outbound.metadata.room_id, "lobby")
        self.assertIn("[room room-aes-256-gcm+scrypt lobby -> room]", outbound.traffic_message.render())
        self.assertEqual(inbound.plaintext, "hello world")
        self.assertEqual(inbound.metadata.mode, "room-aes-256-gcm+scrypt")
        self.assertEqual(inbound.metadata.conversation_kind, "room")
        self.assertEqual(inbound.metadata.room_id, "lobby")
        self.assertEqual(
            inbound.traffic_message.render(),
            "[room room-aes-256-gcm+scrypt lobby] room: hello world",
        )

    def test_room_snapshot_round_trips_portable_contract(self):
        self.controller.set_room_key(room_id="lobby", secret="secret-passphrase")

        snapshot = self.controller.room_snapshot("lobby")

        self.assertEqual(snapshot.room_id, "lobby")
        self.assertEqual(snapshot.mode, "room-aes-256-gcm+scrypt")
        self.assertTrue(snapshot.room_key_present)
        self.assertGreaterEqual(snapshot.epoch, 1)
        self.assertTrue(str(snapshot.epoch_secret_ref).startswith("ges::"))
        self.assertTrue(str(snapshot.commit_secret_ref).startswith("gcs::"))
        self.assertTrue(str(snapshot.welcome_secret_ref).startswith("gws::"))
        self.assertTrue(str(snapshot.application_secret_ref).startswith("gas::"))

    def test_record_room_members_updates_snapshot(self):
        self.controller.set_room_key(room_id="lobby", secret="secret-passphrase")
        before = self.controller.room_snapshot("lobby")

        snapshot = self.controller.record_room_members(room_id="lobby", member_count=3)

        self.assertEqual(snapshot.member_count, 3)
        self.assertTrue(str(snapshot.commit_secret_ref).startswith("gcs::"))
        self.assertEqual(snapshot.application_secret_ref, before.application_secret_ref)

    def test_room_epoch_update_prepares_and_applies_control(self):
        self.controller.set_room_key(room_id="lobby", secret="secret-passphrase")

        outbound = self.controller.prepare_room_epoch_update(
            room_id="lobby",
            sender_client_id="client-a",
        )
        applied = self.controller.apply_room_control(payload=outbound.payload)

        self.assertEqual(outbound.payload["type"], "RoomEpochUpdate")
        self.assertEqual(outbound.snapshot_epoch, applied.snapshot_epoch)
        self.assertTrue(str(applied.epoch_key_ref).startswith("room-epoch::lobby::"))
        self.assertTrue(str(applied.epoch_secret_ref).startswith("ges::"))
        self.assertTrue(str(applied.commit_secret_ref).startswith("gcs::"))
        self.assertTrue(str(applied.welcome_secret_ref).startswith("gws::"))
        self.assertTrue(str(applied.application_secret_ref).startswith("gas::"))

    def test_room_proposal_commit_and_welcome_apply(self):
        self.controller.set_room_key(room_id="lobby", secret="secret-passphrase")

        proposal = self.controller.prepare_room_proposal(
            room_id="lobby",
            sender_client_id="client-a",
            target_client_id="client-b",
        )
        self.assertEqual(proposal.message_type, "RoomProposal")

        applied_proposal = self.controller.apply_room_control(payload=proposal.payload)
        self.assertEqual(applied_proposal.message_type, "RoomProposal")

        commit = self.controller.prepare_room_commit(
            room_id="lobby",
            sender_client_id="client-a",
        )
        self.assertEqual(commit.message_type, "RoomCommit")
        self.assertEqual(commit.payload["type"], "RoomCommit")

        welcome = self.controller.prepare_room_welcome(
            room_id="lobby",
            sender_client_id="client-a",
            recipient_client_id="client-b",
        )
        self.assertEqual(welcome.message_type, "RoomWelcome")
        self.assertEqual(welcome.payload["type"], "RoomWelcome")

    def test_room_control_plan_round_trips_portable_contract(self):
        self.controller.set_room_key(room_id="lobby", secret="secret-passphrase")

        commit = self.controller.prepare_room_commit(
            room_id="lobby",
            sender_client_id="client-a",
        )
        restored = type(commit).from_contract_dict(
            commit.to_contract_dict(),
            room_payload=commit.payload,
        )

        self.assertEqual(restored.message_type, "RoomCommit")
        self.assertEqual(restored.snapshot_epoch, commit.snapshot_epoch)
        self.assertEqual(restored.epoch_key_ref, commit.epoch_key_ref)
        self.assertEqual(restored.epoch_secret_ref, commit.epoch_secret_ref)
        self.assertEqual(restored.commit_secret_ref, commit.commit_secret_ref)
        self.assertEqual(restored.welcome_secret_ref, commit.welcome_secret_ref)
        self.assertEqual(restored.application_secret_ref, commit.application_secret_ref)

    def test_room_epoch_mismatch_rejects_old_payload(self):
        self.controller.set_room_key(room_id="lobby", secret="secret-passphrase")
        old_payload = self.controller.encrypt_room_message(
            room_id="lobby",
            plaintext="before-commit",
        ).payload
        self.controller.prepare_room_epoch_update(
            room_id="lobby",
            sender_client_id="client-a",
        )

        with self.assertRaises(ClientAppControllerError):
            self.controller.decrypt_room_message(payload=old_payload)

    def test_conflicting_same_epoch_room_control_is_rejected(self):
        self.controller.set_room_key(room_id="lobby", secret="secret-passphrase")
        commit = self.controller.prepare_room_commit(
            room_id="lobby",
            sender_client_id="client-a",
        )

        conflicting_payload = dict(commit.payload)
        conflicting_payload["epochKeyRef"] = "room-epoch::lobby::forged"

        with self.assertRaises(ClientAppControllerError):
            self.controller.apply_room_control(payload=conflicting_payload)

    def test_strict_mls_mode_rejects_placeholder_room_control(self):
        self.controller.set_room_key(room_id="lobby", secret="secret-passphrase")
        previous = os.environ.get("STRICT_MLS_REQUIRED")
        os.environ["STRICT_MLS_REQUIRED"] = "1"
        try:
            with self.assertRaises(ClientAppControllerError) as error:
                self.controller.prepare_room_commit(
                    room_id="lobby",
                    sender_client_id="client-a",
                )
        finally:
            if previous is None:
                os.environ.pop("STRICT_MLS_REQUIRED", None)
            else:
                os.environ["STRICT_MLS_REQUIRED"] = previous

        self.assertIn("requires a real MLS backend", str(error.exception))

    def test_strict_mls_mode_still_allows_non_mls_room_messages(self):
        previous = os.environ.get("STRICT_MLS_REQUIRED")
        os.environ["STRICT_MLS_REQUIRED"] = "1"
        try:
            outbound = self.controller.encrypt_room_message(
                room_id="lobby",
                plaintext="hello world",
            )
            inbound = self.controller.decrypt_room_message(payload=outbound.payload)
        finally:
            if previous is None:
                os.environ.pop("STRICT_MLS_REQUIRED", None)
            else:
                os.environ["STRICT_MLS_REQUIRED"] = previous

        self.assertEqual(inbound.plaintext, "hello world")

    def test_peer_upsert_wraps_validation_error(self):
        with self.assertRaises(ClientAppControllerError):
            self.controller.apply_peer_upsert(
                peer={"clientId": "peer-a", "username": "alice"},
                room_id="lobby",
            )

    def test_resolve_peer_accepts_username(self):
        join = self.controller.build_join_request(
            client_id="peer-a",
            username="bob",
            room_id="lobby",
        )
        self.controller.apply_peer_upsert(
            peer={
                "clientId": "peer-a",
                "username": "bob",
                "directKey": join.direct_key,
                "directSigningKey": join.direct_signing_key,
                "directSignature": join.direct_signature,
            },
            room_id="lobby",
        )

        resolved = self.controller.resolve_peer("bob")

        self.assertEqual(resolved["clientId"], "peer-a")

    def test_peer_safety_number_returns_stable_value_for_verified_peer(self):
        join = self.controller.build_join_request(
            client_id="peer-a",
            username="bob",
            room_id="lobby",
        )
        accepted = self.controller.apply_peer_upsert(
            peer={
                "clientId": "peer-a",
                "username": "bob",
                "directKey": join.direct_key,
                "directSigningKey": join.direct_signing_key,
                "directSignature": join.direct_signature,
            },
            room_id="lobby",
        )

        safety_number = self.controller.peer_safety_number(accepted)

        self.assertIsNotNone(safety_number)
        self.assertRegex(safety_number, r"^[0-9a-f]{4}( [0-9a-f]{4}){5}$")

    def test_reset_peer_trust_clears_existing_peer_pin(self):
        join = self.controller.build_join_request(
            client_id="peer-a",
            username="bob",
            room_id="lobby",
        )
        accepted = self.controller.apply_peer_upsert(
            peer={
                "clientId": "peer-a",
                "username": "bob",
                "directKey": join.direct_key,
                "directSigningKey": join.direct_signing_key,
                "directSignature": join.direct_signature,
            },
            room_id="lobby",
        )

        removed = self.controller.reset_peer_trust(accepted, room_id="lobby")

        self.assertTrue(removed)



if __name__ == "__main__":
    unittest.main()
