import sys
import tempfile
import unittest
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


CLIENT_TUI_ROOT = Path(__file__).resolve().parents[1]
if str(CLIENT_TUI_ROOT) not in sys.path:
    sys.path.insert(0, str(CLIENT_TUI_ROOT))

from app.client_session_adapter import (  # noqa: E402
    ClientSessionAdapter,
    ClientSessionAdapterError,
)
from app.direct_adapter import DirectMessageAdapter  # noqa: E402
from app.direct_crypto import DirectCipher  # noqa: E402
from app.direct_session import DirectSessionStore  # noqa: E402
from app.httpq_client import HTTPQVerifier  # noqa: E402
from app.peer_pin_store import PeerPinStore  # noqa: E402
from app.pin_store import PinStore  # noqa: E402
from app.room_crypto import RoomCipher  # noqa: E402
from app.trust_adapter import TrustAdapter  # noqa: E402


class ClientSessionAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.pin_store = PinStore(path=str(Path(self.tempdir.name) / "pins.json"))
        self.room_cipher = RoomCipher()
        self.room_cipher.set_room_key("lobby", "secret-passphrase")
        self.trust = TrustAdapter(HTTPQVerifier("ws://127.0.0.1:8443/ws", self.pin_store))
        self.direct_cipher = DirectCipher(X25519PrivateKey.generate(), Ed25519PrivateKey.generate())
        self.direct = DirectMessageAdapter(
            self.direct_cipher,
            DirectSessionStore(path=str(Path(self.tempdir.name) / "sessions.json")),
        )
        self.peer_pin_store = PeerPinStore(path=str(Path(self.tempdir.name) / "peer-pins.json"))
        self.adapter = ClientSessionAdapter(
            trust=self.trust,
            direct=self.direct,
            direct_cipher=self.direct_cipher,
            room_cipher=self.room_cipher,
            peer_pin_store=self.peer_pin_store,
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def test_build_join_identity_contains_direct_fields(self):
        identity = self.adapter.build_join_identity(
            client_id="client-a",
            username="alice",
            room_id="lobby",
        )

        self.assertTrue(identity.direct_key)
        self.assertTrue(identity.direct_signing_key)
        self.assertTrue(identity.direct_signature)

    def test_verify_peer_rejects_incomplete_identity(self):
        with self.assertRaises(ClientSessionAdapterError):
            self.adapter.verify_peer(
                peer={"clientId": "client-b", "username": "bob"},
                room_id="lobby",
            )

    def test_verify_peer_pins_first_seen_identity(self):
        identity = self.adapter.build_join_identity(
            client_id="client-b",
            username="bob",
            room_id="lobby",
        )

        self.adapter.verify_peer(
            peer={
                "clientId": "client-b",
                "username": "bob",
                "directKey": identity.direct_key,
                "directSigningKey": identity.direct_signing_key,
                "directSignature": identity.direct_signature,
            },
            room_id="lobby",
        )

        pinned = self.peer_pin_store.get(room_id="lobby", username="bob")
        self.assertIsNotNone(pinned)
        self.assertEqual(pinned.signing_key_b64, identity.direct_signing_key)

    def test_verify_peer_rejects_pinned_identity_change(self):
        identity = self.adapter.build_join_identity(
            client_id="client-b",
            username="bob",
            room_id="lobby",
        )
        self.adapter.verify_peer(
            peer={
                "clientId": "client-b",
                "username": "bob",
                "directKey": identity.direct_key,
                "directSigningKey": identity.direct_signing_key,
                "directSignature": identity.direct_signature,
            },
            room_id="lobby",
        )

        other_cipher = DirectCipher(X25519PrivateKey.generate(), Ed25519PrivateKey.generate())
        forged_signature = other_cipher.sign_peer_announcement(
            client_id="client-c",
            username="bob",
            room_id="lobby",
        )

        with self.assertRaises(ClientSessionAdapterError) as error:
            self.adapter.verify_peer(
                peer={
                    "clientId": "client-c",
                    "username": "bob",
                    "directKey": other_cipher.encryption_public_key_b64,
                    "directSigningKey": other_cipher.signing_public_key_b64,
                    "directSignature": forged_signature,
                },
                room_id="lobby",
            )

        self.assertIn("security warning:", str(error.exception).lower())
        self.assertIn("changed from", str(error.exception))
        self.assertIn("to", str(error.exception))

    def test_peer_safety_number_is_stable_for_same_identity(self):
        identity = self.adapter.build_join_identity(
            client_id="client-b",
            username="bob",
            room_id="lobby",
        )

        first = self.adapter.peer_safety_number(
            username="bob",
            encryption_key_b64=identity.direct_key,
            signing_key_b64=identity.direct_signing_key,
        )
        second = self.adapter.peer_safety_number(
            username="bob",
            encryption_key_b64=identity.direct_key,
            signing_key_b64=identity.direct_signing_key,
        )

        self.assertEqual(first, second)
        self.assertRegex(first, r"^[0-9a-f]{4}( [0-9a-f]{4}){5}$")

    def test_reset_peer_trust_removes_existing_pin(self):
        identity = self.adapter.build_join_identity(
            client_id="client-b",
            username="bob",
            room_id="lobby",
        )
        self.adapter.verify_peer(
            peer={
                "clientId": "client-b",
                "username": "bob",
                "directKey": identity.direct_key,
                "directSigningKey": identity.direct_signing_key,
                "directSignature": identity.direct_signature,
            },
            room_id="lobby",
        )

        removed = self.adapter.reset_peer_trust(room_id="lobby", username="bob")

        self.assertTrue(removed)
        self.assertIsNone(self.peer_pin_store.get(room_id="lobby", username="bob"))


    def test_room_encrypt_decrypt_round_trip(self):
        payload = self.adapter.encrypt_room_message(
            room_id="lobby",
            plaintext="hello world",
            epoch=1,
            epoch_key_ref="room-epoch::lobby::1",
            epoch_secret_ref="ges::demo",
            application_secret_ref="gas::demo",
        )
        decrypted = self.adapter.decrypt_room_message(
            payload=payload,
            expected_epoch=1,
            expected_epoch_key_ref="room-epoch::lobby::1",
            expected_epoch_secret_ref="ges::demo",
            expected_application_secret_ref="gas::demo",
        )

        self.assertEqual(decrypted.room_id, "lobby")
        self.assertEqual(decrypted.plaintext, "hello world")
        self.assertEqual(decrypted.epoch_secret_ref, "ges::demo")
        self.assertEqual(decrypted.application_secret_ref, "gas::demo")

    def test_room_application_secret_ref_tamper_breaks_decrypt(self):
        payload = self.adapter.encrypt_room_message(
            room_id="lobby",
            plaintext="hello world",
            epoch=1,
            epoch_key_ref="room-epoch::lobby::1",
            epoch_secret_ref="ges::demo",
            application_secret_ref="gas::demo",
        )
        envelope = json.loads(payload)
        envelope["applicationSecretRef"] = "gas::forged"

        with self.assertRaises(ClientSessionAdapterError):
            self.adapter.decrypt_room_message(payload=json.dumps(envelope, separators=(",", ":")))


if __name__ == "__main__":
    unittest.main()
