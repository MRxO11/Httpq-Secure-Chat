import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


CLIENT_TUI_ROOT = Path(__file__).resolve().parents[1]
if str(CLIENT_TUI_ROOT) not in sys.path:
    sys.path.insert(0, str(CLIENT_TUI_ROOT))

from app.chat_session_controller import ChatSessionController  # noqa: E402
from app.direct_adapter import DirectMessageAdapter  # noqa: E402
from app.direct_crypto import DirectCipher  # noqa: E402
from app.direct_session import DirectSessionStore  # noqa: E402


class ChatSessionControllerTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.alice_adapter = DirectMessageAdapter(
            DirectCipher(X25519PrivateKey.generate(), Ed25519PrivateKey.generate()),
            DirectSessionStore(path=str(Path(self.tempdir.name) / "alice-sessions.json")),
        )
        self.bob_adapter = DirectMessageAdapter(
            DirectCipher(X25519PrivateKey.generate(), Ed25519PrivateKey.generate()),
            DirectSessionStore(path=str(Path(self.tempdir.name) / "bob-sessions.json")),
        )
        self.alice = ChatSessionController(self.alice_adapter)
        self.bob = ChatSessionController(self.bob_adapter)

    def tearDown(self):
        self.tempdir.cleanup()

    def test_prepare_outbound_direct_emits_bootstrap_control_first(self):
        outbound = self.alice.prepare_outbound_direct(
            local_client_id="alice-id",
            peer_client_id="bob-id",
            peer_display_name="bob",
            peer_encryption_public_key_b64=self.bob_adapter.cipher.encryption_public_key_b64,
            room_id="lobby",
            plaintext="hello bob",
        )

        self.assertIsNotNone(outbound.control_frame)
        self.assertIsNotNone(outbound.control_metadata)
        self.assertEqual(outbound.application_frame.target_client_id, "bob-id")
        self.assertEqual(outbound.metadata.sequence, 1)
        self.assertEqual(outbound.metadata.mode, "signed-static-session")
        self.assertEqual(outbound.metadata.conversation_kind, "direct")
        self.assertIsNone(outbound.metadata.message_key_ref)
        self.assertEqual(outbound.control_metadata.conversation_kind, "control")
        self.assertEqual(outbound.control_metadata.transport_kind, "control")
        self.assertIn("-> bob]", outbound.traffic_message.render())

    def test_handle_inbound_direct_returns_ack_for_bootstrap_message(self):
        outbound = self.alice.prepare_outbound_direct(
            local_client_id="alice-id",
            peer_client_id="bob-id",
            peer_display_name="bob",
            peer_encryption_public_key_b64=self.bob_adapter.cipher.encryption_public_key_b64,
            room_id="lobby",
            plaintext="hello bob",
        )

        received = self.bob.handle_inbound_direct(
            peer_client_id="alice-id",
            peer_display_name="alice",
            payload=outbound.application_frame.payload,
            room_id="lobby",
            target_client_id="bob-id",
            expected_signing_key_b64=self.alice_adapter.cipher.signing_public_key_b64,
        )

        self.assertEqual(received.decrypted.plaintext, "hello bob")
        self.assertIsNone(received.ack_frame)
        self.assertEqual(received.metadata.mode, "signed-static-session")
        self.assertEqual(received.metadata.conversation_kind, "direct")
        self.assertIsNone(received.metadata.message_key_ref)
        self.assertIn("alice: hello bob", received.traffic_message.render())

        control = self.bob.handle_inbound_control(
            local_client_id="bob-id",
            peer_client_id="alice-id",
            peer_display_name="alice",
            room_id="lobby",
            payload=outbound.control_frame.payload,
        )

        self.assertIsNotNone(control.ack_frame)
        self.assertEqual(control.metadata.conversation_kind, "control")
        self.assertEqual(control.metadata.transport_kind, "control")
        self.assertIsNotNone(control.ack_metadata)
        self.assertIn("bootstrap received", control.bootstrap_log)

    def test_handle_inbound_control_ack_logs_acknowledgement(self):
        outbound = self.alice.prepare_outbound_direct(
            local_client_id="alice-id",
            peer_client_id="bob-id",
            peer_display_name="bob",
            peer_encryption_public_key_b64=self.bob_adapter.cipher.encryption_public_key_b64,
            room_id="lobby",
            plaintext="hello bob",
        )
        control = self.bob.handle_inbound_control(
            local_client_id="bob-id",
            peer_client_id="alice-id",
            peer_display_name="alice",
            room_id="lobby",
            payload=outbound.control_frame.payload,
        )

        ack = self.alice.handle_inbound_control(
            local_client_id="alice-id",
            peer_client_id="bob-id",
            peer_display_name="bob",
            room_id="lobby",
            payload=control.ack_frame.payload,
        )

        self.assertIsNone(ack.ack_frame)
        self.assertIn("bootstrap acknowledged", ack.ack_log)


if __name__ == "__main__":
    unittest.main()
