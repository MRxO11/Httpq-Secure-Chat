import base64
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


CLIENT_TUI_ROOT = Path(__file__).resolve().parents[1]
if str(CLIENT_TUI_ROOT) not in sys.path:
    sys.path.insert(0, str(CLIENT_TUI_ROOT))

from app.direct_crypto import DirectCipher, DirectCryptoError  # noqa: E402
from app.direct_math import direct_message_bytes, peer_announcement_bytes  # noqa: E402
from app.direct_protocol import DirectEnvelope, DirectEnvelopeAlgorithm  # noqa: E402


class DirectProtocolTests(unittest.TestCase):
    def test_direct_envelope_round_trip(self):
        envelope = DirectEnvelope(
            version=1,
            algorithm="test",
            session_id="dm::lobby::a::b",
            sequence=1,
            message_number=1,
            sender_key_b64="enc",
            sender_ratchet_key_b64="ratchet",
            sender_signing_key_b64="sig",
            salt_b64="salt",
            nonce_b64="nonce",
            ciphertext_b64="cipher",
            signature_b64="signed",
            bootstrap_payload={"type": "PqxdhInit"},
        )
        parsed = DirectEnvelope.from_json(envelope.to_json())
        self.assertEqual(parsed, envelope)

    def test_direct_message_bytes_are_canonical(self):
        payload_a = {"b": 2, "a": 1}
        payload_b = {"a": 1, "b": 2}
        self.assertEqual(
            direct_message_bytes(
                room_id="lobby",
                target_client_id="peer-b",
                envelope=payload_a,
            ),
            direct_message_bytes(
                room_id="lobby",
                target_client_id="peer-b",
                envelope=payload_b,
            ),
        )

    def test_peer_announcement_bytes_include_expected_fields(self):
        message = peer_announcement_bytes(
            client_id="anon-1",
            username="alice",
            room_id="lobby",
            encryption_key_b64="enc",
            signing_key_b64="sig",
        )
        self.assertIn(b"PEER/1\nlobby\nanon-1\nalice\nenc\nsig", message)

    def test_direct_envelope_classifies_known_algorithms(self):
        static_envelope = DirectEnvelope(
            version=1,
            algorithm=DirectEnvelopeAlgorithm.AUTHENTICATED_STATIC_BRIDGE.value,
            session_id="dm::lobby::a::b",
            sequence=1,
            message_number=1,
            sender_key_b64="enc",
            sender_ratchet_key_b64=None,
            sender_signing_key_b64="sig",
            salt_b64="salt",
            nonce_b64="nonce",
            ciphertext_b64="cipher",
            signature_b64="signed",
        )
        session_envelope = DirectEnvelope(
            version=1,
            algorithm=DirectEnvelopeAlgorithm.SESSION_CHAIN_BRIDGE.value,
            session_id="dm::lobby::a::b",
            sequence=2,
            message_number=2,
            sender_key_b64="enc",
            sender_ratchet_key_b64="ratchet",
            sender_signing_key_b64="sig",
            salt_b64="salt",
            nonce_b64="nonce",
            ciphertext_b64="cipher",
            signature_b64="signed",
        )

        self.assertEqual(
            static_envelope.classified_algorithm(),
            DirectEnvelopeAlgorithm.AUTHENTICATED_STATIC_BRIDGE,
        )
        self.assertFalse(static_envelope.uses_session_chain())
        self.assertEqual(
            session_envelope.classified_algorithm(),
            DirectEnvelopeAlgorithm.SESSION_CHAIN_BRIDGE,
        )
        self.assertTrue(session_envelope.uses_session_chain())


class DirectCipherTests(unittest.TestCase):
    def setUp(self):
        self.alice_cipher = DirectCipher(
            X25519PrivateKey.generate(),
            Ed25519PrivateKey.generate(),
        )
        self.bob_cipher = DirectCipher(
            X25519PrivateKey.generate(),
            Ed25519PrivateKey.generate(),
        )

    def test_encrypt_and_decrypt_round_trip(self):
        payload = self.alice_cipher.encrypt_for_peer(
            peer_encryption_public_key_b64=self.bob_cipher.encryption_public_key_b64,
            target_client_id="peer-b",
            room_id="lobby",
            session_id="dm::lobby::peer-a::peer-b",
            sequence=1,
            message_number=1,
            sender_ratchet_key_b64="alice-ratchet",
            bootstrap_message={"type": "PqxdhInit"},
            plaintext="hello",
        )
        decrypted = self.bob_cipher.decrypt_from_peer(
            payload=payload,
            room_id="lobby",
            target_client_id="peer-b",
        )
        self.assertEqual(decrypted.plaintext, "hello")
        self.assertEqual(decrypted.sequence, 1)
        self.assertEqual(decrypted.message_number, 1)
        self.assertEqual(decrypted.sender_ratchet_key_b64, "alice-ratchet")
        self.assertEqual(decrypted.bootstrap_message, {"type": "PqxdhInit"})

    def test_detects_tampered_signature(self):
        payload = self.alice_cipher.encrypt_for_peer(
            peer_encryption_public_key_b64=self.bob_cipher.encryption_public_key_b64,
            target_client_id="peer-b",
            room_id="lobby",
            session_id="dm::lobby::peer-a::peer-b",
            sequence=1,
            message_number=1,
            sender_ratchet_key_b64=None,
            bootstrap_message=None,
            plaintext="hello",
        )
        tampered = DirectEnvelope.from_json(payload)
        tampered = DirectEnvelope(
            version=tampered.version,
            algorithm=tampered.algorithm,
            session_id=tampered.session_id,
            sequence=tampered.sequence,
            message_number=tampered.message_number,
            sender_key_b64=tampered.sender_key_b64,
            sender_ratchet_key_b64=tampered.sender_ratchet_key_b64,
            sender_signing_key_b64=tampered.sender_signing_key_b64,
            salt_b64=tampered.salt_b64,
            nonce_b64=tampered.nonce_b64,
            ciphertext_b64=tampered.ciphertext_b64,
            signature_b64=base64.b64encode(b"broken-signature").decode("ascii"),
            bootstrap_payload=tampered.bootstrap_payload,
        )
        with self.assertRaises(DirectCryptoError):
            self.bob_cipher.decrypt_from_peer(
                payload=tampered.to_json(),
                room_id="lobby",
                target_client_id="peer-b",
            )


if __name__ == "__main__":
    unittest.main()
