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

from app.direct_adapter import DirectAdapterError, DirectMessageAdapter  # noqa: E402
from app.direct_crypto import DirectCipher  # noqa: E402
from app.direct_bootstrap import PqxdhInitMessage  # noqa: E402
from app.direct_protocol import DirectEnvelope  # noqa: E402
from app.direct_session import DirectSessionStore  # noqa: E402


class DirectAdapterTests(unittest.TestCase):
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

    def tearDown(self):
        self.tempdir.cleanup()

    def test_prepare_outbound_message_emits_bootstrap_once(self):
        first = self.alice_adapter.prepare_outbound_message(
            local_client_id="peer-a",
            peer_client_id="peer-b",
            peer_encryption_public_key_b64=self.bob_adapter.cipher.encryption_public_key_b64,
            room_id="lobby",
            plaintext="hello",
        )
        second = self.alice_adapter.prepare_outbound_message(
            local_client_id="peer-a",
            peer_client_id="peer-b",
            peer_encryption_public_key_b64=self.bob_adapter.cipher.encryption_public_key_b64,
            room_id="lobby",
            plaintext="again",
        )

        self.assertIsNotNone(first.bootstrap_message)
        self.assertIsNone(second.bootstrap_message)
        self.assertEqual(first.sequence, 1)
        self.assertEqual(second.sequence, 2)
        self.assertEqual(first.mode, "signed-static-session")
        self.assertEqual(second.mode, "signed-static-session")
        self.assertIsNone(first.message_key_ref)
        self.assertIsNone(second.message_key_ref)
        self.assertTrue(first.ratchet_public_key_b64)
        self.assertTrue(first.bootstrap_message.sender_ephemeral_key_b64)
        self.assertTrue(first.bootstrap_message.signature_b64)

    def test_handle_bootstrap_init_produces_ack(self):
        ephemeral_private_key_b64, ephemeral_public_key_b64 = self.alice_adapter.cipher.generate_ephemeral_keypair()
        init = PqxdhInitMessage(
            protocol="PQXDH/1",
            sender_client_id="peer-a",
            receiver_client_id="peer-b",
            sender_encryption_identity_key=self.alice_adapter.cipher.encryption_public_key_b64,
            sender_signing_identity_key=self.alice_adapter.cipher.signing_public_key_b64,
            sender_ephemeral_key_b64=ephemeral_public_key_b64,
            receiver_signed_prekey_id=1,
            receiver_one_time_prekey_id=None,
            receiver_pq_prekey_present=False,
            signature_b64="",
        )
        init = PqxdhInitMessage(
            **{
                **init.__dict__,
                "signature_b64": self.alice_adapter.cipher.sign_bootstrap_payload(
                    init.to_payload(include_signature=False)
                ),
            }
        )
        result = self.bob_adapter.handle_bootstrap_message(
            local_client_id="peer-b",
            peer_client_id="peer-a",
            room_id="lobby",
            bootstrap_payload=init,
        )

        self.assertIsNotNone(result.ack_message)
        self.assertEqual(result.ack_sequence, 1)
        self.assertTrue(result.ack_message.sender_ephemeral_key_b64)
        self.assertTrue(result.ack_message.signature_b64)

        contract = result.to_contract_dict()
        self.assertEqual(contract["peer_client_id"], "peer-a")
        self.assertEqual(contract["session_id"], "dm::lobby::peer-a::peer-b")
        self.assertEqual(contract["mode"], "pqxdh-control")
        self.assertEqual(contract["received_type"], "PqxdhInit")
        self.assertEqual(contract["has_response"], True)
        self.assertEqual(contract["response_type"], "PqxdhInitAck")
        self.assertEqual(contract["response_sequence"], 1)

    def test_inbound_message_rotates_local_ratchet_on_new_remote_ratchet_key(self):
        outbound = self.alice_adapter.prepare_outbound_message(
            local_client_id="peer-a",
            peer_client_id="peer-b",
            peer_encryption_public_key_b64=self.bob_adapter.cipher.encryption_public_key_b64,
            room_id="lobby",
            plaintext="hello",
        )

        before = self.bob_adapter.sessions.snapshot("peer-a")
        self.assertIsNone(before)

        inbound = self.bob_adapter.accept_inbound_message(
            peer_client_id="peer-a",
            payload=outbound.encrypted_payload,
            room_id="lobby",
            target_client_id="peer-b",
            expected_signing_key_b64=self.alice_adapter.cipher.signing_public_key_b64,
        )

        session = self.bob_adapter.sessions.snapshot("peer-a")
        self.assertIsNotNone(session)
        self.assertEqual(
            session.remote_ratchet_public_key_b64,
            outbound.ratchet_public_key_b64,
        )
        self.assertEqual(session.dh_ratchet_turn, 1)
        self.assertEqual(
            inbound.ratchet_public_key_b64,
            session.local_ratchet_public_key_b64,
        )
        self.assertEqual(inbound.mode, "signed-static-session")
        self.assertIsNone(inbound.message_key_ref)

    def test_bootstrap_ack_derives_matching_secret_ref_on_both_sides(self):
        outbound = self.alice_adapter.prepare_outbound_message(
            local_client_id="peer-a",
            peer_client_id="peer-b",
            peer_encryption_public_key_b64=self.bob_adapter.cipher.encryption_public_key_b64,
            room_id="lobby",
            plaintext="hello",
        )
        init_result = self.bob_adapter.handle_bootstrap_message(
            local_client_id="peer-b",
            peer_client_id="peer-a",
            room_id="lobby",
            bootstrap_payload=outbound.bootstrap_message,
            session_id=outbound.session_id,
        )
        self.alice_adapter.handle_bootstrap_message(
            local_client_id="peer-a",
            peer_client_id="peer-b",
            room_id="lobby",
            bootstrap_payload=init_result.ack_message,
            session_id=outbound.session_id,
        )

        alice_session = self.alice_adapter.sessions.snapshot("peer-b")
        bob_session = self.bob_adapter.sessions.snapshot("peer-a")
        self.assertIsNotNone(alice_session.bootstrap_secret_ref)
        self.assertEqual(alice_session.bootstrap_secret_ref, bob_session.bootstrap_secret_ref)

    def test_duplicate_bootstrap_init_is_rejected(self):
        outbound = self.alice_adapter.prepare_outbound_message(
            local_client_id="peer-a",
            peer_client_id="peer-b",
            peer_encryption_public_key_b64=self.bob_adapter.cipher.encryption_public_key_b64,
            room_id="lobby",
            plaintext="hello",
        )
        self.bob_adapter.handle_bootstrap_message(
            local_client_id="peer-b",
            peer_client_id="peer-a",
            room_id="lobby",
            bootstrap_payload=outbound.bootstrap_message,
            session_id=outbound.session_id,
        )

        with self.assertRaises(DirectAdapterError) as error:
            self.bob_adapter.handle_bootstrap_message(
                local_client_id="peer-b",
                peer_client_id="peer-a",
                room_id="lobby",
                bootstrap_payload=outbound.bootstrap_message,
                session_id=outbound.session_id,
            )

        self.assertIn("duplicate bootstrap init rejected", str(error.exception))

    def test_duplicate_bootstrap_ack_is_rejected(self):
        outbound = self.alice_adapter.prepare_outbound_message(
            local_client_id="peer-a",
            peer_client_id="peer-b",
            peer_encryption_public_key_b64=self.bob_adapter.cipher.encryption_public_key_b64,
            room_id="lobby",
            plaintext="hello",
        )
        init_result = self.bob_adapter.handle_bootstrap_message(
            local_client_id="peer-b",
            peer_client_id="peer-a",
            room_id="lobby",
            bootstrap_payload=outbound.bootstrap_message,
            session_id=outbound.session_id,
        )
        self.alice_adapter.handle_bootstrap_message(
            local_client_id="peer-a",
            peer_client_id="peer-b",
            room_id="lobby",
            bootstrap_payload=init_result.ack_message,
            session_id=outbound.session_id,
        )

        with self.assertRaises(DirectAdapterError) as error:
            self.alice_adapter.handle_bootstrap_message(
                local_client_id="peer-a",
                peer_client_id="peer-b",
                room_id="lobby",
                bootstrap_payload=init_result.ack_message,
                session_id=outbound.session_id,
            )

        self.assertIn("duplicate bootstrap ack rejected", str(error.exception))

    def test_session_snapshot_reports_bootstrap_and_ratchet_state(self):
        outbound = self.alice_adapter.prepare_outbound_message(
            local_client_id="peer-a",
            peer_client_id="peer-b",
            peer_encryption_public_key_b64=self.bob_adapter.cipher.encryption_public_key_b64,
            room_id="lobby",
            plaintext="hello",
        )
        init_result = self.bob_adapter.handle_bootstrap_message(
            local_client_id="peer-b",
            peer_client_id="peer-a",
            room_id="lobby",
            bootstrap_payload=outbound.bootstrap_message,
            session_id=outbound.session_id,
        )
        self.alice_adapter.handle_bootstrap_message(
            local_client_id="peer-a",
            peer_client_id="peer-b",
            room_id="lobby",
            bootstrap_payload=init_result.ack_message,
            session_id=outbound.session_id,
        )

        snapshot = self.alice_adapter.session_snapshot("peer-b")
        self.assertIsNotNone(snapshot)
        self.assertTrue(snapshot.bootstrap_ready)
        self.assertTrue(snapshot.ratchet_initialized)
        self.assertEqual(snapshot.mode, "pqxdh-bridge-session")
        self.assertEqual(snapshot.outbound_sequence, 1)
        self.assertEqual(snapshot.dh_ratchet_turn, 0)
        self.assertIsNotNone(snapshot.local_ratchet_public_key_b64)
        self.assertIsNotNone(snapshot.send_chain_key_ref)
        self.assertIsNotNone(snapshot.receive_chain_key_ref)
        self.assertEqual(snapshot.last_send_message_number, 1)
        self.assertIsNone(snapshot.last_send_message_key_ref)

    def test_session_snapshot_contract_round_trip(self):
        outbound = self.alice_adapter.prepare_outbound_message(
            local_client_id="peer-a",
            peer_client_id="peer-b",
            peer_encryption_public_key_b64=self.bob_adapter.cipher.encryption_public_key_b64,
            room_id="lobby",
            plaintext="hello",
        )
        init_result = self.bob_adapter.handle_bootstrap_message(
            local_client_id="peer-b",
            peer_client_id="peer-a",
            room_id="lobby",
            bootstrap_payload=outbound.bootstrap_message,
            session_id=outbound.session_id,
        )
        self.alice_adapter.handle_bootstrap_message(
            local_client_id="peer-a",
            peer_client_id="peer-b",
            room_id="lobby",
            bootstrap_payload=init_result.ack_message,
            session_id=outbound.session_id,
        )

        snapshot = self.alice_adapter.session_snapshot("peer-b")
        contract = snapshot.to_contract_dict()
        restored = snapshot.from_contract_dict(contract)

        self.assertEqual(restored.peer_client_id, snapshot.peer_client_id)
        self.assertEqual(restored.session_id, snapshot.session_id)
        self.assertEqual(restored.mode, snapshot.mode)
        self.assertEqual(restored.send_chain_key_ref, snapshot.send_chain_key_ref)
        self.assertEqual(restored.receive_chain_key_ref, snapshot.receive_chain_key_ref)
        self.assertIsNone(restored.send_chain_secret_ref)
        self.assertIsNone(restored.receive_chain_secret_ref)

    def test_post_bootstrap_messages_use_session_key_algorithm(self):
        first = self.alice_adapter.prepare_outbound_message(
            local_client_id="peer-a",
            peer_client_id="peer-b",
            peer_encryption_public_key_b64=self.bob_adapter.cipher.encryption_public_key_b64,
            room_id="lobby",
            plaintext="bootstrap-message",
        )
        init_result = self.bob_adapter.handle_bootstrap_message(
            local_client_id="peer-b",
            peer_client_id="peer-a",
            room_id="lobby",
            bootstrap_payload=first.bootstrap_message,
            session_id=first.session_id,
        )
        self.alice_adapter.handle_bootstrap_message(
            local_client_id="peer-a",
            peer_client_id="peer-b",
            room_id="lobby",
            bootstrap_payload=init_result.ack_message,
            session_id=first.session_id,
        )
        alice_send_chain_before = self.alice_adapter.session_snapshot("peer-b").send_chain_secret_ref

        second = self.alice_adapter.prepare_outbound_message(
            local_client_id="peer-a",
            peer_client_id="peer-b",
            peer_encryption_public_key_b64=self.bob_adapter.cipher.encryption_public_key_b64,
            room_id="lobby",
            plaintext="session-protected",
        )
        envelope = DirectEnvelope.from_json(second.encrypted_payload)
        self.assertEqual(envelope.algorithm, "pqxdh-bridge+hkdf+aes-256-gcm+ed25519")
        alice_session_after_send = self.alice_adapter.session_snapshot("peer-b")
        self.assertNotEqual(
            alice_send_chain_before,
            alice_session_after_send.send_chain_secret_ref,
        )
        self.assertEqual(second.mode, "pqxdh-bridge-session")
        self.assertIsNotNone(second.message_key_ref)

        inbound = self.bob_adapter.accept_inbound_message(
            peer_client_id="peer-a",
            payload=second.encrypted_payload,
            room_id="lobby",
            target_client_id="peer-b",
            expected_signing_key_b64=self.alice_adapter.cipher.signing_public_key_b64,
        )
        self.assertEqual(inbound.decrypted.plaintext, "session-protected")
        self.assertEqual(inbound.mode, "pqxdh-bridge-session")
        self.assertIsNotNone(inbound.message_key_ref)
        bob_snapshot = self.bob_adapter.session_snapshot("peer-a")
        self.assertEqual(bob_snapshot.mode, "pqxdh-bridge-session")
        self.assertEqual(bob_snapshot.last_receive_message_number, 1)
        self.assertIsNotNone(bob_snapshot.last_receive_message_key_ref)

    def test_direct_event_contract_exports_python_compatible_fields(self):
        outbound = self.alice_adapter.prepare_outbound_message(
            local_client_id="peer-a",
            peer_client_id="peer-b",
            peer_encryption_public_key_b64=self.bob_adapter.cipher.encryption_public_key_b64,
            room_id="lobby",
            plaintext="hello",
        )
        outbound_contract = outbound.to_contract_dict()
        self.assertEqual(outbound_contract["peer_client_id"], "peer-b")
        self.assertEqual(outbound_contract["mode"], "signed-static-session")
        self.assertEqual(outbound_contract["ratchet_message_number"], 1)
        self.assertEqual(outbound_contract["has_bootstrap_message"], True)

        inbound = self.bob_adapter.accept_inbound_message(
            peer_client_id="peer-a",
            payload=outbound.encrypted_payload,
            room_id="lobby",
            target_client_id="peer-b",
            expected_signing_key_b64=self.alice_adapter.cipher.signing_public_key_b64,
        )
        inbound_contract = inbound.to_contract_dict()
        self.assertEqual(inbound_contract["peer_client_id"], "peer-a")
        self.assertEqual(inbound_contract["mode"], "signed-static-session")
        self.assertEqual(inbound_contract["used_skipped_message_key"], False)

    def test_accept_inbound_message_rejects_wrong_signing_key(self):
        outbound = self.alice_adapter.prepare_outbound_message(
            local_client_id="peer-a",
            peer_client_id="peer-b",
            peer_encryption_public_key_b64=self.bob_adapter.cipher.encryption_public_key_b64,
            room_id="lobby",
            plaintext="hello",
        )

        with self.assertRaises(DirectAdapterError):
            self.bob_adapter.accept_inbound_message(
                peer_client_id="peer-a",
                payload=outbound.encrypted_payload,
                room_id="lobby",
                target_client_id="peer-b",
                expected_signing_key_b64="wrong-signing-key",
            )

    def test_accept_inbound_message_rejects_duplicate_replay(self):
        outbound = self.alice_adapter.prepare_outbound_message(
            local_client_id="peer-a",
            peer_client_id="peer-b",
            peer_encryption_public_key_b64=self.bob_adapter.cipher.encryption_public_key_b64,
            room_id="lobby",
            plaintext="hello",
        )

        first = self.bob_adapter.accept_inbound_message(
            peer_client_id="peer-a",
            payload=outbound.encrypted_payload,
            room_id="lobby",
            target_client_id="peer-b",
            expected_signing_key_b64=self.alice_adapter.cipher.signing_public_key_b64,
        )
        self.assertEqual(first.decrypted.plaintext, "hello")

        with self.assertRaises(DirectAdapterError):
            self.bob_adapter.accept_inbound_message(
                peer_client_id="peer-a",
                payload=outbound.encrypted_payload,
                room_id="lobby",
                target_client_id="peer-b",
                expected_signing_key_b64=self.alice_adapter.cipher.signing_public_key_b64,
            )

    def test_out_of_order_post_bootstrap_messages_use_skipped_receive_secret(self):
        first = self.alice_adapter.prepare_outbound_message(
            local_client_id="peer-a",
            peer_client_id="peer-b",
            peer_encryption_public_key_b64=self.bob_adapter.cipher.encryption_public_key_b64,
            room_id="lobby",
            plaintext="bootstrap-message",
        )
        init_result = self.bob_adapter.handle_bootstrap_message(
            local_client_id="peer-b",
            peer_client_id="peer-a",
            room_id="lobby",
            bootstrap_payload=first.bootstrap_message,
            session_id=first.session_id,
        )
        self.alice_adapter.handle_bootstrap_message(
            local_client_id="peer-a",
            peer_client_id="peer-b",
            room_id="lobby",
            bootstrap_payload=init_result.ack_message,
            session_id=first.session_id,
        )

        second = self.alice_adapter.prepare_outbound_message(
            local_client_id="peer-a",
            peer_client_id="peer-b",
            peer_encryption_public_key_b64=self.bob_adapter.cipher.encryption_public_key_b64,
            room_id="lobby",
            plaintext="second-message",
        )
        third = self.alice_adapter.prepare_outbound_message(
            local_client_id="peer-a",
            peer_client_id="peer-b",
            peer_encryption_public_key_b64=self.bob_adapter.cipher.encryption_public_key_b64,
            room_id="lobby",
            plaintext="third-message",
        )

        third_inbound = self.bob_adapter.accept_inbound_message(
            peer_client_id="peer-a",
            payload=third.encrypted_payload,
            room_id="lobby",
            target_client_id="peer-b",
            expected_signing_key_b64=self.alice_adapter.cipher.signing_public_key_b64,
        )
        self.assertEqual(third_inbound.decrypted.plaintext, "third-message")
        self.assertFalse(third_inbound.used_skipped_key)
        self.assertIsNotNone(third_inbound.message_key_ref)

        second_inbound = self.bob_adapter.accept_inbound_message(
            peer_client_id="peer-a",
            payload=second.encrypted_payload,
            room_id="lobby",
            target_client_id="peer-b",
            expected_signing_key_b64=self.alice_adapter.cipher.signing_public_key_b64,
        )
        self.assertEqual(second_inbound.decrypted.plaintext, "second-message")
        self.assertTrue(second_inbound.used_skipped_key)
        self.assertIsNotNone(second_inbound.message_key_ref)

    def test_skipped_receive_cache_evicts_oldest_message_numbers(self):
        limited_tempdir = tempfile.TemporaryDirectory()
        try:
            alice = DirectMessageAdapter(
                DirectCipher(X25519PrivateKey.generate(), Ed25519PrivateKey.generate()),
                DirectSessionStore(path=str(Path(limited_tempdir.name) / "alice.json"), max_skipped_message_keys=1),
            )
            bob = DirectMessageAdapter(
                DirectCipher(X25519PrivateKey.generate(), Ed25519PrivateKey.generate()),
                DirectSessionStore(path=str(Path(limited_tempdir.name) / "bob.json"), max_skipped_message_keys=1),
            )

            first = alice.prepare_outbound_message(
                local_client_id="peer-a",
                peer_client_id="peer-b",
                peer_encryption_public_key_b64=bob.cipher.encryption_public_key_b64,
                room_id="lobby",
                plaintext="bootstrap-message",
            )
            init_result = bob.handle_bootstrap_message(
                local_client_id="peer-b",
                peer_client_id="peer-a",
                room_id="lobby",
                bootstrap_payload=first.bootstrap_message,
                session_id=first.session_id,
            )
            alice.handle_bootstrap_message(
                local_client_id="peer-a",
                peer_client_id="peer-b",
                room_id="lobby",
                bootstrap_payload=init_result.ack_message,
                session_id=first.session_id,
            )

            second = alice.prepare_outbound_message(
                local_client_id="peer-a",
                peer_client_id="peer-b",
                peer_encryption_public_key_b64=bob.cipher.encryption_public_key_b64,
                room_id="lobby",
                plaintext="second-message",
            )
            third = alice.prepare_outbound_message(
                local_client_id="peer-a",
                peer_client_id="peer-b",
                peer_encryption_public_key_b64=bob.cipher.encryption_public_key_b64,
                room_id="lobby",
                plaintext="third-message",
            )
            fourth = alice.prepare_outbound_message(
                local_client_id="peer-a",
                peer_client_id="peer-b",
                peer_encryption_public_key_b64=bob.cipher.encryption_public_key_b64,
                room_id="lobby",
                plaintext="fourth-message",
            )

            fourth_inbound = bob.accept_inbound_message(
                peer_client_id="peer-a",
                payload=fourth.encrypted_payload,
                room_id="lobby",
                target_client_id="peer-b",
                expected_signing_key_b64=alice.cipher.signing_public_key_b64,
            )
            self.assertEqual(fourth_inbound.decrypted.plaintext, "fourth-message")
            self.assertEqual(bob.sessions.snapshot("peer-a").skipped_message_keys, [3])

            with self.assertRaises(DirectAdapterError):
                bob.accept_inbound_message(
                    peer_client_id="peer-a",
                    payload=second.encrypted_payload,
                    room_id="lobby",
                    target_client_id="peer-b",
                    expected_signing_key_b64=alice.cipher.signing_public_key_b64,
                )

            third_inbound = bob.accept_inbound_message(
                peer_client_id="peer-a",
                payload=third.encrypted_payload,
                room_id="lobby",
                target_client_id="peer-b",
                expected_signing_key_b64=alice.cipher.signing_public_key_b64,
            )
            self.assertEqual(third_inbound.decrypted.plaintext, "third-message")
            self.assertTrue(third_inbound.used_skipped_key)
        finally:
            limited_tempdir.cleanup()

    def test_local_send_ratchet_rotates_on_configured_interval(self):
        self.alice_adapter.sessions.send_ratchet_rotation_interval = 2

        first = self.alice_adapter.prepare_outbound_message(
            local_client_id="peer-a",
            peer_client_id="peer-b",
            peer_encryption_public_key_b64=self.bob_adapter.cipher.encryption_public_key_b64,
            room_id="lobby",
            plaintext="bootstrap-message",
        )
        init_result = self.bob_adapter.handle_bootstrap_message(
            local_client_id="peer-b",
            peer_client_id="peer-a",
            room_id="lobby",
            bootstrap_payload=first.bootstrap_message,
            session_id=first.session_id,
        )
        self.alice_adapter.handle_bootstrap_message(
            local_client_id="peer-a",
            peer_client_id="peer-b",
            room_id="lobby",
            bootstrap_payload=init_result.ack_message,
            session_id=first.session_id,
        )

        second = self.alice_adapter.prepare_outbound_message(
            local_client_id="peer-a",
            peer_client_id="peer-b",
            peer_encryption_public_key_b64=self.bob_adapter.cipher.encryption_public_key_b64,
            room_id="lobby",
            plaintext="first-session-message",
        )
        session_before_rotate = self.alice_adapter.session_snapshot("peer-b")
        first_ratchet_key = second.ratchet_public_key_b64
        self.assertEqual(session_before_rotate.send_chain_generation, 2)

        second_inbound = self.bob_adapter.accept_inbound_message(
            peer_client_id="peer-a",
            payload=second.encrypted_payload,
            room_id="lobby",
            target_client_id="peer-b",
            expected_signing_key_b64=self.alice_adapter.cipher.signing_public_key_b64,
        )
        self.assertEqual(second_inbound.decrypted.plaintext, "first-session-message")

        third = self.alice_adapter.prepare_outbound_message(
            local_client_id="peer-a",
            peer_client_id="peer-b",
            peer_encryption_public_key_b64=self.bob_adapter.cipher.encryption_public_key_b64,
            room_id="lobby",
            plaintext="rotated-message",
        )
        self.assertNotEqual(first_ratchet_key, third.ratchet_public_key_b64)
        self.assertEqual(third.message_number, 1)

        third_inbound = self.bob_adapter.accept_inbound_message(
            peer_client_id="peer-a",
            payload=third.encrypted_payload,
            room_id="lobby",
            target_client_id="peer-b",
            expected_signing_key_b64=self.alice_adapter.cipher.signing_public_key_b64,
        )
        self.assertEqual(third_inbound.decrypted.plaintext, "rotated-message")
        bob_session = self.bob_adapter.session_snapshot("peer-a")
        self.assertEqual(bob_session.remote_ratchet_public_key_b64, third.ratchet_public_key_b64)


if __name__ == "__main__":
    unittest.main()
