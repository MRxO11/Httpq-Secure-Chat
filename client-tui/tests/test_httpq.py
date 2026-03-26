import base64
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


CLIENT_TUI_ROOT = Path(__file__).resolve().parents[1]
if str(CLIENT_TUI_ROOT) not in sys.path:
    sys.path.insert(0, str(CLIENT_TUI_ROOT))

from app.httpq_client import HTTPQVerificationError, HTTPQVerifier  # noqa: E402
from app.httpq_math import (  # noqa: E402
    hash_leaf,
    hash_node,
    httpq_transcript_bytes,
    sth_message,
    verify_consistency_proof,
    witness_message,
)
from app.httpq_protocol import (  # noqa: E402
    HTTPQProtocolError,
    HTTPQServerHello,
    KtInclusionPayload,
    WitnessCheckpoint,
)
from app.pin_store import PinStore  # noqa: E402


class MockHTTPResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False


def json_response(payload: dict) -> MockHTTPResponse:
    return MockHTTPResponse(json.dumps(payload).encode("utf-8"))


def sample_handshake():
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
        "clientNonce": base64.b64encode(bytes([1]) * 32).decode("ascii"),
        "serverNonce": hello["serverNonce"],
        "relayPublicKey": relay_public_key_b64,
        "signature": base64.b64encode(
            relay_key.sign(
                httpq_transcript_bytes(
                    realm=hello["realm"],
                    client_id="anon-1",
                    client_nonce_b64=base64.b64encode(bytes([1]) * 32).decode("ascii"),
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
            "signature": base64.b64encode(kt_key.sign(sth_message(2, root_hash))).decode(
                "ascii"
            ),
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
    consistency = {
        "fromTreeSize": 2,
        "toTreeSize": 2,
        "proof": [],
        "oldRootHash": inclusion["sth"]["rootHash"],
        "newRootHash": inclusion["sth"]["rootHash"],
        "signingPublicKey": kt_public_key_b64,
    }
    return hello, proof, inclusion, checkpoint, consistency


class HTTPQProtocolTests(unittest.TestCase):
    def test_server_hello_requires_protocol_version(self):
        with self.assertRaises(HTTPQProtocolError):
            HTTPQServerHello.from_payload({"relayId": "relay-local", "realm": "secure-chat"})

    def test_kt_inclusion_payload_parses_valid_payload(self):
        _, _, inclusion, _, _ = sample_handshake()
        parsed = KtInclusionPayload.from_payload(inclusion)
        self.assertEqual(parsed.record.relay_id, "relay-local")
        self.assertEqual(parsed.sth.tree_size, 2)

    def test_witness_checkpoint_round_trip_payload(self):
        checkpoint = WitnessCheckpoint(
            log_id="http://127.0.0.1:8081",
            tree_size=2,
            root_hash_b64="abcd",
            signing_public_key_b64="efgh",
        )
        parsed = WitnessCheckpoint.from_payload(checkpoint.to_payload())
        self.assertEqual(parsed, checkpoint)

    def test_consistency_verifier_accepts_same_tree_size_empty_proof(self):
        root = hash_leaf(b"leaf")
        self.assertTrue(
            verify_consistency_proof(
                old_tree_size=1,
                new_tree_size=1,
                old_root_hash=root,
                new_root_hash=root,
                proof=[],
            )
        )


class HTTPQVerifierTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.pin_store = PinStore(path=str(Path(self.tempdir.name) / "pins.json"))
        self.verifier = HTTPQVerifier("ws://127.0.0.1:8443/ws", self.pin_store)

    def tearDown(self):
        self.tempdir.cleanup()

    def test_verifier_accepts_valid_handshake(self):
        hello, proof, inclusion, checkpoint, consistency = sample_handshake()

        def fake_urlopen(request, timeout=5):
            url = request.full_url if hasattr(request, "full_url") else request
            if url.endswith("/proof"):
                return json_response(inclusion)
            if "/v1/consistency" in url:
                return json_response(consistency)
            if "/v1/checkpoints/" in url:
                return json_response(checkpoint)
            if url.endswith("/v1/checkpoints"):
                return json_response(checkpoint)
            raise AssertionError(f"unexpected URL {url}")

        with mock.patch("app.httpq_client.urllib.request.urlopen", side_effect=fake_urlopen):
            client_id = self.verifier.verify_server_proof(hello, proof)

        self.assertEqual(client_id, "anon-1")
        self.assertIsNotNone(self.pin_store.get("relay-local"))

    def test_verifier_rejects_split_view_checkpoint(self):
        hello, proof, inclusion, checkpoint, consistency = sample_handshake()
        checkpoint["rootHash"] = base64.b64encode(bytes([5]) * 32).decode("ascii")

        def fake_urlopen(request, timeout=5):
            url = request.full_url if hasattr(request, "full_url") else request
            if url.endswith("/proof"):
                return json_response(inclusion)
            if "/v1/consistency" in url:
                return json_response(consistency)
            if "/v1/checkpoints/" in url:
                return json_response(checkpoint)
            if url.endswith("/v1/checkpoints"):
                return json_response(checkpoint)
            raise AssertionError(f"unexpected URL {url}")

        with mock.patch("app.httpq_client.urllib.request.urlopen", side_effect=fake_urlopen):
            with self.assertRaises(HTTPQVerificationError):
                self.verifier.verify_server_proof(hello, proof)

    def test_verifier_rejects_kt_public_key_mismatch(self):
        hello, proof, inclusion, checkpoint, consistency = sample_handshake()
        inclusion["record"]["publicKey"] = base64.b64encode(bytes([4]) * 32).decode("ascii")

        def fake_urlopen(request, timeout=5):
            url = request.full_url if hasattr(request, "full_url") else request
            if url.endswith("/proof"):
                return json_response(inclusion)
            if "/v1/consistency" in url:
                return json_response(consistency)
            if "/v1/checkpoints/" in url:
                return json_response(checkpoint)
            if url.endswith("/v1/checkpoints"):
                return json_response(checkpoint)
            raise AssertionError(f"unexpected URL {url}")

        with mock.patch("app.httpq_client.urllib.request.urlopen", side_effect=fake_urlopen):
            with self.assertRaises(HTTPQVerificationError):
                self.verifier.verify_server_proof(hello, proof)

    def test_verifier_rejects_invalid_consistency_proof(self):
        hello, proof, inclusion, checkpoint, consistency = sample_handshake()
        checkpoint["treeSize"] = 1
        checkpoint["rootHash"] = base64.b64encode(hash_leaf(json.dumps(inclusion["record"], separators=(",", ":")).encode("utf-8"))).decode("ascii")
        consistency = {
            "fromTreeSize": 1,
            "toTreeSize": 2,
            "proof": [base64.b64encode(bytes([0]) * 32).decode("ascii")],
            "oldRootHash": checkpoint["rootHash"],
            "newRootHash": inclusion["sth"]["rootHash"],
            "signingPublicKey": inclusion["signingPublicKey"],
        }

        def fake_urlopen(request, timeout=5):
            url = request.full_url if hasattr(request, "full_url") else request
            if url.endswith("/proof"):
                return json_response(inclusion)
            if "/v1/consistency" in url:
                return json_response(consistency)
            if "/v1/checkpoints/" in url:
                return json_response(checkpoint)
            if url.endswith("/v1/checkpoints"):
                return json_response(checkpoint)
            raise AssertionError(f"unexpected URL {url}")

        with mock.patch("app.httpq_client.urllib.request.urlopen", side_effect=fake_urlopen):
            with self.assertRaises(HTTPQVerificationError):
                self.verifier.verify_server_proof(hello, proof)

    def test_verifier_rejects_invalid_witness_signature(self):
        hello, proof, inclusion, checkpoint, consistency = sample_handshake()
        checkpoint["witnessSignature"] = base64.b64encode(bytes([0]) * 64).decode("ascii")

        def fake_urlopen(request, timeout=5):
            url = request.full_url if hasattr(request, "full_url") else request
            if url.endswith("/proof"):
                return json_response(inclusion)
            if "/v1/consistency" in url:
                return json_response(consistency)
            if "/v1/checkpoints/" in url:
                return json_response(checkpoint)
            if url.endswith("/v1/checkpoints"):
                return json_response(checkpoint)
            raise AssertionError(f"unexpected URL {url}")

        with mock.patch("app.httpq_client.urllib.request.urlopen", side_effect=fake_urlopen):
            with self.assertRaises(HTTPQVerificationError):
                self.verifier.verify_server_proof(hello, proof)


if __name__ == "__main__":
    unittest.main()
