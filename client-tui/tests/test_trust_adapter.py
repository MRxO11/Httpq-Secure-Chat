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

from app.httpq_math import (  # noqa: E402
    hash_leaf,
    hash_node,
    httpq_transcript_bytes,
    sth_message,
    witness_message,
)
from app.httpq_client import HTTPQVerifier  # noqa: E402
from app.pin_store import PinStore  # noqa: E402
from app.trust_adapter import TrustAdapter, TrustAdapterError  # noqa: E402


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
    return hello, proof, inclusion, checkpoint


class TrustAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        pin_store = PinStore(path=str(Path(self.tempdir.name) / "pins.json"))
        self.adapter = TrustAdapter(HTTPQVerifier("ws://127.0.0.1:8443/ws", pin_store))

    def tearDown(self):
        self.tempdir.cleanup()

    def test_handle_server_hello_generates_client_nonce(self):
        plan = self.adapter.handle_server_hello(
            {
                "relayId": "relay-local",
                "realm": "secure-chat",
                "protocolVersion": "HTTPq/1",
                "ktLogUrl": "http://127.0.0.1:8081",
                "witnessUrl": "http://127.0.0.1:8082",
                "serverNonce": base64.b64encode(bytes([2]) * 32).decode("ascii"),
                "relayPublicKey": base64.b64encode(bytes([3]) * 32).decode("ascii"),
            }
        )
        self.assertTrue(plan.client_nonce)
        self.assertEqual(plan.relay_id, "relay-local")

    def test_handle_server_proof_rejects_missing_hello(self):
        with self.assertRaises(TrustAdapterError):
            self.adapter.handle_server_proof({})

    def test_handle_server_proof_verifies_after_hello(self):
        hello, _, _, _ = sample_handshake("placeholder")
        hello_plan = self.adapter.handle_server_hello(hello)
        _, proof, inclusion, checkpoint = sample_handshake(hello_plan.client_nonce)

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
            result = self.adapter.handle_server_proof(proof)

        self.assertEqual(result.client_id, "anon-1")
        self.assertTrue(result.verified)
        contract = result.to_contract_dict()
        self.assertEqual(contract["relay_id"], "relay-local")
        self.assertEqual(contract["realm"], "secure-chat")
        self.assertEqual(contract["kt_log_url"], "http://127.0.0.1:8081")
        self.assertEqual(contract["witness_url"], "http://127.0.0.1:8082")
        restored = result.from_contract_dict(contract)
        self.assertEqual(restored.client_id, result.client_id)
        self.assertEqual(restored.relay_id, result.relay_id)
        self.assertEqual(restored.kt_log_url, result.kt_log_url)


if __name__ == "__main__":
    unittest.main()
