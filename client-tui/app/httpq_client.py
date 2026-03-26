import base64
import json
import os
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

try:
    from .httpq_math import (
        httpq_transcript_bytes,
        merkle_root_from_proof,
        sth_message,
        verify_consistency_proof,
        witness_message,
    )
    from .httpq_protocol import (
        HTTPQProtocolError,
        HTTPQServerHello,
        HTTPQServerProof,
        KtInclusionPayload,
        WitnessCheckpoint,
    )
    from .pin_store import PinStore, RelayPin
except ImportError:
    from httpq_math import (
        httpq_transcript_bytes,
        merkle_root_from_proof,
        sth_message,
        verify_consistency_proof,
        witness_message,
    )
    from httpq_protocol import (
        HTTPQProtocolError,
        HTTPQServerHello,
        HTTPQServerProof,
        KtInclusionPayload,
        WitnessCheckpoint,
    )
    from pin_store import PinStore, RelayPin


class HTTPQVerificationError(Exception):
    pass


def generate_client_nonce() -> str:
    return base64.b64encode(os.urandom(32)).decode("ascii")


class HTTPQVerifier:
    def __init__(self, relay_locator: str, pin_store: PinStore) -> None:
        self.relay_locator = relay_locator
        self.pin_store = pin_store

    def verify_server_proof(self, hello: dict, proof: dict) -> str:
        try:
            parsed_hello = HTTPQServerHello.from_payload(hello)
            parsed_proof = HTTPQServerProof.from_payload(proof)
        except HTTPQProtocolError as exc:
            raise HTTPQVerificationError(str(exc)) from exc

        relay_id = parsed_proof.relay_id
        realm = parsed_proof.realm
        public_key_b64 = parsed_proof.relay_public_key_b64
        signature_b64 = parsed_proof.signature_b64
        client_id = parsed_proof.client_id
        client_nonce_b64 = parsed_proof.client_nonce_b64
        server_nonce_b64 = parsed_proof.server_nonce_b64

        if relay_id != parsed_hello.relay_id:
            raise HTTPQVerificationError("relay id changed during handshake")

        if realm != parsed_hello.realm:
            raise HTTPQVerificationError("relay realm changed during handshake")

        if public_key_b64 != parsed_hello.relay_public_key_b64:
            raise HTTPQVerificationError("relay key changed during handshake")

        if server_nonce_b64 != parsed_hello.server_nonce_b64:
            raise HTTPQVerificationError("server nonce changed during handshake")

        try:
            public_key = Ed25519PublicKey.from_public_bytes(
                base64.b64decode(public_key_b64)
            )
            signature = base64.b64decode(signature_b64)
        except Exception as exc:
            raise HTTPQVerificationError("relay proof encoding is invalid") from exc

        transcript = httpq_transcript_bytes(
            realm=realm,
            client_id=client_id,
            client_nonce_b64=client_nonce_b64,
            server_nonce_b64=server_nonce_b64,
            public_key_b64=public_key_b64,
        )

        try:
            public_key.verify(signature, transcript)
        except Exception as exc:
            raise HTTPQVerificationError("relay signature verification failed") from exc

        self._verify_kt_log(
            relay_id=relay_id,
            kt_log_url=parsed_hello.kt_log_url,
            witness_url=parsed_hello.witness_url,
            expected_public_key_b64=public_key_b64,
        )
        self._verify_pin(relay_id=relay_id, realm=realm, public_key_b64=public_key_b64)
        return client_id

    def _verify_pin(self, *, relay_id: str, realm: str, public_key_b64: str) -> None:
        pinned = self.pin_store.get(relay_id)
        if pinned is None:
            self.pin_store.save(
                RelayPin(
                    relay_id=relay_id,
                    realm=realm,
                    public_key_b64=public_key_b64,
                )
            )
            return

        if pinned.public_key_b64 != public_key_b64:
            raise HTTPQVerificationError("relay public key does not match pinned identity")

    def _verify_kt_log(
        self,
        *,
        relay_id: str,
        kt_log_url: str,
        witness_url: str,
        expected_public_key_b64: str,
    ) -> None:
        if not kt_log_url:
            raise HTTPQVerificationError("relay did not advertise a KT log URL")

        try:
            with urllib.request.urlopen(
                f"{kt_log_url.rstrip('/')}/v1/entries/{relay_id}/proof", timeout=5
            ) as response:
                payload = json.load(response)
        except Exception as exc:
            raise HTTPQVerificationError("unable to fetch KT inclusion proof") from exc

        try:
            inclusion = KtInclusionPayload.from_payload(payload)
        except HTTPQProtocolError as exc:
            raise HTTPQVerificationError(str(exc)) from exc

        if inclusion.record.relay_id != relay_id:
            raise HTTPQVerificationError("KT log returned a different relay record")
        if inclusion.record.public_key_b64 != expected_public_key_b64:
            raise HTTPQVerificationError("KT log public key does not match relay proof")

        try:
            root_hash = base64.b64decode(inclusion.sth.root_hash_b64)
            signature = base64.b64decode(inclusion.sth.signature_b64)
            signing_key = Ed25519PublicKey.from_public_bytes(
                base64.b64decode(inclusion.signing_public_key_b64)
            )
        except Exception as exc:
            raise HTTPQVerificationError("KT proof payload encoding is invalid") from exc

        tree_size = inclusion.sth.tree_size

        signed_tree_message = sth_message(tree_size, root_hash)
        try:
            signing_key.verify(signature, signed_tree_message)
        except Exception as exc:
            raise HTTPQVerificationError("KT log STH signature verification failed") from exc

        try:
            proof = [base64.b64decode(node) for node in inclusion.proof_b64]
        except Exception as exc:
            raise HTTPQVerificationError("KT proof nodes are invalid") from exc

        record_bytes = json.dumps(
            {
                "relayId": inclusion.record.relay_id,
                "publicKey": inclusion.record.public_key_b64,
                "algorithm": inclusion.record.algorithm,
                "createdAt": inclusion.record.created_at,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        calculated_root = merkle_root_from_proof(
            record_bytes=record_bytes,
            index=inclusion.index,
            proof=proof,
        )
        if calculated_root != root_hash:
            raise HTTPQVerificationError("KT inclusion proof does not match signed tree head")

        self._check_witness(
            witness_url=witness_url,
            log_id=kt_log_url,
            tree_size=tree_size,
            root_hash_b64=inclusion.sth.root_hash_b64,
            signing_public_key_b64=inclusion.signing_public_key_b64,
        )

    def _check_witness(
        self,
        *,
        witness_url: str,
        log_id: str,
        tree_size: int,
        root_hash_b64: str,
        signing_public_key_b64: str,
    ) -> None:
        if not witness_url:
            raise HTTPQVerificationError("relay did not advertise a witness URL")

        known_checkpoint = None
        try:
            with urllib.request.urlopen(
                f"{witness_url.rstrip('/')}/v1/checkpoints/{urllib.parse.quote(log_id, safe='')}",
                timeout=5,
            ) as response:
                known_checkpoint = WitnessCheckpoint.from_payload(json.load(response))
        except Exception:
            known_checkpoint = None

        if known_checkpoint is not None:
            self._verify_witness_signature(known_checkpoint)
            known_size = known_checkpoint.tree_size
            known_root = known_checkpoint.root_hash_b64
            known_key = known_checkpoint.signing_public_key_b64

            if known_key and known_key != signing_public_key_b64:
                raise HTTPQVerificationError("witness observed a different KT signing key")
            if tree_size < known_size:
                raise HTTPQVerificationError("KT log view is older than witness checkpoint")
            if tree_size == known_size and root_hash_b64 != known_root:
                raise HTTPQVerificationError("witness detected a split-view tree head")
            if tree_size > known_size:
                self._verify_consistency_proof(
                    kt_log_url=log_id,
                    old_tree_size=known_size,
                    new_tree_size=tree_size,
                    old_root_hash_b64=known_root,
                    new_root_hash_b64=root_hash_b64,
                )

        body = json.dumps(
            WitnessCheckpoint(
                log_id=log_id,
                tree_size=tree_size,
                root_hash_b64=root_hash_b64,
                signing_public_key_b64=signing_public_key_b64,
            ).to_payload()
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{witness_url.rstrip('/')}/v1/checkpoints",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=5):
                pass
        except Exception as exc:
            raise HTTPQVerificationError("witness rejected the KT checkpoint") from exc

    def _verify_witness_signature(self, checkpoint: WitnessCheckpoint) -> None:
        if not checkpoint.witness_public_key_b64 or not checkpoint.witness_signature_b64:
            raise HTTPQVerificationError("witness checkpoint is missing witness signature")

        try:
            public_key = Ed25519PublicKey.from_public_bytes(
                base64.b64decode(checkpoint.witness_public_key_b64)
            )
            signature = base64.b64decode(checkpoint.witness_signature_b64)
        except Exception as exc:
            raise HTTPQVerificationError("witness checkpoint signature encoding is invalid") from exc

        try:
            public_key.verify(
                signature,
                witness_message(
                    log_id=checkpoint.log_id,
                    tree_size=checkpoint.tree_size,
                    root_hash_b64=checkpoint.root_hash_b64,
                    signing_public_key_b64=checkpoint.signing_public_key_b64,
                ),
            )
        except Exception as exc:
            raise HTTPQVerificationError("witness checkpoint signature verification failed") from exc

    def _verify_consistency_proof(
        self,
        *,
        kt_log_url: str,
        old_tree_size: int,
        new_tree_size: int,
        old_root_hash_b64: str,
        new_root_hash_b64: str,
    ) -> None:
        consistency_url = (
            f"{kt_log_url.rstrip('/')}/v1/consistency?from={old_tree_size}&to={new_tree_size}"
        )
        try:
            with urllib.request.urlopen(consistency_url, timeout=5) as response:
                payload = json.load(response)
        except Exception as exc:
            raise HTTPQVerificationError("unable to fetch KT consistency proof") from exc

        try:
            proof = [base64.b64decode(node) for node in payload.get("proof", [])]
            returned_old_root = base64.b64decode(payload.get("oldRootHash", ""))
            returned_new_root = base64.b64decode(payload.get("newRootHash", ""))
        except Exception as exc:
            raise HTTPQVerificationError("KT consistency proof payload encoding is invalid") from exc

        if payload.get("fromTreeSize") != old_tree_size or payload.get("toTreeSize") != new_tree_size:
            raise HTTPQVerificationError("KT consistency proof tree sizes do not match request")
        if payload.get("oldRootHash") != old_root_hash_b64 or payload.get("newRootHash") != new_root_hash_b64:
            raise HTTPQVerificationError("KT consistency proof roots do not match expected tree heads")

        if not verify_consistency_proof(
            old_tree_size=old_tree_size,
            new_tree_size=new_tree_size,
            old_root_hash=returned_old_root,
            new_root_hash=returned_new_root,
            proof=proof,
        ):
            raise HTTPQVerificationError("KT consistency proof does not verify append-only history")
